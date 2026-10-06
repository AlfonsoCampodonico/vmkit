//! The sandbox: one program in unprivileged user, PID, mount, net, IPC and UTS namespaces
//! (kiln spec §9.2 for VMMs, potter spec §9.4 for build steps).
//!
//! [`spawn`] checks a [`Spec`], resolves what the helper needs on the host (subordinate id
//! ranges, `ip`, `nft`, `pasta`) into a [`Plan`], and runs `vmkit-sandbox run <plan.json>`;
//! the helper does the namespace work.
//!
//! A VMM runs in an empty root: a read-only tmpfs with only its devices, `/vmm` (itself),
//! `/vm/kernel`, `/vm/initramfs`, `/vm/disk/<n>` and `/vm/sock/`, which is `<run_dir>/sock`
//! on the host. Its paths never depend on where files live on the host.

use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{ChildStderr, ChildStdout, ExitStatus};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::binary;
use crate::error::{Error, Result};
use crate::net::{self, NetSpec};
use crate::process::{self, Proc};
use crate::spec::VmSpec;
use crate::subid;

/// What the sandbox runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Program {
    /// A host file, bound read-only into the root at `target` (absolute). Only for [`Root::Empty`].
    Bound { host: PathBuf, target: PathBuf },
    /// An absolute path inside the root; for [`Root::Host`] that is a host path.
    Path(PathBuf),
}

/// Ids inside the program's user namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups.
    pub groups: Vec<u32>,
}

/// The program and how it starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub program: Program,
    /// `argv[0]`; defaults to the program's file name.
    pub arg0: Option<String>,
    pub args: Vec<String>,
    /// The program's whole environment, or `None` to inherit the caller's.
    pub env: Option<Vec<(String, String)>>,
    /// The working directory inside the sandbox: absolute, without `.` or `..`.
    pub cwd: PathBuf,
    /// Ids inside the program's user namespace (only under [`Ids::Subordinate`], where the
    /// default is root). Under [`Ids::Caller`] the program runs as the caller.
    pub user: Option<User>,
}

/// The program's root directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Root {
    /// A read-only 1 MiB tmpfs holding only the program and the mounts (the VMM sandbox).
    Empty,
    /// The host's tree, recursively read-only, nosuid and nodev, with the sandbox's own `/proc`.
    /// Mount targets must already exist.
    Host,
    /// An overlay of `lowers` (top first) with `upper` and `work` (on one filesystem), mounted
    /// with `userxattr`, with `/proc`, a read-only `/sys` and a `/dev` holding null, zero,
    /// full, random, urandom, tty, pts and shm. Mount points missing from the root are
    /// created in the upper.
    Overlay {
        lowers: Vec<PathBuf>,
        upper: PathBuf,
        work: PathBuf,
    },
}

/// A file system attached inside the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mount {
    /// `source`, opened without following a final symlink (a symlink is refused).
    Bind {
        source: PathBuf,
        target: PathBuf,
        writable: bool,
    },
    Tmpfs {
        target: PathBuf,
        size_mib: u32,
    },
}

impl Mount {
    /// Where the mount appears inside the root.
    pub fn target(&self) -> &Path {
        match self {
            Mount::Bind { target, .. } | Mount::Tmpfs { target, .. } => target,
        }
    }
}

/// How ids map into the sandbox's user namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ids {
    /// Only the caller's uid and gid, identity-mapped: the program is never root (the VMM sandbox).
    Caller,
    /// Root inside is the caller; ids `1..=count` map onto the caller's `/etc/subuid` and
    /// `/etc/subgid` ranges (through `newuidmap` and `newgidmap`).
    Subordinate { count: u32 },
}

/// The sandbox's network namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Only loopback: down under [`Root::Empty`], up otherwise.
    None,
    /// The VM network: a tap, forwards and the nftables policy (kiln spec §9.3).
    Tap(NetSpec),
    /// No tap: `pasta` egress for the namespace's own processes under the same deny and allow
    /// sets (potter spec §9.5). Forwards are refused. DNS is answered at [`net::NAMESERVER`].
    Egress(NetSpec),
}

/// A systemd user scope's limits (used when [`cgroups_available`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cgroup {
    pub memory_mib: u32,
    pub cpu_percent: u32,
    pub tasks: u32,
}

/// Resource limits applied to the program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub open_files: u64,
    pub processes: u64,
    /// Ignored when the systemd user session cannot create scopes; callers warn.
    pub cgroup: Option<Cgroup>,
}

/// One sandboxed program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub command: Command,
    pub root: Root,
    pub mounts: Vec<Mount>,
    pub ids: Ids,
    pub network: Network,
    /// Runs the program in a nested user namespace with no capability over the sandbox's
    /// namespaces (needs [`Ids::Subordinate`] and a root other than [`Root::Empty`]).
    pub nest: bool,
    /// Applies the deny-list seccomp filter to the program.
    pub seccomp: bool,
    pub limits: Limits,
    /// Created if missing; holds the plan, the root's mount point and the pid file.
    pub run_dir: PathBuf,
}

/// An absolute path without `.` or `..`.
fn plain_absolute(p: &Path) -> bool {
    p.is_absolute()
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn require_plain(what: &str, p: &Path) -> std::result::Result<(), String> {
    if plain_absolute(p) {
        Ok(())
    } else {
        Err(format!(
            "{what} {} must be an absolute path without `.` or `..`",
            p.display()
        ))
    }
}

impl Spec {
    /// Refuses a spec the sandbox cannot run as asked.
    pub fn check(&self) -> std::result::Result<(), String> {
        let c = &self.command;
        require_plain("the working directory", &c.cwd)?;
        for m in &self.mounts {
            require_plain("the mount target", m.target())?;
        }
        match (&c.program, &self.root) {
            (Program::Bound { target, .. }, Root::Empty) => require_plain("the program's target", target)?,
            (Program::Bound { .. }, _) => {
                return Err("a bound program needs Root::Empty; name the program inside the root instead".into());
            }
            (Program::Path(_), Root::Empty) => {
                return Err("Root::Empty holds no programs; bind one with Program::Bound".into());
            }
            (Program::Path(p), _) => require_plain("the program", p)?,
        }
        if let Root::Overlay { lowers, upper, work } = &self.root {
            if lowers.is_empty() {
                return Err("an overlay root needs at least one lower directory".into());
            }
            for p in lowers.iter().chain([upper, work]) {
                require_plain("the overlay directory", p)?;
            }
        }
        match self.ids {
            Ids::Caller => {
                if c.user.is_some() {
                    return Err(
                        "under Ids::Caller the program runs as the caller; `user` needs Ids::Subordinate".into(),
                    );
                }
                if self.nest {
                    return Err("a nested user namespace needs Ids::Subordinate".into());
                }
            }
            Ids::Subordinate { count } => {
                if count == 0 || count == u32::MAX {
                    return Err(format!("{count} subordinate ids cannot be mapped"));
                }
                if let Some(u) = &c.user {
                    if let Some(id) = [u.uid, u.gid].iter().chain(&u.groups).find(|&&id| id > count) {
                        return Err(format!("id {id} is outside the {count} mapped ids"));
                    }
                }
            }
        }
        if self.nest && self.root == Root::Empty {
            return Err("a nested user namespace needs a Root::Host or Root::Overlay".into());
        }
        match &self.network {
            Network::Egress(n) if !n.forwards.is_empty() => {
                return Err("egress without a tap cannot forward ports".into());
            }
            Network::Tap(n) | Network::Egress(n) => n.check()?,
            Network::None => {}
        }
        Ok(())
    }
}

/// The program's output streams. Its stdin is always `/dev/null`: the helper's stages talk
/// to each other over their standard input.
pub struct Stdio {
    pub stdout: std::process::Stdio,
    pub stderr: std::process::Stdio,
}

impl Stdio {
    /// Output and errors inherited.
    pub fn inherit() -> Self {
        Self {
            stdout: std::process::Stdio::inherit(),
            stderr: std::process::Stdio::inherit(),
        }
    }

    /// Output and errors piped to the caller.
    pub fn piped() -> Self {
        Self {
            stdout: std::process::Stdio::piped(),
            stderr: std::process::Stdio::piped(),
        }
    }
}

/// A running sandbox: the helper, in a process group of its own. Its exit mirrors the
/// program's; a setup failure exits 125 with one `vmkit-sandbox: ...` line on stderr.
pub struct Sandbox {
    child: std::process::Child,
}

impl Sandbox {
    /// The helper's PID.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    pub fn stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait()
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Kills the helper; every process in the sandbox dies with it.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    /// Waits for the program, collecting its piped output.
    pub fn wait_with_output(self) -> std::io::Result<std::process::Output> {
        self.child.wait_with_output()
    }
}

/// The subordinate id ranges the helper maps (`newuidmap` and `newgidmap`).
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubidPlan {
    pub newuidmap: PathBuf,
    pub newgidmap: PathBuf,
    pub uid_start: u32,
    pub gid_start: u32,
    pub count: u32,
}

/// The nftables policy and `pasta` attachment of a network namespace.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub nft: PathBuf,
    /// Loaded with `nft -f -`.
    pub ruleset: String,
    /// `pasta` and its options; the helper adds the namespace to attach to.
    pub pasta: PathBuf,
    pub pasta_args: Vec<String>,
}

/// What the helper sets up in the network namespace.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetKind {
    /// Loopback up, nothing else.
    Loopback,
    /// The VM's tap, routing and policy.
    Tap(Policy),
    /// The namespace's own processes reach out through pasta under the policy.
    Egress(Policy),
}

/// The network setup, run inside the namespace before the root is replaced.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPlan {
    pub ip: PathBuf,
    pub kind: NetKind,
}

/// Everything the helper needs: the spec plus what the library resolved on the host.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub spec: Spec,
    /// Host directory the root is mounted on while it is built.
    pub root: PathBuf,
    /// The helper writes the host PID of the sandbox's first process here.
    pub pid_file: PathBuf,
    pub subid: Option<SubidPlan>,
    pub net: Option<NetPlan>,
}

/// The kernel inside the sandbox.
pub(crate) const KERNEL: &str = "/vm/kernel";
/// The initramfs inside the sandbox.
pub(crate) const INITRAMFS: &str = "/vm/initramfs";
/// The VMM's own directory inside the sandbox: sockets and the logs it writes itself.
pub(crate) const SOCK: &str = "/vm/sock";
/// The tap's device, inside the sandbox.
pub(crate) const TUN: &str = "/dev/net/tun";

/// Disk `n` (0-based) inside the sandbox.
pub(crate) fn disk(n: usize) -> String {
    format!("/vm/disk/{n}")
}

/// `name` in the VMM's directory, inside the sandbox.
pub(crate) fn inside(name: &str) -> String {
    format!("{SOCK}/{name}")
}

/// `name` in the VMM's directory, on the host (`<run_dir>/sock/<name>`).
pub(crate) fn host(spec: &VmSpec, name: &str) -> PathBuf {
    spec.run_dir.join("sock").join(name)
}

/// The file holding the host PID of the sandbox's first process (the VMM) once it runs:
/// `<run_dir>/vmm.pid`.
pub fn pid_file(run_dir: &Path) -> PathBuf {
    run_dir.join("vmm.pid")
}

/// The sandbox helper (`$VMKIT_SANDBOX`, else `vmkit-sandbox` next to the running
/// program, else on `PATH`).
pub(crate) fn find_helper() -> Result<PathBuf> {
    const NAME: &str = "vmkit-sandbox";
    if std::env::var_os("VMKIT_SANDBOX").is_none() {
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join(NAME)));
        if let Some(p) = sibling.filter(|p| binary::is_executable(p)) {
            return Ok(p);
        }
    }
    binary::find(NAME, "VMKIT_SANDBOX")
}

/// Whether sandboxes go into a cgroup with memory, CPU and task limits: true when the
/// systemd user session can create a scope (kiln spec §9.2). Callers warn when false.
pub fn cgroups_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "--collect", "--", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// The bind mounts for `spec`: its devices, kernel, initramfs, disks and the VMM's directory.
fn binds(spec: &VmSpec) -> Vec<Mount> {
    let bind = |source: &Path, target: &str, writable: bool| Mount::Bind {
        source: source.to_path_buf(),
        target: target.into(),
        writable,
    };
    let mut binds = vec![
        bind(Path::new("/dev/kvm"), "/dev/kvm", true),
        bind(Path::new("/dev/null"), "/dev/null", true),
        bind(Path::new("/dev/urandom"), "/dev/urandom", false),
    ];
    if spec.net.is_some() {
        binds.push(bind(Path::new(TUN), TUN, true));
    }
    binds.push(bind(&spec.kernel, KERNEL, false));
    if let Some(i) = &spec.initramfs {
        binds.push(bind(i, INITRAMFS, false));
    }
    for (n, d) in spec.disks.iter().enumerate() {
        binds.push(bind(&d.path, &disk(n), !d.read_only));
    }
    binds.push(bind(&spec.run_dir.join("sock"), SOCK, true));
    binds
}

/// The VM's cgroup: guest memory plus the VMM's and pasta's overhead, one CPU per vCPU plus
/// one for the VMM's own threads, and tasks for its device threads.
fn vm_cgroup(spec: &VmSpec) -> Cgroup {
    Cgroup {
        memory_mib: spec.memory_mib + 256,
        cpu_percent: (u32::from(spec.vcpus) + 1) * 100,
        tasks: 64 + u32::from(spec.vcpus) + 2 * spec.devices_needed(),
    }
}

/// `systemd-run` properties for `c`.
fn scope_properties(c: &Cgroup) -> Vec<String> {
    vec![
        "-p".into(),
        format!("MemoryMax={}M", c.memory_mib),
        "-p".into(),
        format!("CPUQuota={}%", c.cpu_percent),
        "-p".into(),
        format!("TasksMax={}", c.tasks),
    ]
}

/// The sandbox a VMM runs in: an empty root, the caller's own ids, the VMM bound at `/vmm`.
pub(crate) fn vmm_spec(spec: &VmSpec, vmm: &Path, args: &[String]) -> Spec {
    Spec {
        command: Command {
            program: Program::Bound {
                host: vmm.to_path_buf(),
                target: "/vmm".into(),
            },
            arg0: None,
            args: args.to_vec(),
            env: None,
            cwd: "/".into(),
            user: None,
        },
        root: Root::Empty,
        mounts: binds(spec),
        ids: Ids::Caller,
        network: spec.net.clone().map_or(Network::None, Network::Tap),
        nest: false,
        seccomp: false,
        limits: Limits {
            open_files: 1024,
            processes: 256,
            cgroup: Some(vm_cgroup(spec)),
        },
        run_dir: spec.run_dir.clone(),
    }
}

/// The policy half of a network plan: the ruleset for the host's current addresses.
fn policy(ruleset: impl Fn(&[Ipv4Addr]) -> String, pasta_args: Vec<String>) -> Result<Policy> {
    let host: Vec<Ipv4Addr> = net::host_addresses(&std::fs::read_to_string("/proc/net/fib_trie")?);
    Ok(Policy {
        nft: binary::find_system("nft")?,
        ruleset: ruleset(&host),
        pasta: binary::find("pasta", "VMKIT_PASTA")?,
        pasta_args,
    })
}

/// The network plan for `spec`.
fn net_plan(spec: &Spec) -> Result<Option<NetPlan>> {
    let kind = match &spec.network {
        // The VMM sandbox keeps loopback down (and needs no `ip`).
        Network::None if spec.root == Root::Empty => return Ok(None),
        Network::None => NetKind::Loopback,
        Network::Tap(n) => NetKind::Tap(policy(|host| net::ruleset(n, host), net::pasta_args(n))?),
        Network::Egress(n) => NetKind::Egress(policy(|host| net::egress_ruleset(n, host), net::pasta_args(n))?),
    };
    Ok(Some(NetPlan {
        ip: binary::find_system("ip")?,
        kind,
    }))
}

/// The caller's subordinate ranges for `count` ids and the tools that map them.
fn resolve_subids(count: u32) -> Result<SubidPlan> {
    use std::os::unix::fs::MetadataExt;
    let read = |file: &str| std::fs::read_to_string(file).map_err(|e| Error::Prerequisite(format!("{file}: {e}")));
    // `/proc/self` belongs to the caller's effective ids.
    let me = std::fs::metadata("/proc/self")?;
    let uid = me.uid();
    let name = subid::user_name(&read("/etc/passwd")?, uid).unwrap_or_else(|| uid.to_string());
    let range = |file: &str| {
        subid::find(&read(file)?, &name, uid, count).map_err(|e| Error::Prerequisite(format!("{file}: {e}")))
    };
    let (uids, gids) = (range("/etc/subuid")?, range("/etc/subgid")?);
    Ok(SubidPlan {
        newuidmap: binary::find_system("newuidmap")?,
        newgidmap: binary::find_system("newgidmap")?,
        uid_start: uids.start,
        gid_start: gids.start,
        count,
    })
}

/// Checks `spec` and resolves everything the helper needs.
#[doc(hidden)]
pub fn plan(spec: &Spec) -> Result<Plan> {
    spec.check().map_err(Error::InvalidSpec)?;
    if spec.seccomp {
        return Err(Error::Unsupported("seccomp for sandboxed programs"));
    }
    Ok(Plan {
        spec: spec.clone(),
        root: spec.run_dir.join("sandbox-root"),
        pid_file: pid_file(&spec.run_dir),
        subid: match spec.ids {
            Ids::Subordinate { count } => Some(resolve_subids(count)?),
            Ids::Caller => None,
        },
        net: net_plan(spec)?,
    })
}

/// Writes `plan` to `<run_dir>/sandbox.json`, with the directories the helper uses.
fn write_plan(plan: &Plan) -> Result<PathBuf> {
    let run_dir = &plan.spec.run_dir;
    std::fs::create_dir_all(&plan.root)?;
    std::fs::create_dir_all(run_dir.join("sock"))?;
    let _ = std::fs::remove_file(&plan.pid_file);
    let path = run_dir.join("sandbox.json");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(plan).map_err(|e| Error::InvalidSpec(e.to_string()))?,
    )?;
    Ok(path)
}

/// The command line that starts the helper on `plan_path`, inside a systemd scope when
/// `cgroup` is set and scopes are available.
fn launcher(helper: &Path, plan_path: &Path, cgroup: Option<&Cgroup>) -> (PathBuf, Vec<String>) {
    let run = vec!["run".to_string(), plan_path.display().to_string()];
    match cgroup {
        Some(c) if cgroups_available() => {
            let mut args: Vec<String> = ["--user", "--scope", "--quiet", "--collect"].map(String::from).to_vec();
            args.extend(scope_properties(c));
            args.push("--".into());
            args.push(helper.display().to_string());
            args.extend(run);
            (PathBuf::from("systemd-run"), args)
        }
        _ => (helper.to_path_buf(), run),
    }
}

/// Starts the program `spec` describes. The helper is the returned child, in a process group
/// of its own, with the caller's `stdio`.
pub fn spawn(spec: &Spec, stdio: Stdio) -> Result<Sandbox> {
    let helper = find_helper()?;
    let plan = plan(spec)?;
    let path = write_plan(&plan)?;
    let (program, args) = launcher(&helper, &path, spec.limits.cgroup.as_ref());
    let child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(stdio.stdout)
        .stderr(stdio.stderr)
        .process_group(0)
        .spawn()?;
    Ok(Sandbox { child })
}

/// Starts `vmm` with in-sandbox `args` under the sandbox `helper` for `spec`. Guest serial is
/// appended to `spec.console_log`; the VMM's and the helper's stderr go to `stderr_log`.
pub(crate) fn spawn_vmm(helper: &Path, vmm: &Path, args: &[String], spec: &VmSpec, stderr_log: &Path) -> Result<Proc> {
    let sandbox = vmm_spec(spec, vmm, args);
    let plan = plan(&sandbox)?;
    let path = write_plan(&plan)?;
    let (program, args) = launcher(helper, &path, sandbox.limits.cgroup.as_ref());
    process::spawn(&program, &args, &spec.console_log, stderr_log).map(|p| p.with_vmm_pid_file(&plan.pid_file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Disk;

    fn spec() -> VmSpec {
        VmSpec {
            kernel: "/k/vmlinux".into(),
            initramfs: Some("/k/initramfs".into()),
            cmdline: Vec::new(),
            disks: vec![
                Disk {
                    path: "/d/ro.img".into(),
                    read_only: true,
                },
                Disk {
                    path: "/d/rw.img".into(),
                    read_only: false,
                },
            ],
            vcpus: 2,
            memory_mib: 512,
            vsock: None,
            net: None,
            console_log: "/run/vm/console.log".into(),
            run_dir: "/run/vm".into(),
        }
    }

    fn targets(binds: &[Mount]) -> Vec<(String, String, bool)> {
        binds
            .iter()
            .map(|b| match b {
                Mount::Bind {
                    source,
                    target,
                    writable,
                } => (source.display().to_string(), target.display().to_string(), *writable),
                Mount::Tmpfs { .. } => panic!("the VMM gets no tmpfs"),
            })
            .collect()
    }

    fn exec_spec() -> Spec {
        Spec {
            command: Command {
                program: Program::Path("/bin/sh".into()),
                arg0: None,
                args: vec!["-c".into(), "true".into()],
                env: Some(vec![("PATH".into(), "/bin".into())]),
                cwd: "/".into(),
                user: None,
            },
            root: Root::Overlay {
                lowers: vec!["/l".into()],
                upper: "/u".into(),
                work: "/w".into(),
            },
            mounts: Vec::new(),
            ids: Ids::Subordinate { count: 65536 },
            network: Network::None,
            nest: true,
            seccomp: true,
            limits: Limits {
                open_files: 1024,
                processes: 1024,
                cgroup: None,
            },
            run_dir: "/run/s".into(),
        }
    }

    #[test]
    fn a_well_formed_spec_passes() {
        assert_eq!(exec_spec().check(), Ok(()));
    }

    #[test]
    fn malformed_specs_are_refused() {
        type Mutation = Box<dyn Fn(&mut Spec)>;
        let bound = || Program::Bound {
            host: "/x".into(),
            target: "/x".into(),
        };
        let cases: Vec<(&str, Mutation)> = vec![
            ("relative cwd", Box::new(|s| s.command.cwd = "app".into())),
            (
                "dotdot mount",
                Box::new(|s| {
                    s.mounts.push(Mount::Tmpfs {
                        target: "/a/../b".into(),
                        size_mib: 1,
                    })
                }),
            ),
            (
                "bound program outside an empty root",
                Box::new(move |s| s.command.program = bound()),
            ),
            ("nest without subordinate ids", Box::new(|s| s.ids = Ids::Caller)),
            (
                "nest in an empty root",
                Box::new(move |s| {
                    s.root = Root::Empty;
                    s.command.program = bound();
                }),
            ),
            (
                "path program in an empty root",
                Box::new(|s| {
                    s.root = Root::Empty;
                    s.nest = false;
                }),
            ),
            (
                "overlay without lowers",
                Box::new(|s| {
                    s.root = Root::Overlay {
                        lowers: vec![],
                        upper: "/u".into(),
                        work: "/w".into(),
                    }
                }),
            ),
            (
                "egress with forwards",
                Box::new(|s| {
                    s.network = Network::Egress(NetSpec {
                        forwards: vec![net::PortForward {
                            protocol: net::Protocol::Tcp,
                            host: 8080,
                            guest: 80,
                        }],
                        ..Default::default()
                    })
                }),
            ),
            (
                "zero subordinate ids",
                Box::new(|s| s.ids = Ids::Subordinate { count: 0 }),
            ),
            (
                "user beyond the range",
                Box::new(|s| {
                    s.command.user = Some(User {
                        uid: 70000,
                        gid: 0,
                        groups: vec![],
                    })
                }),
            ),
            (
                "a user under the caller's ids",
                Box::new(|s| {
                    s.nest = false;
                    s.ids = Ids::Caller;
                    s.command.user = Some(User {
                        uid: 0,
                        gid: 0,
                        groups: vec![],
                    })
                }),
            ),
            (
                "relative program path",
                Box::new(|s| s.command.program = Program::Path("sh".into())),
            ),
        ];
        for (what, mutate) in cases {
            let mut s = exec_spec();
            mutate(&mut s);
            assert!(s.check().is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn the_vmm_sandbox_is_an_empty_root_with_the_callers_ids() {
        let s = vmm_spec(&spec(), Path::new("/bin/vmm"), &["--x".into()]);
        assert_eq!(s.root, Root::Empty);
        assert_eq!(s.ids, Ids::Caller);
        assert!(!s.nest && !s.seccomp);
        assert_eq!(s.command.env, None, "the VMM inherits the caller's environment");
        assert_eq!(
            s.command.program,
            Program::Bound {
                host: "/bin/vmm".into(),
                target: "/vmm".into()
            }
        );
        assert_eq!(s.check(), Ok(()));
    }

    #[test]
    fn the_vmm_sees_only_its_devices_kernel_disks_and_directory() {
        let t = targets(&vmm_spec(&spec(), Path::new("/bin/vmm"), &[]).mounts);
        let expected: Vec<(&str, &str, bool)> = vec![
            ("/dev/kvm", "/dev/kvm", true),
            ("/dev/null", "/dev/null", true),
            ("/dev/urandom", "/dev/urandom", false),
            ("/k/vmlinux", "/vm/kernel", false),
            ("/k/initramfs", "/vm/initramfs", false),
            ("/d/ro.img", "/vm/disk/0", false),
            ("/d/rw.img", "/vm/disk/1", true),
            ("/run/vm/sock", "/vm/sock", true),
        ];
        let expected: Vec<(String, String, bool)> =
            expected.into_iter().map(|(s, d, w)| (s.into(), d.into(), w)).collect();
        assert_eq!(t, expected);
    }

    #[test]
    fn a_network_adds_the_tun_device() {
        let mut s = spec();
        s.net = Some(net::NetSpec::default());
        assert!(targets(&binds(&s)).contains(&(TUN.into(), TUN.into(), true)));
    }

    #[test]
    fn the_scope_limits_follow_the_vm_size() {
        assert_eq!(
            scope_properties(&vm_cgroup(&spec())),
            ["-p", "MemoryMax=768M", "-p", "CPUQuota=300%", "-p", "TasksMax=70"]
        );
    }

    #[test]
    fn the_plan_round_trips_as_json() {
        let plan = Plan {
            spec: exec_spec(),
            root: "/r".into(),
            pid_file: "/p".into(),
            subid: Some(SubidPlan {
                newuidmap: "/usr/bin/newuidmap".into(),
                newgidmap: "/usr/bin/newgidmap".into(),
                uid_start: 100000,
                gid_start: 100000,
                count: 65536,
            }),
            net: Some(NetPlan {
                ip: "/sbin/ip".into(),
                kind: NetKind::Tap(Policy {
                    nft: "/sbin/nft".into(),
                    ruleset: "table inet vmkit {}".into(),
                    pasta: "/bin/pasta".into(),
                    pasta_args: vec!["--quiet".into()],
                }),
            }),
        };
        let back: Plan = serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(back, plan);
    }
}
