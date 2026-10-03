//! The VMM sandbox (kiln spec §9.2). The library writes a [`Plan`] and runs
//! `vmkit-sandbox run <plan.json>`; the helper does the namespace work.
//!
//! Inside, the VMM sees a read-only tmpfs root with only its devices, `/vmm` (itself),
//! `/vm/kernel`, `/vm/initramfs`, `/vm/disk/<n>` and `/vm/sock/`, which is
//! `<run_dir>/sock` on the host. Its paths never depend on where files live on the host.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::binary;
use crate::error::{Error, Result};
use crate::net;
use crate::process::{self, Proc};
use crate::spec::VmSpec;

/// One file or directory the VMM may see, attached by file descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
    /// Host path; opened with `O_NOFOLLOW` semantics (a symlink is refused).
    pub source: PathBuf,
    /// Absolute path inside the sandbox root.
    pub target: PathBuf,
    pub writable: bool,
}

/// Resource limits applied to the VMM process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub open_files: u64,
    pub processes: u64,
}

/// The VM's network (kiln spec §9.3): set up in its namespace before the VMM starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetPlan {
    /// `ip` and `nft`, run inside the namespace before the root is replaced.
    pub ip: PathBuf,
    pub nft: PathBuf,
    /// The nftables ruleset, loaded with `nft -f -`.
    pub ruleset: String,
    /// `pasta` and its options; the helper adds the namespace to attach to.
    pub pasta: PathBuf,
    pub pasta_args: Vec<String>,
}

/// Everything the helper needs to start one VMM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// The VMM binary on the host; it appears at `/vmm` inside.
    pub vmm: PathBuf,
    /// Arguments, already in terms of in-sandbox paths.
    pub args: Vec<String>,
    /// Files and directories under `/vm` (and the device nodes under `/dev`).
    pub binds: Vec<Bind>,
    pub limits: Limits,
    /// Host directory the tmpfs root is mounted on while it is built.
    pub root: PathBuf,
    /// The helper writes the VMM's host PID here.
    pub pid_file: PathBuf,
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

/// The file holding the VMM's host PID once it runs: `<run_dir>/vmm.pid`.
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

/// Whether VMMs go into a cgroup with memory, CPU and task limits: true when the
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
fn binds(spec: &VmSpec) -> Vec<Bind> {
    let bind = |source: &Path, target: &str, writable: bool| Bind {
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

/// The network plan for `spec`, with the host's addresses denied by default egress.
fn net_plan(net: &net::NetSpec) -> Result<NetPlan> {
    net.check().map_err(Error::InvalidSpec)?;
    let host: Vec<Ipv4Addr> = net::host_addresses(&std::fs::read_to_string("/proc/net/fib_trie")?);
    Ok(NetPlan {
        ip: binary::find_system("ip")?,
        nft: binary::find_system("nft")?,
        ruleset: net::ruleset(net, &host),
        pasta: binary::find("pasta", "VMKIT_PASTA")?,
        pasta_args: net::pasta_args(net),
    })
}

/// The cgroup limits for `spec`: guest memory plus the VMM's and pasta's overhead, one CPU
/// per vCPU plus one for the VMM's own threads, and tasks for its device threads.
fn scope_properties(spec: &VmSpec) -> Vec<String> {
    let memory = u64::from(spec.memory_mib) + 256;
    let cpu = (u32::from(spec.vcpus) + 1) * 100;
    let tasks = 64 + u32::from(spec.vcpus) + 2 * spec.devices_needed();
    vec![
        "-p".into(),
        format!("MemoryMax={memory}M"),
        "-p".into(),
        format!("CPUQuota={cpu}%"),
        "-p".into(),
        format!("TasksMax={tasks}"),
    ]
}

/// Starts `vmm` with in-sandbox `args` under the sandbox `helper` for `spec`. Guest serial is
/// appended to `spec.console_log`; the VMM's and the helper's stderr go to `stderr_log`.
pub(crate) fn spawn(helper: &Path, vmm: &Path, args: &[String], spec: &VmSpec, stderr_log: &Path) -> Result<Proc> {
    let net = spec.net.as_ref().map(net_plan).transpose()?;
    let root = spec.run_dir.join("sandbox-root");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(spec.run_dir.join("sock"))?;
    let pid_file = pid_file(&spec.run_dir);
    let _ = std::fs::remove_file(&pid_file);
    let plan = Plan {
        vmm: vmm.to_path_buf(),
        args: args.to_vec(),
        binds: binds(spec),
        limits: Limits {
            open_files: 1024,
            processes: 256,
        },
        root,
        pid_file,
        net,
    };
    let pid_file = plan.pid_file.clone();
    let plan_path = spec.run_dir.join("sandbox.json");
    std::fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&plan).map_err(|e| Error::InvalidSpec(e.to_string()))?,
    )?;
    let run = vec![
        helper.display().to_string(),
        "run".into(),
        plan_path.display().to_string(),
    ];
    if cgroups_available() {
        let mut args: Vec<String> = ["--user", "--scope", "--quiet", "--collect"].map(String::from).to_vec();
        args.extend(scope_properties(spec));
        args.push("--".into());
        args.extend(run);
        process::spawn(Path::new("systemd-run"), &args, &spec.console_log, stderr_log)
    } else {
        process::spawn(helper, &run[1..], &spec.console_log, stderr_log)
    }
    .map(|p| p.with_vmm_pid_file(&pid_file))
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

    fn targets(binds: &[Bind]) -> Vec<(String, String, bool)> {
        binds
            .iter()
            .map(|b| {
                (
                    b.source.display().to_string(),
                    b.target.display().to_string(),
                    b.writable,
                )
            })
            .collect()
    }

    #[test]
    fn the_vmm_sees_only_its_devices_kernel_disks_and_directory() {
        let t = targets(&binds(&spec()));
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
            scope_properties(&spec()),
            ["-p", "MemoryMax=768M", "-p", "CPUQuota=300%", "-p", "TasksMax=70"]
        );
    }

    #[test]
    fn the_plan_round_trips_as_json() {
        let plan = Plan {
            vmm: "/bin/vmm".into(),
            args: vec!["--x".into()],
            binds: binds(&spec()),
            limits: Limits {
                open_files: 1,
                processes: 2,
            },
            root: "/r".into(),
            pid_file: "/p".into(),
            net: Some(NetPlan {
                ip: "/sbin/ip".into(),
                nft: "/sbin/nft".into(),
                ruleset: "table inet vmkit {}".into(),
                pasta: "/bin/pasta".into(),
                pasta_args: vec!["--quiet".into()],
            }),
        };
        let back: Plan = serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(back, plan);
    }
}
