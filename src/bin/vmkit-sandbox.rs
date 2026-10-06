//! `vmkit-sandbox`: runs one VMM inside unprivileged user, PID, mount, net, IPC and UTS
//! namespaces with a minimal root (kiln spec §9.2). Started by the vmkit library.
//!
//!   vmkit-sandbox run <plan.json>      outer: user + PID namespaces, attaches pasta, waits for the program
//!   vmkit-sandbox userns <plan.json>   for subordinate ids: the user namespace `run` maps from outside
//!   vmkit-sandbox init <plan.json>     inner (PID 1): mount, net, IPC and UTS namespaces, then the program
//!
//! Stages talk over a socket on the later stage's stdin. `userns` sends `unshared` once its
//! user namespace exists and waits for `mapped`, which `run` sends after `newuidmap` and
//! `newgidmap`. `init` sends `ready` once its namespaces exist, and waits for `go`, which its
//! parent sends after attaching `pasta`. If a parent dies first, the stage sees end-of-file.
#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vmkit-sandbox: only Linux is supported");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::Path;
    use std::process::{Command, ExitStatus, Stdio};

    use rustix::fs::{CWD, Dir, FileType, Mode, OFlags, fstat, openat, statvfs};
    use rustix::io::{FdFlags, fcntl_setfd};
    use rustix::mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MountFlags, MountPropagationFlags, MoveMountFlags, OpenTreeFlags,
        UnmountFlags, fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, mount, mount_change,
        mount_remount, move_mount, open_tree, unmount,
    };
    use rustix::process::{Gid, Uid};
    use rustix::process::{
        Resource, Rlimit, Signal, getpid, kill_process, pivot_root, set_parent_process_death_signal, setrlimit,
    };
    use rustix::thread::{
        CapabilitySet, UnshareFlags, capabilities, clear_ambient_capability_set, configure_capability_in_ambient_set,
        set_capabilities, set_no_new_privs, set_thread_groups, set_thread_res_gid, set_thread_res_uid,
    };
    use vmkit::net::{GATEWAY, PREFIX, TAP};
    use vmkit::sandbox::{Mount, NetKind, NetPlan, Plan, Policy, Program, Root, SubidPlan};

    /// The capabilities `init` needs inside the user namespace: mounts and pivot_root,
    /// then the net namespace's tap and nftables. They reach `init` (and `pasta`) across
    /// exec as ambient capabilities; an identity-mapped, non-root user loses everything else.
    const SETUP: [CapabilitySet; 2] = [CapabilitySet::SYS_ADMIN, CapabilitySet::NET_ADMIN];

    fn fail(what: &str, e: impl std::fmt::Display) -> ! {
        eprintln!("vmkit-sandbox: {what}: {e}");
        std::process::exit(125);
    }

    fn read_plan(path: &str) -> Plan {
        let bytes = fs::read(path).unwrap_or_else(|e| fail("reading the plan", e));
        serde_json::from_slice(&bytes).unwrap_or_else(|e| fail("parsing the plan", e))
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        match (args.get(1).map(String::as_str), args.get(2)) {
            (Some("run"), Some(plan)) => run(plan),
            (Some("userns"), Some(plan)) => userns(plan),
            (Some("init"), Some(plan)) => init(plan),
            _ => fail("usage", "vmkit-sandbox run|userns|init <plan.json>"),
        }
    }

    /// Unshares namespaces. This process is single-threaded and does not share its
    /// file-descriptor table, so the `unshare` safety requirement (no `FILES`) holds.
    fn unshare(flags: UnshareFlags) {
        assert!(
            !flags.contains(UnshareFlags::FILES),
            "unshare must not be asked to unshare the descriptor table"
        );
        #[allow(unsafe_code)]
        // SAFETY: `flags` never includes `UnshareFlags::FILES` (see the doc comment).
        let r = unsafe { rustix::thread::unshare_unsafe(flags) };
        r.unwrap_or_else(|e| fail("unshare", e));
    }

    /// Marks every inherited descriptor above stderr close-on-exec, so nothing the
    /// caller leaked reaches the VMM.
    fn close_inherited_fds() {
        let dir = openat(
            CWD,
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|e| fail("listing descriptors", e));
        // The listing's own descriptor is open for the whole listing, so it is excluded by number.
        let listing = dir.as_raw_fd();
        let fds: Vec<i32> = Dir::new(dir)
            .unwrap_or_else(|e| fail("listing descriptors", e))
            .filter_map(|e| e.ok()?.file_name().to_str().ok()?.parse().ok())
            .filter(|&fd| fd > 2 && fd != listing)
            .collect();
        for fd in fds {
            #[allow(unsafe_code)]
            // SAFETY: `fd` was listed as open, is not the listing's own descriptor (which is
            // closed by now), and nothing in this single-threaded process closes or opens
            // descriptors between the listing and this call, so it still names an open descriptor.
            let fd = unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) };
            let _ = fcntl_setfd(fd, FdFlags::CLOEXEC);
        }
    }

    fn pass_setup_capabilities() {
        let mut caps = capabilities(None).unwrap_or_else(|e| fail("reading capabilities", e));
        caps.inheritable = SETUP[0] | SETUP[1];
        set_capabilities(None, caps).unwrap_or_else(|e| fail("setting inheritable capabilities", e));
        for cap in SETUP {
            configure_capability_in_ambient_set(cap, true).unwrap_or_else(|e| fail("raising an ambient capability", e));
        }
    }

    /// Gives this process a new, empty session keyring, so the VMM cannot reach the keys
    /// in the caller's session keyring.
    fn leave_session_keyring() {
        #[allow(unsafe_code)]
        // SAFETY: KEYCTL_JOIN_SESSION_KEYRING takes one pointer, the name of the keyring to join,
        // or NULL for a new anonymous one. NULL is passed, so the kernel reads no memory of ours.
        let r = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                libc::KEYCTL_JOIN_SESSION_KEYRING as libc::c_long,
                std::ptr::null::<libc::c_char>(),
            )
        };
        if r < 0 {
            fail("joining a new session keyring", std::io::Error::last_os_error());
        }
    }

    /// Sets both limits of `resource` to `n`.
    fn limit(resource: Resource, what: &str, n: u64) {
        setrlimit(
            resource,
            Rlimit {
                current: Some(n),
                maximum: Some(n),
            },
        )
        .unwrap_or_else(|e| fail(&format!("limiting {what}"), e))
    }

    /// Ends this process the way the VMM ended: the same exit code, or the same signal.
    fn mirror(status: ExitStatus) -> ! {
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
        if let Some(sig) = status.signal().and_then(Signal::from_named_raw) {
            let _ = kill_process(getpid(), sig);
        }
        // An ignored signal (Rust ignores SIGPIPE) cannot be re-raised.
        std::process::exit(128 + status.signal().unwrap_or(0));
    }

    fn run(plan_path: &str) {
        close_inherited_fds();
        let plan = read_plan(plan_path);
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        if uid == 0 || rustix::process::geteuid().as_raw() == 0 {
            fail(
                "refusing to run as root",
                "the VMM would keep every capability in its namespaces; run vmkit as an unprivileged user (kiln spec T6)",
            );
        }
        if let Some(subid) = &plan.subid {
            run_subordinate(subid, plan_path);
        }
        unshare(UnshareFlags::NEWUSER | UnshareFlags::NEWPID);
        // Identity-map the invoking user (no root inside the namespace).
        let write = |file: &str, data: String| {
            fs::write(file, data).unwrap_or_else(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    fail(
                        &format!("writing {file}"),
                        format!(
                            "{e} (AppArmor restricts unprivileged user namespaces here: \
                             run vmkit's scripts/install-apparmor.sh for this binary)"
                        ),
                    )
                }
                fail(&format!("writing {file}"), e)
            })
        };
        write("/proc/self/setgroups", "deny".into());
        write("/proc/self/uid_map", format!("{uid} {uid} 1"));
        write("/proc/self/gid_map", format!("{gid} {gid} 1"));
        continue_in_userns(&plan, plan_path);
    }

    /// The rest of the outer helper, inside the sandbox's user namespace: limits, then `init`
    /// as PID 1 of the new PID namespace, `pasta`, and the program's exit.
    fn continue_in_userns(plan: &Plan, plan_path: &str) -> ! {
        // Nothing in the sandbox (the VMM above all) may create user namespaces of its own:
        // this AppArmor profile's permission would otherwise reach the program too. A nested
        // program's namespace is the one exception; `init` creates it and closes the door behind it.
        let nested = if plan.spec.nest { "1" } else { "0" };
        fs::write("/proc/sys/user/max_user_namespaces", nested)
            .unwrap_or_else(|e| fail("writing /proc/sys/user/max_user_namespaces", e));
        // No core dump holds guest memory.
        limit(Resource::Core, "core dumps", 0);
        // Nothing in the sandbox may trace this stage.
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap_or_else(|e| fail("making the helper undumpable", e));
        pass_setup_capabilities();
        let (ours, theirs) = UnixStream::pair().unwrap_or_else(|e| fail("socketpair", e));
        let me = std::env::current_exe().unwrap_or_else(|e| fail("finding myself", e));
        // The first child is PID 1 of the new PID namespace: the VMM after `init` execs it.
        let mut child = Command::new(me)
            .args(["init", plan_path])
            .stdin(std::os::fd::OwnedFd::from(theirs))
            .spawn()
            .unwrap_or_else(|e| fail("starting the init", e));
        let pid = child.id();
        fs::write(&plan.pid_file, format!("{pid}\n")).unwrap_or_else(|e| fail("writing the pid file", e));
        let mut lines = BufReader::new(&ours);
        let mut line = String::new();
        if lines.read_line(&mut line).is_ok() && line == "ready\n" {
            if let Some(NetPlan {
                kind: NetKind::Tap(policy) | NetKind::Egress(policy),
                ..
            }) = &plan.net
            {
                attach_pasta(policy, pid);
            }
            let _ = (&ours).write_all(b"go\n");
        }
        let status = child.wait().unwrap_or_else(|e| fail("waiting for the sandbox", e));
        // A supervising `init` reports how the program ended: as PID 1 it cannot re-raise a signal.
        let mut report = String::new();
        let _ = lines.read_line(&mut report);
        drop(lines);
        drop(ours);
        mirror(reported(&report).unwrap_or(status));
    }

    /// The status in `init`'s report (`exit <code>` or `signal <number>`).
    fn reported(report: &str) -> Option<ExitStatus> {
        let (kind, n) = report.trim_end().split_once(' ')?;
        let n: i32 = n.parse().ok()?;
        match kind {
            "exit" => Some(ExitStatus::from_raw((n & 0xff) << 8)),
            "signal" => Some(ExitStatus::from_raw(n & 0x7f)),
            _ => None,
        }
    }

    /// For subordinate ids: starts `userns`, maps its user namespace with `newuidmap` and
    /// `newgidmap` once it exists, and ends as it ends.
    fn run_subordinate(subid: &SubidPlan, plan_path: &str) -> ! {
        let (ours, theirs) = UnixStream::pair().unwrap_or_else(|e| fail("socketpair", e));
        let me = std::env::current_exe().unwrap_or_else(|e| fail("finding myself", e));
        let mut child = Command::new(me)
            .args(["userns", plan_path])
            .stdin(std::os::fd::OwnedFd::from(theirs))
            .spawn()
            .unwrap_or_else(|e| fail("starting the user namespace", e));
        let mut lines = BufReader::new(&ours);
        let mut line = String::new();
        if lines.read_line(&mut line).is_err() || line != "unshared\n" {
            // The stage failed and said why.
            mirror(child.wait().unwrap_or_else(|e| fail("waiting for the sandbox", e)));
        }
        map_subordinate(subid, child.id());
        (&ours)
            .write_all(b"mapped\n")
            .unwrap_or_else(|e| fail("signalling the id maps", e));
        drop(lines);
        drop(ours);
        mirror(child.wait().unwrap_or_else(|e| fail("waiting for the sandbox", e)));
    }

    /// Maps root to the caller and `1..=count` to the subordinate ranges in `pid`'s user namespace.
    fn map_subordinate(s: &SubidPlan, pid: u32) {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        for (tool, own, start) in [(&s.newuidmap, uid, s.uid_start), (&s.newgidmap, gid, s.gid_start)] {
            let args = [pid, 0, own, 1, 1, start, s.count].map(|n| n.to_string());
            let status = Command::new(tool)
                .args(args)
                .stdin(Stdio::null())
                .status()
                .unwrap_or_else(|e| fail(&format!("starting {}", tool.display()), e));
            if !status.success() {
                fail(&tool.display().to_string(), format!("exited with {status}"));
            }
        }
    }

    /// The user namespace for subordinate ids: `run` maps it from outside.
    fn userns(plan_path: &str) {
        set_parent_process_death_signal(Some(Signal::KILL)).unwrap_or_else(|e| fail("pdeathsig", e));
        let plan = read_plan(plan_path);
        unshare(UnshareFlags::NEWUSER);
        let control = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .unwrap_or_else(|e| fail("dup stdin", e));
        let control = UnixStream::from(control);
        (&control)
            .write_all(b"unshared\n")
            .unwrap_or_else(|e| fail("signalling the user namespace", e));
        let mut line = String::new();
        BufReader::new(&control)
            .read_line(&mut line)
            .unwrap_or_else(|e| fail("waiting for the id maps", e));
        if line != "mapped\n" {
            fail("waiting for the id maps", "the outer helper went away");
        }
        drop(control);
        unshare(UnshareFlags::NEWPID);
        continue_in_userns(&plan, plan_path);
    }

    /// Starts `pasta` on the VM's namespace. It returns once its interface is configured
    /// and keeps running in the PID namespace, so it ends with the VMM. After it daemonizes
    /// its daemon is a child of the VMM (PID 1), which never reaps it if it exits early; it
    /// cannot outlive the PID namespace.
    fn attach_pasta(net: &Policy, pid: u32) {
        let status = Command::new(&net.pasta)
            .args(&net.pasta_args)
            .args(["--netns", &format!("/proc/{pid}/ns/net"), "--netns-only"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap_or_else(|e| fail(&format!("starting {}", net.pasta.display()), e));
        if !status.success() {
            let child = rustix::process::Pid::from_raw(pid as i32).unwrap_or_else(|| fail("child pid", pid));
            let _ = kill_process(child, Signal::KILL);
            fail("pasta", format!("{} exited with {status}", net.pasta.display()));
        }
    }

    /// Runs a setup tool inside the namespace; failures end the sandbox with its message.
    fn tool(program: &Path, args: &[&str], input: Option<&str>) {
        let mut child = Command::new(program)
            .args(args)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| fail(&format!("starting {}", program.display()), e));
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            stdin
                .write_all(text.as_bytes())
                .unwrap_or_else(|e| fail("writing the ruleset", e));
        }
        let status = child.wait().unwrap_or_else(|e| fail("waiting for a setup tool", e));
        if !status.success() {
            fail(&format!("{} {}", program.display(), args.join(" ")), status);
        }
    }

    /// The tap the VMM opens (owned by the invoking user), routing, and the nftables policy.
    fn setup_net(ip: &Path, net: &Policy) {
        let uid = rustix::process::getuid().as_raw().to_string();
        let gid = rustix::process::getgid().as_raw().to_string();
        let gateway = format!("{GATEWAY}/{PREFIX}");
        tool(ip, &["link", "set", "lo", "up"], None);
        tool(
            ip,
            &["tuntap", "add", TAP, "mode", "tap", "user", &uid, "group", &gid],
            None,
        );
        tool(ip, &["addr", "add", &gateway, "dev", TAP], None);
        tool(ip, &["link", "set", TAP, "up"], None);
        // Both apply to this namespace only. `route_localnet` lets a forwarded connection that
        // pasta spliced from host loopback leave through the tap after DNAT.
        let sysctl = |path: &str| fs::write(path, "1").unwrap_or_else(|e| fail(&format!("writing {path}"), e));
        sysctl("/proc/sys/net/ipv4/ip_forward");
        sysctl(&format!("/proc/sys/net/ipv4/conf/{TAP}/route_localnet"));
        tool(&net.nft, &["-f", "-"], Some(&net.ruleset));
    }

    /// A mount of `source` (opened without following a final symlink) onto `target`, which is
    /// created when missing if `create` (else it must exist).
    fn attach(source: &Path, target: &Path, writable: bool, create: bool) {
        let fd = open_tree(
            CWD,
            source,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC | OpenTreeFlags::AT_SYMLINK_NOFOLLOW,
        )
        .unwrap_or_else(|e| fail(&format!("opening {}", source.display()), e));
        // The type of what was opened, not of whatever the path names now.
        let kind = FileType::from_raw_mode(
            fstat(&fd)
                .unwrap_or_else(|e| fail(&format!("stat {}", source.display()), e))
                .st_mode,
        );
        if kind == FileType::Symlink {
            fail(&source.display().to_string(), "is a symlink, which vmkit never follows");
        }
        if fs::symlink_metadata(target).is_err() {
            if !create {
                fail(
                    &target.display().to_string(),
                    "a mount target must exist under Root::Host",
                );
            }
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|e| fail("mkdir", e));
            }
            if kind == FileType::Directory {
                fs::create_dir_all(target).unwrap_or_else(|e| fail("mkdir", e));
            } else {
                fs::File::create(target).unwrap_or_else(|e| fail(&format!("creating {}", target.display()), e));
            }
        }
        move_mount(&fd, "", CWD, target, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)
            .unwrap_or_else(|e| fail(&format!("attaching {}", target.display()), e));
        if !writable {
            // A user namespace cannot clear the source mount's locked flags, so keep them.
            let st = statvfs(target).unwrap_or_else(|e| fail(&format!("statvfs {}", target.display()), e));
            // The kernel's ST_* values, which statvfs reports. (rustix's `StatVfsMountFlags::RELATIME`
            // is MS_RELATIME, a different bit, so the flags are mapped explicitly.)
            const ST_NOSUID: u64 = 0x2;
            const ST_NODEV: u64 = 0x4;
            const ST_NOEXEC: u64 = 0x8;
            const ST_NOATIME: u64 = 0x400;
            const ST_NODIRATIME: u64 = 0x800;
            const ST_RELATIME: u64 = 0x1000;
            let reported = st.f_flag.bits() as u64;
            let mut locked = MountFlags::empty();
            for (st_flag, flag) in [
                (ST_NOSUID, MountFlags::NOSUID),
                (ST_NODEV, MountFlags::NODEV),
                (ST_NOEXEC, MountFlags::NOEXEC),
                (ST_NOATIME, MountFlags::NOATIME),
                (ST_NODIRATIME, MountFlags::NODIRATIME),
                (ST_RELATIME, MountFlags::RELATIME),
            ] {
                if reported & st_flag != 0 {
                    locked |= flag;
                }
            }
            if !locked.intersects(MountFlags::NOATIME | MountFlags::RELATIME) {
                locked |= MountFlags::STRICTATIME;
            }
            mount_remount(
                target,
                MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | locked,
                "",
            )
            .unwrap_or_else(|e| fail(&format!("making {} read-only", target.display()), e));
        }
    }

    /// A tmpfs of `size_mib` on `target`, created if missing.
    fn tmpfs(target: &Path, size_mib: u32) {
        fs::create_dir_all(target).unwrap_or_else(|e| fail(&format!("mkdir {}", target.display()), e));
        let options =
            std::ffi::CString::new(format!("mode=0755,size={size_mib}m")).unwrap_or_else(|e| fail("tmpfs options", e));
        mount(
            "tmpfs",
            target,
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            Some(options.as_c_str()),
        )
        .unwrap_or_else(|e| fail(&format!("mounting a tmpfs on {}", target.display()), e));
    }

    fn init(plan_path: &str) {
        // If the outer helper dies, so does everything in this PID namespace.
        set_parent_process_death_signal(Some(Signal::KILL)).unwrap_or_else(|e| fail("pdeathsig", e));
        let plan = read_plan(plan_path);
        // The library checked the spec; a plan file is checked again before it is trusted.
        plan.spec.check().unwrap_or_else(|e| fail("the plan", e));
        unshare(UnshareFlags::NEWNS | UnshareFlags::NEWNET | UnshareFlags::NEWIPC | UnshareFlags::NEWUTS);
        match &plan.net {
            Some(NetPlan {
                ip,
                kind: NetKind::Tap(policy),
            }) => setup_net(ip, policy),
            Some(_) => fail("the network", "not implemented yet"),
            None => {}
        }
        // `go` also proves the outer helper outlived the death-signal setup above.
        let control = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .unwrap_or_else(|e| fail("dup stdin", e));
        let control = UnixStream::from(control);
        (&control)
            .write_all(b"ready\n")
            .unwrap_or_else(|e| fail("signalling ready", e));
        let mut line = String::new();
        BufReader::new(&control)
            .read_line(&mut line)
            .unwrap_or_else(|e| fail("waiting for go", e));
        if line != "go\n" {
            fail("waiting for go", "the outer helper went away");
        }
        // The program's stdin, from the host: the new root need not have a /dev/null.
        let null = fs::File::open("/dev/null").unwrap_or_else(|e| fail("opening /dev/null", e));
        rustix::stdio::dup2_stdin(&null).unwrap_or_else(|e| fail("stdin", e));
        drop(null);
        mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC)
            .unwrap_or_else(|e| fail("making mounts private", e));
        build_root(&plan);
        limit(Resource::Nofile, "open files", plan.spec.limits.open_files);
        limit(Resource::Nproc, "processes", plan.spec.limits.processes);
        limit(Resource::Core, "core dumps", 0);
        leave_session_keyring();
        if plan.spec.root == Root::Empty && !plan.spec.nest {
            // The VMM sandbox: the program is PID 1 itself.
            drop(control);
            exec_program(&plan);
        }
        supervise(&plan, control);
    }

    /// Mounts the root `plan` asks for on `plan.root`, attaches the mounts, and pivots into it.
    fn build_root(plan: &Plan) {
        let root = &plan.root;
        fs::create_dir_all(root).unwrap_or_else(|e| fail("creating the root", e));
        let inside = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));
        let create = match &plan.spec.root {
            Root::Empty => {
                mount(
                    "tmpfs",
                    root,
                    "tmpfs",
                    MountFlags::NOSUID | MountFlags::NODEV,
                    Some(c"mode=0755,size=1m"),
                )
                .unwrap_or_else(|e| fail("mounting the root tmpfs", e));
                let Program::Bound { host, target } = &plan.spec.command.program else {
                    fail("the program", "Root::Empty runs a bound program")
                };
                attach(host, &inside(target), false, true);
                true
            }
            Root::Host => {
                host_root(root);
                false
            }
            Root::Overlay { lowers, upper, work } => {
                overlay_root(root, lowers, upper, work);
                container_mounts(root, plan.subid.is_some());
                true
            }
        };
        for m in &plan.spec.mounts {
            match m {
                Mount::Bind {
                    source,
                    target,
                    writable,
                } => attach(source, &inside(target), *writable, create),
                Mount::Tmpfs { target, size_mib } => tmpfs(&inside(target), *size_mib),
            }
        }
        // pivot_root(".", ".") stacks the old root under the new one, so the new root needs no
        // directory for it (a read-only root could not hold one).
        std::env::set_current_dir(root).unwrap_or_else(|e| fail("chdir to the root", e));
        pivot_root(".", ".").unwrap_or_else(|e| fail("pivot_root", e));
        unmount(".", UnmountFlags::DETACH).unwrap_or_else(|e| fail("detaching the old root", e));
        std::env::set_current_dir("/").unwrap_or_else(|e| fail("chdir /", e));
        if plan.spec.root == Root::Empty {
            mount_remount("/", MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV, "")
                .unwrap_or_else(|e| fail("making the root read-only", e));
        }
    }

    /// The kernel's `struct mount_attr` (MOUNT_ATTR_SIZE_VER0).
    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    const MOUNT_ATTR_RDONLY: u64 = 0x1;
    const MOUNT_ATTR_NOSUID: u64 = 0x2;
    const AT_RECURSIVE: libc::c_uint = 0x8000;

    /// Sets `attrs` on every mount of the detached tree `tree`.
    fn set_tree_attrs(tree: &std::os::fd::OwnedFd, attrs: u64) {
        let attr = MountAttr {
            attr_set: attrs,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        #[allow(unsafe_code)]
        // SAFETY: mount_setattr reads `size_of::<MountAttr>()` bytes from `attr`, a live
        // `repr(C)` value with the layout of the kernel's `struct mount_attr`; the path is an empty
        // C string (with AT_EMPTY_PATH the descriptor itself is the target), and `tree` is open.
        let r = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                tree.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint | AT_RECURSIVE,
                &attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            )
        };
        if r < 0 {
            fail("making the host tree read-only", std::io::Error::last_os_error());
        }
    }

    /// The host's tree, recursively read-only and nosuid, on `root`, with the sandbox's own `/proc`.
    fn host_root(root: &Path) {
        let tree = open_tree(
            CWD,
            "/",
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC | OpenTreeFlags::AT_RECURSIVE,
        )
        .unwrap_or_else(|e| fail("cloning the host tree", e));
        set_tree_attrs(&tree, MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID);
        move_mount(&tree, "", CWD, root, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)
            .unwrap_or_else(|e| fail("attaching the host tree", e));
        mount(
            "proc",
            root.join("proc"),
            "proc",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            None,
        )
        .unwrap_or_else(|e| fail("mounting /proc", e));
    }

    /// An overlay of `lowers` (top first), `upper` and `work` on `root`, with user xattrs.
    fn overlay_root(root: &Path, lowers: &[std::path::PathBuf], upper: &Path, work: &Path) {
        let fs = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC).unwrap_or_else(|e| fail("opening overlayfs", e));
        let set = |key: &str, value: &Path| {
            fsconfig_set_string(&fs, key, value).map_err(|e| (format!("overlay {key} {}", value.display()), e))
        };
        // One `lowerdir+` per layer (Linux 6.8), in `lowerdir=` order: the first is the top. It
        // takes paths of any length; a single `lowerdir=` string is bounded by a page.
        let per_layer = lowers.iter().try_for_each(|l| set("lowerdir+", l));
        match per_layer {
            Ok(()) => {
                set("upperdir", upper)
                    .and_then(|()| set("workdir", work))
                    .unwrap_or_else(|(what, e)| fail(&what, e));
                fsconfig_set_flag(&fs, "userxattr").unwrap_or_else(|e| fail("overlay userxattr", e));
                fsconfig_create(&fs).unwrap_or_else(|e| fail("creating the overlay", e));
                let mnt = fsmount(&fs, FsMountFlags::FSMOUNT_CLOEXEC, MountAttrFlags::empty())
                    .unwrap_or_else(|e| fail("mounting the overlay", e));
                move_mount(&mnt, "", CWD, root, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)
                    .unwrap_or_else(|e| fail("attaching the overlay", e));
            }
            Err((_, rustix::io::Errno::INVAL)) => {
                let joined: Vec<String> = lowers.iter().map(|l| l.display().to_string()).collect();
                let options = format!(
                    "lowerdir={},upperdir={},workdir={},userxattr",
                    joined.join(":"),
                    upper.display(),
                    work.display()
                );
                if options.len() > 4000 {
                    fail(
                        "the overlay",
                        "too many layers for this kernel (Linux 6.8 lifts the limit)",
                    );
                }
                let options = std::ffi::CString::new(options).unwrap_or_else(|e| fail("overlay options", e));
                mount(
                    "overlay",
                    root,
                    "overlay",
                    MountFlags::empty(),
                    Some(options.as_c_str()),
                )
                .unwrap_or_else(|e| fail("mounting the overlay", e));
            }
            Err((what, e)) => fail(&what, e),
        }
    }

    /// `/proc`, a read-only `/sys`, and a `/dev` with the host's null, zero, full, random,
    /// urandom and tty, a devpts of its own and a shm tmpfs. `tty_group`: gid 5 is mapped.
    fn container_mounts(root: &Path, tty_group: bool) {
        let at = |p: &str| {
            let dir = root.join(p);
            fs::create_dir_all(&dir).unwrap_or_else(|e| fail(&format!("mkdir /{p}"), e));
            dir
        };
        let mount_at = |source: &str, p: &str, fstype: &str, flags: MountFlags, options: &str| {
            let options = std::ffi::CString::new(options).unwrap_or_else(|e| fail("mount options", e));
            mount(source, at(p), fstype, flags, Some(options.as_c_str()))
                .unwrap_or_else(|e| fail(&format!("mounting /{p}"), e));
        };
        let hardened = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
        mount_at("proc", "proc", "proc", hardened, "");
        mount_at("sysfs", "sys", "sysfs", hardened | MountFlags::RDONLY, "");
        mount_at(
            "tmpfs",
            "dev",
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            "mode=0755,size=64k",
        );
        for d in ["null", "zero", "full", "random", "urandom", "tty"] {
            let host = Path::new("/dev").join(d);
            attach(&host, &root.join("dev").join(d), true, true);
        }
        for (link, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
            ("ptmx", "pts/ptmx"),
        ] {
            std::os::unix::fs::symlink(target, root.join("dev").join(link))
                .unwrap_or_else(|e| fail(&format!("linking /dev/{link}"), e));
        }
        let pts = if tty_group {
            "newinstance,ptmxmode=0666,mode=0620,gid=5"
        } else {
            "newinstance,ptmxmode=0666,mode=0620"
        };
        mount_at(
            "devpts",
            "dev/pts",
            "devpts",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            pts,
        );
        mount_at(
            "tmpfs",
            "dev/shm",
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            "mode=1777,size=64m",
        );
    }

    /// Forks this single-threaded process; `None` in the child.
    fn fork() -> Option<rustix::process::Pid> {
        #[allow(unsafe_code)]
        // SAFETY: the helper never starts threads, so the child inherits no lock another thread
        // holds; it only makes system calls and allocates before it execs or exits.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => fail("fork", std::io::Error::last_os_error()),
            0 => None,
            p => rustix::process::Pid::from_raw(p),
        }
    }

    /// As PID 1: starts the program, reaps every process until the program ends, reports how it
    /// ended on `control`, and ends the same way (which ends everything else in the namespace).
    fn supervise(plan: &Plan, control: UnixStream) -> ! {
        // Nothing in the namespace may trace or inspect init (Review Focus 1): the program
        // shares its uid, and a dumpable init would be open to it.
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap_or_else(|e| fail("making init undumpable", e));
        let nest = plan
            .spec
            .nest
            .then(|| UnixStream::pair().unwrap_or_else(|e| fail("socketpair", e)));
        let Some(program) = fork() else {
            if let Some((ours, theirs)) = nest {
                drop(ours);
                enter_nested_namespace(theirs);
            }
            exec_program(plan)
        };
        if let Some((ours, theirs)) = nest {
            drop(theirs);
            map_nested_namespace(plan, program, ours);
        }
        let status = loop {
            match rustix::process::waitpid(None, rustix::process::WaitOptions::empty()) {
                Ok(Some((pid, status))) if pid == program => break status,
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => fail("waiting for the program", e),
            }
        };
        let status = ExitStatus::from_raw(status.as_raw() as i32);
        let report = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exit {code}\n"),
            (None, Some(sig)) => format!("signal {sig}\n"),
            (None, None) => "exit 1\n".to_string(),
        };
        let _ = (&control).write_all(report.as_bytes());
        drop(control);
        std::process::exit(status.code().unwrap_or(128 + status.signal().unwrap_or(0)));
    }

    /// In the program's process: a user namespace of its own, mapped by `init` from outside. It
    /// holds no capability over the sandbox's namespaces, and creates no namespaces itself.
    fn enter_nested_namespace(control: UnixStream) {
        unshare(UnshareFlags::NEWUSER);
        (&control)
            .write_all(b"unshared\n")
            .unwrap_or_else(|e| fail("signalling the nested namespace", e));
        let mut line = String::new();
        BufReader::new(&control)
            .read_line(&mut line)
            .unwrap_or_else(|e| fail("waiting for the nested id maps", e));
        if line != "mapped\n" {
            fail("waiting for the nested id maps", "init went away");
        }
        drop(control);
        fs::write("/proc/sys/user/max_user_namespaces", "0")
            .unwrap_or_else(|e| fail("writing /proc/sys/user/max_user_namespaces", e));
    }

    /// In init: maps every id of the sandbox, unchanged, into the program's namespace.
    fn map_nested_namespace(plan: &Plan, program: rustix::process::Pid, control: UnixStream) {
        let mut lines = BufReader::new(&control);
        let mut line = String::new();
        if lines.read_line(&mut line).is_err() || line != "unshared\n" {
            fail("the nested namespace", "the program's process went away");
        }
        // One extent per extent of the sandbox's own map: the kernel maps each extent through a
        // single extent of the parent's map, and root (the caller) and 1..=count (subordinate ids)
        // are two of them.
        let count = plan.subid.as_ref().map_or(0, |s| s.count);
        let pid = program.as_raw_nonzero();
        for map in ["uid_map", "gid_map"] {
            let file = format!("/proc/{pid}/{map}");
            fs::write(&file, format!("0 0 1\n1 1 {count}\n")).unwrap_or_else(|e| fail(&format!("writing {file}"), e));
        }
        (&control)
            .write_all(b"mapped\n")
            .unwrap_or_else(|e| fail("signalling the nested id maps", e));
    }

    /// Becomes the program: its ids, working directory and no new privileges, then exec.
    fn exec_program(plan: &Plan) -> ! {
        let command = &plan.spec.command;
        let (path, file) = match &command.program {
            Program::Bound { host, target } => (target, host.file_name()),
            Program::Path(p) => (p, p.file_name()),
        };
        if let Some(u) = &command.user {
            let groups: Vec<Gid> = u.groups.iter().map(|&g| Gid::from_raw(g)).collect();
            set_thread_groups(&groups).unwrap_or_else(|e| fail("setgroups", e));
            let gid = Gid::from_raw(u.gid);
            set_thread_res_gid(gid, gid, gid).unwrap_or_else(|e| fail("setresgid", e));
            let uid = Uid::from_raw(u.uid);
            set_thread_res_uid(uid, uid, uid).unwrap_or_else(|e| fail("setresuid", e));
        }
        std::env::set_current_dir(&command.cwd)
            .unwrap_or_else(|e| fail(&format!("chdir {}", command.cwd.display()), e));
        set_no_new_privs(true).unwrap_or_else(|e| fail("no_new_privs", e));
        // No ambient or inheritable capabilities: a non-root program has none after exec.
        clear_ambient_capability_set().unwrap_or_else(|e| fail("clearing ambient capabilities", e));
        let mut caps = capabilities(None).unwrap_or_else(|e| fail("reading capabilities", e));
        caps.inheritable = CapabilitySet::empty();
        set_capabilities(None, caps).unwrap_or_else(|e| fail("clearing inheritable capabilities", e));
        let name = command
            .arg0
            .clone()
            .unwrap_or_else(|| file.map_or_else(|| "program".into(), |n| n.to_string_lossy().into_owned()));
        let mut exec = Command::new(path);
        exec.arg0(name).args(&command.args).stdin(Stdio::inherit());
        if let Some(env) = &command.env {
            exec.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
        }
        fail("exec", exec.exec());
    }
}
