//! `vmkit-sandbox`: runs one VMM inside unprivileged user, PID, mount and net
//! namespaces with a minimal root (kiln spec §9.2). Started by the vmkit library.
//!
//!   vmkit-sandbox run <plan.json>    outer: user + PID namespaces, attaches pasta, waits for the VMM
//!   vmkit-sandbox init <plan.json>   inner (PID 1): mount + net namespaces, then execs the VMM
//!
//! The outer helper and `init` talk over a socket on `init`'s stdin: `init` sends
//! `ready` once its namespaces exist, and waits for `go`, which the outer helper sends
//! after attaching `pasta`. If the outer helper dies first, `init` sees end-of-file.
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
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::Path;
    use std::process::{Command, ExitStatus, Stdio};

    use rustix::fs::{CWD, FileType, StatVfsMountFlags, fstat, statvfs};
    use rustix::io::{FdFlags, fcntl_setfd};
    use rustix::mount::{
        MountFlags, MountPropagationFlags, MoveMountFlags, OpenTreeFlags, UnmountFlags, mount, mount_change,
        mount_remount, move_mount, open_tree, unmount,
    };
    use rustix::process::{
        Resource, Rlimit, Signal, getpid, kill_process, pivot_root, set_parent_process_death_signal, setrlimit,
    };
    use rustix::thread::{
        CapabilitySet, UnshareFlags, capabilities, clear_ambient_capability_set, configure_capability_in_ambient_set,
        set_capabilities, set_no_new_privs,
    };
    use vmkit::net::{GATEWAY, PREFIX, TAP};
    use vmkit::sandbox::{NetPlan, Plan};

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
            (Some("init"), Some(plan)) => init(plan),
            _ => fail("usage", "vmkit-sandbox run|init <plan.json>"),
        }
    }

    /// Unshares namespaces. This process is single-threaded and does not share its
    /// file-descriptor table, so the `unshare` safety requirement (no `FILES`) holds.
    fn unshare(flags: UnshareFlags) {
        #[allow(unsafe_code)]
        // SAFETY: `flags` never includes `UnshareFlags::FILES` (see the doc comment).
        let r = unsafe { rustix::thread::unshare_unsafe(flags) };
        r.unwrap_or_else(|e| fail("unshare", e));
    }

    /// Marks every inherited descriptor above stderr close-on-exec, so nothing the
    /// caller leaked reaches the VMM.
    fn close_inherited_fds() {
        let fds: Vec<i32> = fs::read_dir("/proc/self/fd")
            .unwrap_or_else(|e| fail("listing descriptors", e))
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
            .filter(|&fd| fd > 2)
            .collect();
        for fd in fds {
            #[allow(unsafe_code)]
            // SAFETY: `fd` was open when listed and nothing in this single-threaded process
            // closes descriptors meanwhile; the one `read_dir` used for the listing is
            // already closed, so setting a flag on that number fails harmlessly.
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
            if let Some(net) = &plan.net {
                attach_pasta(net, pid);
            }
            let _ = (&ours).write_all(b"go\n");
        }
        drop(lines);
        drop(ours);
        mirror(child.wait().unwrap_or_else(|e| fail("waiting for the VMM", e)));
    }

    /// Starts `pasta` on the VM's namespace. It returns once its interface is configured
    /// and keeps running in the PID namespace, so it ends with the VMM.
    fn attach_pasta(net: &NetPlan, pid: u32) {
        let status = Command::new(&net.pasta)
            .args(&net.pasta_args)
            .args(["--netns", &format!("/proc/{pid}/ns/net"), "--netns-only"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .unwrap_or_else(|e| fail(&format!("starting {}", net.pasta.display()), e));
        if !status.success() {
            let _ = kill_process(
                rustix::process::Pid::from_raw(pid as i32).expect("child pid"),
                Signal::KILL,
            );
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
    fn setup_net(net: &NetPlan) {
        let uid = rustix::process::getuid().as_raw().to_string();
        let gid = rustix::process::getgid().as_raw().to_string();
        let gateway = format!("{GATEWAY}/{PREFIX}");
        tool(&net.ip, &["link", "set", "lo", "up"], None);
        tool(
            &net.ip,
            &["tuntap", "add", TAP, "mode", "tap", "user", &uid, "group", &gid],
            None,
        );
        tool(&net.ip, &["addr", "add", &gateway, "dev", TAP], None);
        tool(&net.ip, &["link", "set", TAP, "up"], None);
        // Both apply to this namespace only. `route_localnet` lets a forwarded connection that
        // pasta spliced from host loopback leave through the tap after DNAT.
        let sysctl = |path: &str| fs::write(path, "1").unwrap_or_else(|e| fail(&format!("writing {path}"), e));
        sysctl("/proc/sys/net/ipv4/ip_forward");
        sysctl(&format!("/proc/sys/net/ipv4/conf/{TAP}/route_localnet"));
        tool(&net.nft, &["-f", "-"], Some(&net.ruleset));
    }

    /// A mount of `source` (opened without following a final symlink) onto `target`.
    fn attach(source: &Path, target: &Path, writable: bool) {
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
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|e| fail("mkdir", e));
        }
        if kind == FileType::Directory {
            fs::create_dir_all(target).unwrap_or_else(|e| fail("mkdir", e));
        } else {
            fs::File::create(target).unwrap_or_else(|e| fail(&format!("creating {}", target.display()), e));
        }
        move_mount(&fd, "", CWD, target, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)
            .unwrap_or_else(|e| fail(&format!("attaching {}", target.display()), e));
        if !writable {
            // A user namespace cannot clear the source mount's locked flags, so keep them.
            let st = statvfs(target).unwrap_or_else(|e| fail(&format!("statvfs {}", target.display()), e));
            let keep = StatVfsMountFlags::NOSUID
                | StatVfsMountFlags::NODEV
                | StatVfsMountFlags::NOEXEC
                | StatVfsMountFlags::NOATIME
                | StatVfsMountFlags::NODIRATIME
                | StatVfsMountFlags::RELATIME;
            let locked = MountFlags::from_bits_retain((st.f_flag & keep).bits() as u32);
            mount_remount(
                target,
                MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | locked,
                "",
            )
            .unwrap_or_else(|e| fail(&format!("making {} read-only", target.display()), e));
        }
    }

    fn init(plan_path: &str) {
        // If the outer helper dies, so does everything in this PID namespace.
        set_parent_process_death_signal(Some(Signal::KILL)).unwrap_or_else(|e| fail("pdeathsig", e));
        let plan = read_plan(plan_path);
        unshare(UnshareFlags::NEWNS | UnshareFlags::NEWNET);
        if let Some(net) = &plan.net {
            setup_net(net);
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
        drop(control);
        mount_change("/", MountPropagationFlags::PRIVATE | MountPropagationFlags::REC)
            .unwrap_or_else(|e| fail("making mounts private", e));
        let root = &plan.root;
        fs::create_dir_all(root).unwrap_or_else(|e| fail("creating the root", e));
        mount(
            "tmpfs",
            root,
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            Some(c"mode=0755,size=1m"),
        )
        .unwrap_or_else(|e| fail("mounting the root tmpfs", e));
        let inside = |p: &Path| root.join(p.strip_prefix("/").unwrap_or(p));
        attach(&plan.vmm, &inside(Path::new("/vmm")), false);
        for b in &plan.binds {
            attach(&b.source, &inside(&b.target), b.writable);
        }
        let old = root.join("old-root");
        fs::create_dir_all(&old).unwrap_or_else(|e| fail("mkdir old-root", e));
        pivot_root(root, &old).unwrap_or_else(|e| fail("pivot_root", e));
        std::env::set_current_dir("/").unwrap_or_else(|e| fail("chdir /", e));
        unmount("/old-root", UnmountFlags::DETACH).unwrap_or_else(|e| fail("detaching the old root", e));
        fs::remove_dir("/old-root").unwrap_or_else(|e| fail("removing old-root", e));
        mount_remount("/", MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV, "")
            .unwrap_or_else(|e| fail("making the root read-only", e));
        let lim = |r: Resource, n: u64| {
            setrlimit(
                r,
                Rlimit {
                    current: Some(n),
                    maximum: Some(n),
                },
            )
            .unwrap_or_else(|e| fail("setrlimit", e))
        };
        lim(Resource::Nofile, plan.limits.open_files);
        lim(Resource::Nproc, plan.limits.processes);
        set_no_new_privs(true).unwrap_or_else(|e| fail("no_new_privs", e));
        // The VMM gets no capabilities: no ambient set, and exec as a non-root user.
        clear_ambient_capability_set().unwrap_or_else(|e| fail("clearing ambient capabilities", e));
        let mut caps = capabilities(None).unwrap_or_else(|e| fail("reading capabilities", e));
        caps.inheritable = CapabilitySet::empty();
        set_capabilities(None, caps).unwrap_or_else(|e| fail("clearing inheritable capabilities", e));
        let name = plan
            .vmm
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vmm".into());
        let err = Command::new("/vmm")
            .arg0(name)
            .args(&plan.args)
            .stdin(Stdio::null())
            .exec();
        fail("exec", err);
    }
}
