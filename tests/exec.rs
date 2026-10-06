//! The sandbox running any program (potter spec §9.4): subordinate ids, host and overlay roots,
//! the nested user namespace, egress without a tap, and seccomp.
//!
//! Needs Linux, `VMKIT_SANDBOX` naming a built `vmkit-sandbox` that may create user namespaces
//! (see `scripts/install-apparmor.sh`), `newuidmap`/`newgidmap` (uidmap) with a range of at
//! least 65536 ids for the caller in `/etc/subuid` and `/etc/subgid`, and a static busybox at
//! `/usr/bin/busybox` (`busybox-static`). Without `VMKIT_SANDBOX` each test is skipped, unless
//! VMKIT_REQUIRE_KVM_TESTS=1 makes that a failure.
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitStatus;

use vmkit::sandbox::{self, Command, Ids, Limits, Mount, Network, Program, Root, Spec, User};

const BUSYBOX: &str = "/usr/bin/busybox";
const IDS: Ids = Ids::Subordinate { count: 65536 };

struct Out {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Option<Self> {
        if std::env::var_os("VMKIT_SANDBOX").is_none() {
            assert!(
                std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
                "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_SANDBOX is not"
            );
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("w")).unwrap();
        Some(Self { dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The first subordinate uid of the caller.
    fn subuid_start(&self) -> u32 {
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap();
        let name = passwd
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.get(2)? == &uid.to_string().as_str()).then(|| f[0].to_string())
            })
            .unwrap();
        std::fs::read_to_string("/etc/subuid")
            .unwrap()
            .lines()
            .find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f[0] == name || f[0] == uid.to_string()).then(|| f[1].parse().unwrap())
            })
            .unwrap()
    }

    fn base(&self, command: Command, root: Root) -> Spec {
        Spec {
            command,
            root,
            mounts: Vec::new(),
            ids: IDS,
            network: Network::None,
            nest: false,
            seccomp: false,
            limits: Limits {
                open_files: 1024,
                processes: 1024,
                cgroup: None,
            },
            run_dir: self.path("run"),
        }
    }

    /// `busybox sh -c script` in an empty root, with the fixture's `w` writable at `/w`.
    fn empty_spec(&self, script: &str, ids: Ids) -> Spec {
        let mut s = self.base(
            Command {
                program: Program::Bound {
                    host: BUSYBOX.into(),
                    target: "/bin/busybox".into(),
                },
                arg0: Some("sh".into()),
                args: vec!["-c".into(), script.into()],
                env: Some(vec![("PATH".into(), "/bin".into())]),
                cwd: "/".into(),
                user: None,
            },
            Root::Empty,
        );
        s.ids = ids;
        s.mounts.push(Mount::Bind {
            source: self.path("w"),
            target: "/w".into(),
            writable: true,
        });
        s
    }

    /// `args` (a host program first) in the host root.
    fn host_spec(&self, args: &[&str]) -> Spec {
        self.base(
            Command {
                program: Program::Path(args[0].into()),
                arg0: None,
                args: args[1..].iter().map(|a| a.to_string()).collect(),
                env: Some(vec![("PATH".into(), "/usr/bin:/bin".into())]),
                cwd: "/".into(),
                user: None,
            },
            Root::Host,
        )
    }

    fn run_host(&self, args: &[&str], mounts: Vec<Mount>) -> Out {
        let mut s = self.host_spec(args);
        s.mounts = mounts;
        self.output(&s)
    }

    /// The fixture's `w`, writable at its own path.
    fn w_bind(&self) -> Mount {
        Mount::Bind {
            source: self.path("w"),
            target: self.path("w"),
            writable: true,
        }
    }

    /// A busybox root at `name`: `bin/busybox`, its applets as symlinks, `etc/old` holding
    /// `content`, and the mount points the overlay root uses.
    fn rootfs(&self, name: &str, content: &str) -> PathBuf {
        let root = self.path(name);
        for d in ["bin", "etc", "proc", "sys", "dev", "tmp"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::copy(BUSYBOX, root.join("bin/busybox")).unwrap();
        for applet in [
            "sh", "ls", "cat", "rm", "mkdir", "touch", "chown", "id", "env", "sleep", "mount", "ip", "unshare", "kill",
            "nc",
        ] {
            std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
        }
        std::fs::write(root.join("etc/old"), content).unwrap();
        root
    }

    /// `/bin/sh -c script` in an overlay of the fixture's busybox root.
    fn overlay_spec(&self, script: &str) -> Spec {
        let lower = self.rootfs("lower", "lower\n");
        for d in ["upper", "work"] {
            std::fs::create_dir(self.path(d)).unwrap();
        }
        self.base(
            Command {
                program: Program::Path("/bin/sh".into()),
                arg0: None,
                args: vec!["-c".into(), script.into()],
                env: Some(vec![("PATH".into(), "/bin".into())]),
                cwd: "/".into(),
                user: None,
            },
            Root::Overlay {
                lowers: vec![lower],
                upper: self.path("upper"),
                work: self.path("work"),
            },
        )
    }

    fn run_overlay(&self, script: &str, mounts: Vec<Mount>) -> Out {
        let mut s = self.overlay_spec(script);
        s.mounts = mounts;
        self.output(&s)
    }

    fn output(&self, spec: &Spec) -> Out {
        let o = sandbox::spawn(spec, sandbox::Stdio::piped())
            .unwrap()
            .wait_with_output()
            .unwrap();
        Out {
            status: o.status,
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }
}

fn xattr(path: &std::path::Path, name: &str) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    let n = rustix::fs::lgetxattr(path, name, &mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

#[test]
fn subordinate_ids_make_the_caller_root() {
    let Some(t) = Fixture::new() else { return };
    let out = t.output(&t.empty_spec("busybox id -u; busybox id -g", IDS));
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(out.stdout, "0\n0\n");
}

#[test]
fn a_file_made_by_uid_1000_belongs_to_the_subordinate_range_on_the_host() {
    let Some(t) = Fixture::new() else { return };
    let out = t.output(&t.empty_spec("busybox touch /w/f && busybox chown 1000:1000 /w/f", IDS));
    assert!(out.status.success(), "{}", out.stderr);
    let meta = std::fs::metadata(t.path("w/f")).unwrap();
    assert_eq!(meta.uid(), t.subuid_start() + 999);
}

#[test]
fn a_missing_range_is_named() {
    let Some(t) = Fixture::new() else { return };
    let spec = t.empty_spec("true", Ids::Subordinate { count: u32::MAX - 1 });
    let err = sandbox::spawn(&spec, sandbox::Stdio::piped())
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("/etc/subuid"), "{err}");
}

#[test]
fn the_callers_ids_stay_unprivileged() {
    let Some(t) = Fixture::new() else { return };
    let out = t.output(&t.empty_spec("busybox id -u", Ids::Caller));
    let caller = std::fs::metadata("/proc/self").unwrap().uid().to_string();
    assert_eq!(out.stdout.trim(), caller, "{}", out.stderr);
}

#[test]
fn the_host_root_is_read_only_except_writable_binds() {
    let Some(t) = Fixture::new() else { return };
    let w = t.path("w");
    let script = format!(
        "cat /etc/hostname >/dev/null && ! touch /etc/vmkit-probe 2>/dev/null && ! touch /tmp/vmkit-probe 2>/dev/null && touch {}/ok",
        w.display()
    );
    let out = t.run_host(&["/bin/sh", "-c", &script], vec![t.w_bind()]);
    assert!(out.status.success(), "{}", out.stderr);
    assert!(w.join("ok").exists());
}

#[test]
fn proc_is_the_sandboxs_own_and_the_program_is_not_pid_1() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_host(&["/bin/sh", "-c", "echo $$; ls /proc | grep -c '^[0-9]'"], vec![]);
    assert!(out.status.success(), "{}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    // Setup tools (`ip`) may run in the namespace first; the program is never PID 1.
    assert!(lines[0].parse::<u32>().unwrap() > 1, "{}", out.stdout);
    assert!(lines[1].trim().parse::<u32>().unwrap() <= 4, "{}", out.stdout);
}

#[test]
fn the_uid_map_holds_the_caller_and_the_range() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_host(&["/bin/cat", "/proc/self/uid_map"], vec![]);
    assert!(out.status.success(), "{}", out.stderr);
    let lines: Vec<Vec<&str>> = out.stdout.lines().map(|l| l.split_whitespace().collect()).collect();
    let caller = std::fs::metadata("/proc/self").unwrap().uid().to_string();
    let start = t.subuid_start().to_string();
    assert_eq!(
        lines,
        [vec!["0", caller.as_str(), "1"], vec!["1", start.as_str(), "65536"]]
    );
}

#[test]
fn env_cwd_and_user_are_exactly_the_commands() {
    let Some(t) = Fixture::new() else { return };
    let mut s = t.host_spec(&["/bin/sh", "-c", "pwd; id -u; id -g; id -G; env"]);
    s.command.env = Some(vec![("A".into(), "1".into()), ("PATH".into(), "/usr/bin:/bin".into())]);
    s.command.cwd = "/usr".into();
    s.command.user = Some(User {
        uid: 1000,
        gid: 1001,
        groups: vec![1001, 1002],
    });
    let out = t.output(&s);
    assert!(out.status.success(), "{}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines[..4], ["/usr", "1000", "1001", "1001 1002"]);
    let env = &lines[4..];
    assert!(env.contains(&"A=1") && env.contains(&"PATH=/usr/bin:/bin"), "{env:?}");
    for leaked in ["HOME=", "USER=", "VMKIT_SANDBOX="] {
        assert!(!env.iter().any(|l| l.starts_with(leaked)), "{leaked} leaked: {env:?}");
    }
}

#[test]
fn exit_codes_and_signals_of_the_program_are_mirrored() {
    let Some(t) = Fixture::new() else { return };
    assert_eq!(t.run_host(&["/bin/sh", "-c", "exit 7"], vec![]).status.code(), Some(7));
    let killed = t.run_host(&["/bin/sh", "-c", "kill -TERM $$"], vec![]);
    assert_eq!(std::os::unix::process::ExitStatusExt::signal(&killed.status), Some(15));
}

#[test]
fn background_processes_die_with_the_program() {
    let Some(t) = Fixture::new() else { return };
    let w = t.path("w");
    let script = format!("(sleep 2; touch {}/late) & exit 0", w.display());
    let out = t.run_host(&["/bin/sh", "-c", &script], vec![t.w_bind()]);
    assert!(out.status.success(), "{}", out.stderr);
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert!(!w.join("late").exists(), "a background process outlived the sandbox");
}

#[test]
fn a_bind_target_must_exist_in_the_host_root() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_host(
        &["/bin/true"],
        vec![Mount::Bind {
            source: t.path("w"),
            target: "/nonexistent-vmkit-target".into(),
            writable: true,
        }],
    );
    assert_eq!(out.status.code(), Some(125));
    assert!(out.stderr.contains("must exist"), "{}", out.stderr);
}

#[test]
fn an_overlay_root_records_changes_in_the_upper_with_user_xattrs() {
    let Some(t) = Fixture::new() else { return };
    let script = "rm /etc/old && mkdir -p /opt/new && echo hi >/opt/new/f && chown 1000:1000 /opt/new/f \
                  && rm -r /etc && mkdir /etc && echo x >/etc/fresh";
    let out = t.run_overlay(script, Vec::new());
    assert!(out.status.success(), "{}", out.stderr);
    let upper = t.path("upper");
    assert_eq!(std::fs::read_to_string(upper.join("opt/new/f")).unwrap(), "hi\n");
    // `etc` was replaced: an opaque directory, marked with a user xattr, never a trusted one.
    assert_eq!(
        xattr(&upper.join("etc"), "user.overlay.opaque").as_deref(),
        Some(&b"y"[..])
    );
    assert!(xattr(&upper.join("etc"), "trusted.overlay.opaque").is_none());
    let meta = std::fs::symlink_metadata(upper.join("opt/new/f")).unwrap();
    assert_eq!(meta.uid(), t.subuid_start() + 999);
    assert_eq!(
        std::fs::read_to_string(t.path("lower/etc/old")).unwrap(),
        "lower\n",
        "a lower changed"
    );
}

#[test]
fn deleting_a_lower_file_leaves_a_whiteout() {
    use std::os::unix::fs::FileTypeExt;
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay("rm /bin/ls", Vec::new());
    assert!(out.status.success(), "{}", out.stderr);
    let meta = std::fs::symlink_metadata(t.path("upper/bin/ls")).unwrap();
    assert!(meta.file_type().is_char_device() && meta.rdev() == 0, "{meta:?}");
}

#[test]
fn the_first_lower_is_the_top_one() {
    let Some(t) = Fixture::new() else { return };
    let mut s = t.overlay_spec("cat /etc/old");
    let top = t.rootfs("top", "top\n");
    let Root::Overlay { lowers, .. } = &mut s.root else {
        unreachable!()
    };
    lowers.insert(0, top);
    let out = t.output(&s);
    assert_eq!(out.stdout, "top\n", "{}", out.stderr);
}

#[test]
fn the_overlay_root_has_proc_dev_and_shm_and_mounts() {
    let Some(t) = Fixture::new() else { return };
    let cache = t.path("cache");
    std::fs::create_dir(&cache).unwrap();
    let script = "test -c /dev/null && echo x >/dev/null && test -d /proc/self && test -d /dev/shm \
                  && touch /dev/shm/a && test -e /dev/pts/ptmx && touch /cache/hit && touch /run/secrets/s \
                  && ! touch /sys/x 2>/dev/null";
    let mounts = vec![
        Mount::Bind {
            source: cache.clone(),
            target: "/cache".into(),
            writable: true,
        },
        Mount::Tmpfs {
            target: "/run/secrets".into(),
            size_mib: 1,
        },
    ];
    let out = t.run_overlay(script, mounts);
    assert!(out.status.success(), "{}", out.stderr);
    assert!(cache.join("hit").exists());
    assert!(
        !t.path("upper/cache/hit").exists(),
        "a bind mount's writes reached the upper"
    );
    assert!(
        !t.path("upper/run/secrets/s").exists(),
        "a tmpfs's writes reached the upper"
    );
    assert!(!t.path("upper/dev").exists(), "/dev's contents reached the upper");
}

impl Fixture {
    fn run_overlay_nested(&self, script: &str) -> Out {
        let mut s = self.overlay_spec(script);
        s.nest = true;
        self.output(&s)
    }
}

#[test]
fn without_nesting_root_in_the_sandbox_holds_its_namespaces() {
    // The control for the next test: the same probes succeed for an un-nested root.
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay(
        "ip link add d0 type dummy && mount -t tmpfs t /tmp && echo holds",
        Vec::new(),
    );
    assert_eq!(out.stdout, "holds\n", "{}", out.stderr);
}

#[test]
fn a_nested_program_cannot_touch_the_sandboxs_namespaces() {
    let Some(t) = Fixture::new() else { return };
    let script = "id -u; ! ip link add d0 type dummy 2>/dev/null && ! mount -t tmpfs t /tmp 2>/dev/null \
                  && ! unshare -U true 2>/dev/null && echo contained";
    let out = t.run_overlay_nested(script);
    assert_eq!(out.stdout, "0\ncontained\n", "{}", out.stderr);
}

#[test]
fn a_nested_program_still_owns_files_as_root_and_subordinate_users() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay_nested("touch /a && chown 1000:1000 /a && cat /proc/self/uid_map");
    assert!(out.status.success(), "{}", out.stderr);
    assert_eq!(
        out.stdout.split_whitespace().collect::<Vec<_>>(),
        ["0", "0", "1", "1", "1", "65536"]
    );
    let meta = std::fs::symlink_metadata(t.path("upper/a")).unwrap();
    assert_eq!(meta.uid(), t.subuid_start() + 999);
}

#[test]
fn a_nested_program_cannot_signal_or_inspect_init() {
    let Some(t) = Fixture::new() else { return };
    let script = "kill -KILL 1; sleep 0.2; echo alive; cat /proc/1/environ >/dev/null 2>&1 || echo protected";
    let out = t.run_overlay_nested(script);
    assert_eq!(out.stdout, "alive\nprotected\n", "{}", out.stderr);
}

/// The network suite's fixture addresses on the host's loopback (`testguest/net-fixture.sh`).
const METADATA: &str = "169.254.169.254";
const PRIVATE: &str = "10.250.0.1";
const HOST: &str = "198.51.100.7";

impl Fixture {
    /// Like `new`, but only with the network fixture (VMKIT_TEST_NET=1).
    fn net() -> Option<Self> {
        if std::env::var_os("VMKIT_TEST_NET").is_none_or(|v| v != "1") {
            assert!(
                std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
                "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_TEST_NET is not (run testguest/net-fixture.sh)"
            );
            return None;
        }
        Self::new()
    }

    /// `script` nested in the overlay root, with egress allowed to the fixture's host address only.
    fn run_overlay_egress(&self, script: &str) -> Out {
        let mut s = self.overlay_spec(script);
        s.nest = true;
        s.network = Network::Egress(vmkit::NetSpec {
            allow: vec![HOST.parse().unwrap()],
            ..Default::default()
        });
        self.output(&s)
    }
}

/// A host listener on every address, accepting and dropping connections.
fn listen() -> u16 {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in listener.incoming() {
            drop(c);
        }
    });
    port
}

#[test]
fn egress_reaches_allowed_addresses_but_not_private_or_metadata_ones() {
    let Some(t) = Fixture::net() else { return };
    let port = listen();
    let script = format!(
        "nc -w 2 {HOST} {port} </dev/null && echo allowed; \
         nc -w 2 {METADATA} {port} </dev/null || echo metadata-blocked; \
         nc -w 2 {PRIVATE} {port} </dev/null || echo private-blocked"
    );
    let out = t.run_overlay_egress(&script);
    assert_eq!(
        out.stdout, "allowed\nmetadata-blocked\nprivate-blocked\n",
        "{}",
        out.stderr
    );
}

#[test]
fn without_an_allowance_host_addresses_are_denied() {
    let Some(t) = Fixture::net() else { return };
    let port = listen();
    let mut s = t.overlay_spec(&format!("nc -w 2 {HOST} {port} </dev/null || echo denied"));
    s.nest = true;
    s.network = Network::Egress(vmkit::NetSpec::default());
    let out = t.output(&s);
    assert_eq!(out.stdout, "denied\n", "{}", out.stderr);
}

#[test]
fn a_nested_program_cannot_change_the_network() {
    let Some(t) = Fixture::net() else { return };
    let out = t.run_overlay_egress(
        "ip route del default 2>/dev/null || echo kept; ip link set lo down 2>/dev/null || echo up",
    );
    assert_eq!(out.stdout, "kept\nup\n", "{}", out.stderr);
}

#[test]
fn loopback_is_up_without_a_network() {
    let Some(t) = Fixture::new() else { return };
    let out = t.run_overlay("cat /sys/class/net/lo/operstate", Vec::new());
    assert_eq!(out.stdout.trim(), "unknown", "{}", out.stderr);
}
