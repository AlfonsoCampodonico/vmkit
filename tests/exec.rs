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
    assert_eq!(lines[0], "2");
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
