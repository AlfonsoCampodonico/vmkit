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

use vmkit::sandbox::{self, Command, Ids, Limits, Mount, Network, Program, Root, Spec};

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
