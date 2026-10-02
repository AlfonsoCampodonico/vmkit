//! The sandbox helper on its own (kiln spec §9.2), with a static busybox as the "VMM".
//!
//! Needs Linux, `VMKIT_SANDBOX` naming a built `vmkit-sandbox` that may create user
//! namespaces (see `scripts/install-apparmor.sh`), and a static busybox at
//! `/usr/bin/busybox` (`busybox-static`); the network tests also need `ip`, `nft` and `pasta`.
//! Without `VMKIT_SANDBOX` each test is skipped, unless VMKIT_REQUIRE_KVM_TESTS=1 makes that a failure.
//! `the_vmm_opens_no_connection_through_pasta` also needs the fixture addresses of the network
//! suite (`testguest/net-fixture.sh`) and VMKIT_TEST_NET=1.
#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use vmkit::NetSpec;
use vmkit::sandbox::{Bind, Limits, NetPlan, Plan};

const BUSYBOX: &str = "/usr/bin/busybox";
/// Set in the environment of the probe below when it runs as the VMM.
const PROBE: &str = "VMKIT_SESSION_KEYRING_PROBE";

struct Sandbox {
    helper: PathBuf,
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Option<Self> {
        let Some(helper) = std::env::var_os("VMKIT_SANDBOX").map(PathBuf::from) else {
            assert!(
                std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
                "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_SANDBOX is not"
            );
            return None;
        };
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("data"), "ro").unwrap();
        std::fs::create_dir(dir.path().join("sock")).unwrap();
        Some(Self { helper, dir })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Busybox running `applet args...` with `/dev/null`, a read-only `/vm/data` and a writable `/vm/sock`.
    fn plan(&self, args: &[&str]) -> Plan {
        let bind = |source: PathBuf, target: &str, writable| Bind {
            source,
            target: target.into(),
            writable,
        };
        Plan {
            vmm: BUSYBOX.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            binds: vec![
                bind("/dev/null".into(), "/dev/null", true),
                bind(self.path("data"), "/vm/data", false),
                bind(self.path("sock"), "/vm/sock", true),
            ],
            limits: Limits {
                open_files: 64,
                processes: 32,
            },
            root: self.path("root"),
            pid_file: self.path("vmm.pid"),
            net: None,
        }
    }

    fn command(&self, plan: &Plan) -> Command {
        let file = self.path("plan.json");
        std::fs::write(&file, serde_json::to_vec(plan).unwrap()).unwrap();
        let mut cmd = Command::new(&self.helper);
        cmd.arg("run").arg(file).stdin(Stdio::null());
        cmd
    }

    fn output(&self, plan: &Plan) -> Output {
        self.command(plan).output().unwrap()
    }

    fn spawn(&self, plan: &Plan) -> Child {
        self.command(plan).stdout(Stdio::null()).spawn().unwrap()
    }

    /// The VMM's `/proc` directory, once the helper has written its PID.
    fn vmm_proc(&self) -> PathBuf {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(pid) = std::fs::read_to_string(self.path("vmm.pid")) {
                let dir = PathBuf::from(format!("/proc/{}", pid.trim()));
                // Wait for the exec: `init` becomes `/vmm`.
                if std::fs::read_to_string(dir.join("comm")).is_ok_and(|c| c.trim() == "vmm") {
                    return dir;
                }
            }
            assert!(Instant::now() < deadline, "the sandboxed process never started");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn field(status: &str, name: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}:")))
        .unwrap_or_else(|| panic!("no {name}"))
        .trim()
        .to_string()
}

/// A system tool from the usual directories.
fn find(name: &str) -> PathBuf {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.exists())
        .unwrap_or_else(|| panic!("{name} not installed"))
}

fn net_plan(ruleset: String, pasta_args: Vec<String>) -> NetPlan {
    NetPlan {
        ip: find("ip"),
        nft: find("nft"),
        ruleset,
        pasta: std::env::var_os("VMKIT_PASTA")
            .map(PathBuf::from)
            .unwrap_or_else(|| find("pasta")),
        pasta_args,
    }
}

/// The namespace (`ipc`, `uts`, ...) of the process whose `/proc` directory is `proc`.
fn namespace(proc: &Path, kind: &str) -> String {
    std::fs::read_link(proc.join("ns").join(kind))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// The serial of the calling thread's session keyring.
fn session_keyring() -> i64 {
    // SAFETY: KEYCTL_GET_KEYRING_ID takes a keyring id and a flag, no pointers.
    let id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_GET_KEYRING_ID as libc::c_long,
            libc::KEY_SPEC_SESSION_KEYRING as libc::c_long,
            0 as libc::c_long,
        )
    };
    assert!(id > 0, "{}", std::io::Error::last_os_error());
    id
}

fn gone(dir: &Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while dir.exists() {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    true
}

#[test]
fn the_root_holds_only_the_binds() {
    let Some(s) = Sandbox::new() else { return };
    let o = s.output(&s.plan(&["find", "/"]));
    assert!(o.status.success(), "{o:?}");
    let mut seen: Vec<String> = stdout(&o).lines().map(String::from).collect();
    seen.sort();
    assert_eq!(seen, ["/", "/dev", "/dev/null", "/vm", "/vm/data", "/vm/sock", "/vmm"]);
}

#[test]
fn read_only_binds_stay_read_only_and_writable_ones_reach_the_host() {
    let Some(s) = Sandbox::new() else { return };
    // The temporary directory is on a nosuid,nodev tmpfs on most hosts: its locked flags must be kept.
    let o = s.output(&s.plan(&["sh", "-c", "echo x > /vm/data"]));
    // Refused by the read-only mount itself, not by a helper failure (exit 125).
    assert!(!o.status.success() && o.status.code() != Some(125), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("Read-only file system"),
        "{o:?}"
    );
    assert_eq!(std::fs::read_to_string(s.path("data")).unwrap(), "ro");
    let o = s.output(&s.plan(&["sh", "-c", "echo out > /vm/sock/out && echo x > /new"]));
    assert!(!o.status.success(), "the root is read-only");
    assert_eq!(std::fs::read_to_string(s.path("sock/out")).unwrap(), "out\n");
}

#[test]
fn exit_codes_and_signals_are_mirrored() {
    let Some(s) = Sandbox::new() else { return };
    assert_eq!(s.output(&s.plan(&["sh", "-c", "exit 7"])).status.code(), Some(7));
    let mut child = s.spawn(&s.plan(&["sleep", "30"]));
    let vmm = s.vmm_proc();
    let pid = vmm.file_name().unwrap().to_str().unwrap().to_string();
    // As PID 1 of its namespace the VMM takes only SIGKILL from outside it.
    assert!(Command::new("kill").args(["-KILL", &pid]).status().unwrap().success());
    assert_eq!(child.wait().unwrap().signal(), Some(9));
}

#[test]
fn the_vmm_has_no_privileges_and_dies_with_the_helper() {
    let Some(s) = Sandbox::new() else { return };
    let mut child = s.spawn(&s.plan(&["sleep", "30"]));
    let vmm = s.vmm_proc();
    let status = std::fs::read_to_string(vmm.join("status")).unwrap();
    for caps in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(field(&status, caps), "0000000000000000", "{caps}");
    }
    assert_eq!(field(&status, "NoNewPrivs"), "1");
    assert!(field(&status, "NSpid").ends_with("\t1"));
    let me = Path::new("/proc/self");
    for kind in ["ipc", "uts", "mnt", "net", "pid", "user"] {
        assert_ne!(
            namespace(&vmm, kind),
            namespace(me, kind),
            "the VMM shares our {kind} namespace"
        );
    }
    let me = std::fs::read_to_string("/proc/self/status").unwrap();
    assert_eq!(
        field(&status, "Uid"),
        field(&me, "Uid").replace(char::is_whitespace, "\t")
    );
    let limits = std::fs::read_to_string(vmm.join("limits")).unwrap();
    let core: Vec<&str> = limits
        .lines()
        .find_map(|l| l.strip_prefix("Max core file size"))
        .unwrap_or_else(|| panic!("{limits}"))
        .split_whitespace()
        .collect();
    assert_eq!(core[..2], ["0", "0"], "no core dumps, soft or hard:\n{limits}");
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max open files") && l.contains(" 64 ")),
        "{limits}"
    );
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max processes") && l.contains(" 32 ")),
        "{limits}"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(gone(&vmm), "the VMM outlived the helper");
}

#[test]
fn inherited_descriptors_do_not_reach_the_vmm() {
    use std::os::fd::AsRawFd;
    let Some(s) = Sandbox::new() else { return };
    let leaked = std::fs::File::open("/dev/null").unwrap();
    rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).unwrap();
    let mut child = s.spawn(&s.plan(&["sleep", "30"]));
    let vmm = s.vmm_proc();
    let mut fds: Vec<String> = std::fs::read_dir(vmm.join("fd"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    fds.sort();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(fds, ["0", "1", "2"], "descriptor {} leaked", leaked.as_raw_fd());
}

#[test]
fn a_symlink_is_never_followed() {
    let Some(s) = Sandbox::new() else { return };
    std::os::unix::fs::symlink(s.path("data"), s.path("link")).unwrap();
    let mut plan = s.plan(&["true"]);
    plan.binds[1].source = s.path("link");
    let o = s.output(&plan);
    assert_eq!(o.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&o.stderr).contains("is a symlink"), "{o:?}");
}

#[test]
fn the_network_namespace_gets_the_tap_and_pasta() {
    let Some(s) = Sandbox::new() else { return };
    let mut plan = s.plan(&["ip", "-4", "-o", "addr"]);
    plan.net = Some(net_plan(
        "table inet vmkit { }\n".into(),
        [
            "--config-net",
            "--ns-ifname",
            "egress0",
            "--ipv4-only",
            "--quiet",
            "--tcp-ports",
            "none",
            "--udp-ports",
            "none",
            "--tcp-ns",
            "none",
            "--udp-ns",
            "none",
        ]
        .map(String::from)
        .to_vec(),
    ));
    let o = s.output(&plan);
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    assert!(out.contains("tap0") && out.contains("172.30.0.1/30"), "{out}");
    assert!(out.contains("egress0"), "pasta configured its interface:\n{out}");
}

#[test]
fn the_vmm_opens_no_connection_through_pasta() {
    if std::env::var_os("VMKIT_TEST_NET").is_none_or(|v| v != "1") {
        assert!(
            std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none_or(|v| v != "1"),
            "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_TEST_NET is not (run testguest/net-fixture.sh)"
        );
        return;
    }
    let Some(s) = Sandbox::new() else { return };
    // A host listener on every address, as in the network suite.
    let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    std::thread::spawn(move || {
        for c in listener.incoming() {
            drop(c);
        }
    });
    let spec = NetSpec::default();
    // Cloud metadata, a private host address and a public host address: the guest's policy
    // denies them all, and the VMM itself (the namespace's own process) reaches none.
    for addr in ["169.254.169.254", "10.250.0.1", "198.51.100.7"] {
        let mut plan = s.plan(&["nc", "-w", "3", addr, &port]);
        plan.net = Some(net_plan(vmkit::net::ruleset(&spec, &[]), vmkit::net::pasta_args(&spec)));
        let o = s.output(&plan);
        // busybox nc exits 1 when it cannot connect; 0 would be a connection, 125 a helper failure.
        assert_eq!(o.status.code(), Some(1), "the VMM reached {addr}:{port}: {o:?}");
    }
}

#[test]
fn the_vmm_cannot_create_user_namespaces() {
    let Some(s) = Sandbox::new() else { return };
    let o = s.output(&s.plan(&["unshare", "-U", "true"]));
    assert!(!o.status.success() && o.status.code() != Some(125), "{o:?}");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("No space left on device"),
        "max_user_namespaces is 0 in the sandbox: {o:?}"
    );
    // The control: everything else about the command works.
    assert!(s.output(&s.plan(&["true"])).status.success());
}

/// Not a test of its own: the VMM in `the_vmm_gets_a_session_keyring_of_its_own` prints its
/// session keyring when it is this test binary.
#[test]
fn session_keyring_probe() {
    if std::env::var_os(PROBE).is_some() {
        println!("SESSION-KEYRING {}", session_keyring());
    }
}

#[test]
fn the_vmm_gets_a_session_keyring_of_its_own() {
    let Some(s) = Sandbox::new() else { return };
    // This thread joins a fresh session keyring, so the helper (spawned from it) inherits it.
    // SAFETY: KEYCTL_JOIN_SESSION_KEYRING with NULL reads no memory.
    let joined = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_JOIN_SESSION_KEYRING as libc::c_long,
            std::ptr::null::<libc::c_char>(),
        )
    };
    assert!(joined > 0, "{}", std::io::Error::last_os_error());
    let ours = session_keyring();
    assert_eq!(ours, joined);
    // The VMM is this test binary, run by the dynamic loader with the libraries it maps.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut libs: Vec<PathBuf> = maps
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .filter(|p| p.starts_with('/') && p.contains(".so"))
        .map(PathBuf::from)
        .collect();
    libs.sort();
    libs.dedup();
    let loader = libs
        .iter()
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("ld-"))
        .expect("no dynamic loader mapped")
        .clone();
    let dirs: Vec<String> = libs.iter().map(|p| p.parent().unwrap().display().to_string()).collect();
    let mut plan = s.plan(&[
        "--library-path",
        &dirs.join(":"),
        "/probe",
        "session_keyring_probe",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]);
    plan.vmm = loader;
    let bind = |source: PathBuf, target: PathBuf| Bind {
        source,
        target,
        writable: false,
    };
    plan.binds.push(bind(
        std::env::current_exe().unwrap().canonicalize().unwrap(),
        "/probe".into(),
    ));
    plan.binds.extend(libs.iter().map(|l| bind(l.clone(), l.clone())));
    let o = s.command(&plan).env(PROBE, "1").output().unwrap();
    assert!(o.status.success(), "{o:?}");
    // libtest prints the probe's line after its own `test ... ` on the same line.
    let out = stdout(&o);
    let theirs: i64 = out
        .split("SESSION-KEYRING ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("the probe printed no keyring: {o:?}"))
        .parse()
        .unwrap();
    assert_ne!(theirs, ours, "the VMM shares the caller's session keyring");
}
