//! The sandbox helper on its own (kiln spec §9.2), with a static busybox as the "VMM".
//!
//! Needs Linux, `VMKIT_SANDBOX` naming a built `vmkit-sandbox` that may create user
//! namespaces (see `scripts/install-apparmor.sh`), and a static busybox at
//! `/usr/bin/busybox` (`busybox-static`); the network test also needs `ip`, `nft` and `pasta`.
//! Without `VMKIT_SANDBOX` each test is skipped, unless VMKIT_REQUIRE_KVM_TESTS=1 makes that a failure.
#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use vmkit::sandbox::{Bind, Limits, NetPlan, Plan};

const BUSYBOX: &str = "/usr/bin/busybox";

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
    assert!(!o.status.success(), "wrote to a read-only bind");
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
    let me = std::fs::read_to_string("/proc/self/status").unwrap();
    assert_eq!(
        field(&status, "Uid"),
        field(&me, "Uid").replace(char::is_whitespace, "\t")
    );
    let limits = std::fs::read_to_string(vmm.join("limits")).unwrap();
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max open files") && l.contains(" 64 ")),
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
    let find = |name: &str| {
        ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(name))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("{name} not installed"))
    };
    let mut plan = s.plan(&["ip", "-4", "-o", "addr"]);
    plan.net = Some(NetPlan {
        ip: find("ip"),
        nft: find("nft"),
        ruleset: "table inet vmkit { }\n".into(),
        pasta: std::env::var_os("VMKIT_PASTA")
            .map(PathBuf::from)
            .unwrap_or_else(|| find("pasta")),
        pasta_args: [
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
    });
    let o = s.output(&plan);
    assert!(o.status.success(), "{o:?}");
    let out = stdout(&o);
    assert!(out.contains("tap0") && out.contains("172.30.0.1/30"), "{out}");
    assert!(out.contains("egress0"), "pasta configured its interface:\n{out}");
}
