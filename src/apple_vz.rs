//! The Apple Virtualization.framework driver (macOS on Apple Silicon).
//!
//! VZ is an Objective-C framework, so vmkit does not call it: each VM runs in `vmkit-vz`, a
//! small Swift helper (`vz/main.swift`) signed with the `com.apple.security.virtualization`
//! entitlement (`scripts/build-vmkit-vz.sh`). vmkit writes the VM's configuration to
//! `<run_dir>/vz.json`, spawns the helper, and drives it over a JSON-lines socket. The guest
//! runs in Apple's per-VM XPC process, which is Apple's sandbox and dies with the helper;
//! vmkit's Linux sandbox does not apply.
//!
//! What differs from the Linux backends:
//! - No network device: the guest has no NIC, so its egress is always denied. A spec with a
//!   network or a tap is refused, and `set_egress` is unavailable.
//! - No snapshots: VZ's save needs a key in the data-protection keychain, which an ad-hoc
//!   signed helper cannot create (`Capabilities::supports_snapshot` is false).
//! - A guest reset reboots a VZ guest in place, which the host cannot see. The driver appends
//!   `vmkit.reset=poweroff`, which vmkit's kernel (from the patched builds on) turns into a
//!   power-off, so every reset ends the VM. An unpatched kernel loops on reset instead.
//! - vsock: the guest CID is VZ's choice (`VsockSpec::guest_cid` is ignored), and
//!   guest-initiated connections reach the host only on ports in [`VSOCK_PORTS`].

use std::io::{BufRead, BufReader, Read, Write};
use std::ops::RangeInclusive;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::binary::{self, Version};
use crate::error::{Error, Result};
use crate::net::EgressGate;
use crate::process::{self, Proc};
use crate::spec::{Capabilities, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};
use crate::vmm::{Vm, Vmm};

pub const MIN_VERSION: Version = (0, 1, 0);
const NAME: &str = "apple-vz";
const HELPER: &str = "vmkit-vz";
const ENTITLEMENT: &str = "com.apple.security.virtualization";
/// Host ports a guest-initiated vsock connection may target. VZ has no wildcard listener, so
/// the helper registers each of them up front (about 3 ms for the whole range).
pub const VSOCK_PORTS: RangeInclusive<u32> = 1024..=65535;
/// The longest Unix socket path macOS accepts (`sun_path` is 104 bytes with its NUL).
const MAX_SOCKET_PATH: usize = 103;
/// How long `start`, `pause` and `resume` may take.
const API_TIMEOUT: Duration = Duration::from_secs(30);
/// How long after a failed API call to look for the helper's exit before blaming the socket.
const DEATH_GRACE: Duration = Duration::from_millis(500);
const NO_SNAPSHOTS: &str = "snapshots on apple-vz (VZ's save needs a helper signed with a Team ID)";

pub struct AppleVz {
    binary: PathBuf,
}

impl AppleVz {
    /// Finds the helper (`$VMKIT_VZ`, else `vmkit-vz` on `PATH`), checks its version and that
    /// it carries the virtualization entitlement.
    pub fn discover() -> Result<Self> {
        let binary = binary::find(HELPER, "VMKIT_VZ")?;
        binary::check_version(&binary, HELPER, MIN_VERSION)?;
        check_entitlement(&binary)?;
        Ok(Self { binary })
    }
}

/// Without the entitlement VZ refuses to create a VM; say so before any VM is attempted.
fn check_entitlement(binary: &Path) -> Result<()> {
    let out = Command::new("/usr/bin/codesign")
        .args(["--display", "--entitlements", "-"])
        .arg(binary)
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && text.contains(ENTITLEMENT) {
        return Ok(());
    }
    Err(Error::Prerequisite(format!(
        "{} is not signed with the {ENTITLEMENT} entitlement; build it with scripts/build-vmkit-vz.sh",
        binary.display()
    )))
}

const CAPABILITIES: Capabilities = Capabilities {
    // Measured: a 28th virtio device makes VZ refuse the configuration.
    max_virtio_devices: 27,
    // The console and the entropy device.
    implicit_devices: 2,
    supports_snapshot: false,
    supports_diff_snapshot: false,
    supports_balloon: false,
    supports_drive_remap: false,
    lazy_memory: false,
    // Power-off is what VZ honours; with `vmkit.reset=poweroff` a reset ends the VM too.
    guest_exit: GuestExit::Poweroff,
    console: "hvc0",
};

/// Kernel arguments the driver appends: the console, and a reset that powers off.
const BACKEND_ARGS: [&str; 2] = ["console=hvc0", "vmkit.reset=poweroff"];

/// The helper's configuration file.
fn config(spec: &VmSpec, vsock: Option<&Path>) -> Value {
    let cmdline: Vec<&str> = spec.cmdline.iter().map(String::as_str).chain(BACKEND_ARGS).collect();
    let disks: Vec<Value> = spec
        .disks
        .iter()
        .map(|d| json!({"path": d.path, "read_only": d.read_only}))
        .collect();
    json!({
        "kernel": spec.kernel,
        "initramfs": spec.initramfs,
        "cmdline": cmdline.join(" "),
        "disks": disks,
        "vcpus": spec.vcpus,
        "memory_mib": spec.memory_mib,
        "vsock": vsock.map(|socket| json!({
            "socket": socket,
            "first_port": VSOCK_PORTS.start(),
            "last_port": VSOCK_PORTS.end(),
        })),
    })
}

/// Refuses socket paths macOS cannot bind: the API socket, and the vsock socket with the
/// longest `_<port>` suffix.
fn check_socket_paths(api: &Path, vsock: Option<&Path>) -> Result<()> {
    let longest_vsock = vsock.map(|v| PathBuf::from(format!("{}_{}", v.display(), VSOCK_PORTS.end())));
    for path in std::iter::once(api.to_path_buf()).chain(longest_vsock) {
        if path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(Error::InvalidSpec(format!(
                "socket path {} is longer than the {MAX_SOCKET_PATH} bytes macOS allows; use a shorter run_dir",
                path.display()
            )));
        }
    }
    Ok(())
}

impl Vmm for AppleVz {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>> {
        spec.check(&CAPABILITIES)?;
        if spec.has_nic() {
            return Err(Error::Unsupported(
                "a NIC on apple-vz (its VMs have no network device, so egress is always denied)",
            ));
        }
        let sock = spec.run_dir.join("sock");
        let api = sock.join("vz.sock");
        let vsock = spec.vsock.map(|_| sock.join("vsock.sock"));
        check_socket_paths(&api, vsock.as_deref())?;
        std::fs::create_dir_all(&sock)?;
        process::clear_socket(&api)?;
        if let Some(v) = &vsock {
            process::clear_socket(v)?;
        }
        let config_path = spec.run_dir.join("vz.json");
        std::fs::write(&config_path, config(spec, vsock.as_deref()).to_string())?;
        let args = [
            "--config".to_string(),
            config_path.display().to_string(),
            "--api".into(),
            api.display().to_string(),
        ];
        let proc = process::spawn(&self.binary, &args, &spec.console_log, &spec.run_dir.join("vz.stderr"))?;
        let vm = AppleVzVm { proc, api, vsock };
        // Where the Linux backends record the sandboxed VMM: here the helper, whose death
        // ends the VM (callers use it to clean up after a crash).
        std::fs::write(crate::sandbox::pid_file(&spec.run_dir), format!("{}\n", vm.proc.pid()))?;
        vm.proc.wait_for_socket(&vm.api)?;
        Ok(Box::new(vm))
    }

    fn restore(&self, _bundle: &SnapshotBundle, _spec: &RestoreSpec) -> Result<Box<dyn Vm>> {
        Err(Error::Unsupported(NO_SNAPSHOTS))
    }
}

struct AppleVzVm {
    proc: Proc,
    api: PathBuf,
    vsock: Option<PathBuf>,
}

/// One API request: `{"op": op}` in, `{"ok": bool, "error"?: string}` out.
fn exchange(api: &Path, op: &str) -> std::io::Result<Value> {
    let mut stream = UnixStream::connect(api)?;
    stream.set_read_timeout(Some(API_TIMEOUT))?;
    stream.set_write_timeout(Some(API_TIMEOUT))?;
    stream.write_all(format!("{}\n", json!({"op": op})).as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).take(64 * 1024).read_line(&mut line)?;
    if line.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the helper closed the API connection",
        ));
    }
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

impl AppleVzVm {
    fn call(&self, op: &'static str) -> Result<()> {
        let reply = match exchange(&self.api, op) {
            Ok(reply) => reply,
            Err(io) if io.kind() == std::io::ErrorKind::InvalidData => {
                return Err(Error::Http(format!("{NAME} {op}: {io}")));
            }
            Err(io) => {
                // The exit may be a moment behind the closed connection.
                return match self.proc.wait(Some(DEATH_GRACE))? {
                    Some(end) => Err(self.proc.early_exit(end)),
                    None => Err(Error::Io(io)),
                };
            }
        };
        if reply["ok"] == json!(true) {
            return Ok(());
        }
        Err(Error::VmmOp {
            backend: NAME,
            op,
            message: reply["error"].as_str().unwrap_or("no error message").to_string(),
        })
    }
}

impl Vm for AppleVzVm {
    fn start(&mut self) -> Result<()> {
        self.call("start")
    }

    fn pause(&mut self) -> Result<()> {
        self.call("pause")
    }

    fn resume(&mut self) -> Result<()> {
        self.call("resume")
    }

    /// SIGKILL to the helper; VZ tears the VM's XPC process down with it.
    fn kill(&mut self) -> Result<()> {
        self.proc.kill()
    }

    fn wait(&mut self) -> Result<VmEnd> {
        Ok(self.proc.wait(None)?.expect("an unbounded wait returns an end"))
    }

    fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<VmEnd>> {
        self.proc.wait(Some(timeout))
    }

    fn snapshot(&mut self, _dest: &Path) -> Result<SnapshotBundle> {
        Err(Error::Unsupported(NO_SNAPSHOTS))
    }

    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    fn vsock_socket(&self) -> Option<&Path> {
        self.vsock.as_deref()
    }

    fn set_egress(&mut self, _gate: EgressGate) -> Result<()> {
        Err(Error::EgressUnavailable("an apple-vz VM has no NIC"))
    }
}

impl Drop for AppleVzVm {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait(Some(Duration::from_secs(5)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Disk, VsockSpec};

    fn spec(run_dir: &Path) -> VmSpec {
        VmSpec {
            kernel: "/k/Image".into(),
            initramfs: None,
            cmdline: vec!["quiet".into()],
            disks: vec![
                Disk {
                    path: "/d/a.img".into(),
                    read_only: true,
                },
                Disk {
                    path: "/d/b.img".into(),
                    read_only: false,
                },
            ],
            vcpus: 2,
            memory_mib: 512,
            vsock: None,
            net: None,
            tap: None,
            console_log: run_dir.join("console.log"),
            run_dir: run_dir.to_path_buf(),
        }
    }

    #[test]
    fn the_config_appends_the_console_and_the_reset_argument() {
        let s = spec(Path::new("/r"));
        assert_eq!(
            config(&s, Some(Path::new("/r/sock/vsock.sock"))),
            json!({
                "kernel": "/k/Image",
                "initramfs": null,
                "cmdline": "quiet console=hvc0 vmkit.reset=poweroff",
                "disks": [
                    {"path": "/d/a.img", "read_only": true},
                    {"path": "/d/b.img", "read_only": false},
                ],
                "vcpus": 2,
                "memory_mib": 512,
                "vsock": {"socket": "/r/sock/vsock.sock", "first_port": 1024, "last_port": 65535},
            })
        );
        assert_eq!(config(&s, None)["vsock"], Value::Null);
    }

    #[test]
    fn socket_paths_must_fit_sun_path() {
        let short = Path::new("/var/folders/xx/T/.tmpABC/sock");
        assert!(check_socket_paths(&short.join("vz.sock"), Some(&short.join("vsock.sock"))).is_ok());
        let deep = PathBuf::from(format!("/{}/sock", "d".repeat(84)));
        assert!(check_socket_paths(&deep.join("vz.sock"), None).is_ok());
        let err = check_socket_paths(&deep.join("vz.sock"), Some(&deep.join("vsock.sock"))).unwrap_err();
        assert!(
            matches!(&err, Error::InvalidSpec(m) if m.contains("vsock.sock_65535")),
            "{err}"
        );
    }

    #[test]
    fn a_nic_is_refused_before_anything_starts() {
        let dir = tempfile::tempdir().unwrap();
        let vmm = AppleVz {
            binary: "/nonexistent/vmkit-vz".into(),
        };
        let mut s = spec(dir.path());
        s.disks.clear();
        s.net = Some(crate::NetSpec::default());
        assert!(matches!(vmm.create(&s), Err(Error::Unsupported(m)) if m.contains("NIC")));
        s.net = None;
        s.tap = Some(crate::TapAttach {
            tap: "kiln0".into(),
            mac: "02:00:0a:00:00:05".into(),
        });
        assert!(matches!(vmm.create(&s), Err(Error::Unsupported(_))));
        assert!(!dir.path().join("console.log").exists(), "nothing was spawned");
        s.tap = None;
        s.vsock = Some(VsockSpec { guest_cid: 3 });
        assert!(
            matches!(vmm.restore(&SnapshotBundle { dir: dir.path().into() }, &restore_spec(dir.path())), Err(Error::Unsupported(m)) if m.contains("Team ID"))
        );
    }

    fn restore_spec(dir: &Path) -> RestoreSpec {
        RestoreSpec {
            disks: Vec::new(),
            console_log: dir.join("console.log"),
            run_dir: dir.to_path_buf(),
            net: None,
            chunks: None,
            scratch_dir: None,
        }
    }

    #[test]
    fn an_unsigned_helper_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("vmkit-vz");
        std::fs::write(&fake, "#!/bin/sh\necho 'vmkit-vz v0.1.0'\n").unwrap();
        let err = check_entitlement(&fake).unwrap_err();
        assert!(
            matches!(&err, Error::Prerequisite(m) if m.contains(ENTITLEMENT)),
            "{err}"
        );
    }

    #[test]
    fn capabilities_leave_25_devices_and_no_snapshots() {
        assert_eq!(CAPABILITIES.available_devices(), 25);
        let snapshots = CAPABILITIES.supports_snapshot;
        assert!(!snapshots);
    }
}
