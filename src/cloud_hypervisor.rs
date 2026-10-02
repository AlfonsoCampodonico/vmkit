//! The Cloud Hypervisor driver.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::binary::{self, Version};
use crate::error::{Error, Result};
use crate::events;
use crate::process::{self, Proc};
use crate::spec::{Capabilities, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};
use crate::vmm::{Vm, Vmm};

pub const MIN_VERSION: Version = (53, 0, 0);
const NAME: &str = "cloud-hypervisor";

pub struct CloudHypervisor {
    binary: PathBuf,
    arch: &'static str,
}

impl CloudHypervisor {
    /// Finds the binary (`$VMKIT_CLOUD_HYPERVISOR`, else `PATH`) and checks its version.
    pub fn discover() -> Result<Self> {
        let binary = binary::find("cloud-hypervisor", "VMKIT_CLOUD_HYPERVISOR")?;
        binary::check_version(&binary, NAME, MIN_VERSION)?;
        Ok(Self {
            binary,
            arch: std::env::consts::ARCH,
        })
    }
}

/// Landlock rules: Cloud Hypervisor may touch only the VM's own files (kiln spec §9.2).
fn landlock_rules(spec: &VmSpec) -> Vec<Value> {
    let rule = |path: &Path, access: &str| json!({"path": path, "access": access});
    let mut rules = vec![rule(&spec.kernel, "r")];
    if let Some(i) = &spec.initramfs {
        rules.push(rule(i, "r"));
    }
    for d in &spec.disks {
        rules.push(rule(&d.path, if d.read_only { "r" } else { "rw" }));
    }
    rules.push(rule(&spec.run_dir, "rw"));
    if let Some(n) = &spec.net {
        // Opening a tap needs the tun device and reading its flags from sysfs.
        rules.push(rule(Path::new("/dev/net/tun"), "rw"));
        rules.push(rule(&Path::new("/sys/class/net").join(&n.tap), "r"));
    }
    rules
}

/// Cloud Hypervisor splits `path=` option values on commas, so the run directory cannot have one.
fn check_run_dir(spec: &VmSpec) -> Result<()> {
    if spec.run_dir.to_string_lossy().contains(',') {
        return Err(Error::InvalidSpec(format!(
            "run_dir {} contains a comma, which Cloud Hypervisor's option parser cannot take",
            spec.run_dir.display()
        )));
    }
    Ok(())
}

/// The backstop thread: ends the VM on a guest reset, and kills the VMM if it can no longer watch.
fn run_backstop(proc: Proc, events: PathBuf, log: PathBuf) {
    let failure = match events::watch(events::Tail::new(events, proc.clone())) {
        events::Watch::Ended => return,
        events::Watch::Reset => match proc.stop_on_reset() {
            Ok(()) => return,
            Err(e) => format!("could not stop the VMM after a guest reset: {e}"),
        },
        events::Watch::Failed(e) => format!("cannot read the event stream: {e}"),
    };
    let _ = proc.fail_backstop();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = writeln!(f, "vmkit: reset backstop failed: {failure}; the VMM was killed");
    }
}

impl Vmm for CloudHypervisor {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_virtio_devices: 31,
            implicit_devices: 1,
            supports_diff_snapshot: false,
            supports_balloon: true,
            supports_drive_remap: false,
            guest_exit: GuestExit::Poweroff,
            console: if self.arch == "aarch64" { "ttyAMA0" } else { "ttyS0" },
        }
    }

    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>> {
        spec.check(&self.capabilities())?;
        check_run_dir(spec)?;
        let api = spec.run_dir.join("cloud-hypervisor.sock");
        let events = spec.run_dir.join("events.json");
        // A previous VM's events (say, its reset) must not reach this VM's backstop.
        match std::fs::remove_file(&events) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let args = vec![
            "--api-socket".into(),
            format!("path={}", api.display()),
            "--event-monitor".into(),
            format!("path={}", events.display()),
            "--seccomp".into(),
            "true".into(),
        ];
        crate::process::clear_socket(&api)?;
        let proc = process::spawn(
            &self.binary,
            &args,
            &spec.console_log,
            &spec.run_dir.join("cloud-hypervisor.log"),
        )?;
        // The backstop: a guest reset must end the VM, never reboot it (kiln spec §4.1).
        let watcher = proc.clone();
        let backstop_log = spec.run_dir.join("backstop.log");
        std::thread::spawn(move || run_backstop(watcher, events, backstop_log));
        let mut vm = ChVm {
            proc,
            api,
            vsock: None,
            caps: self.capabilities(),
        };
        vm.proc.wait_for_socket(&vm.api)?;
        vm.configure(spec, self.capabilities().console)?;
        Ok(Box::new(vm))
    }

    fn restore(&self, _bundle: &SnapshotBundle, _spec: &RestoreSpec) -> Result<Box<dyn Vm>> {
        Err(Error::Unsupported("restore"))
    }
}

struct ChVm {
    proc: Proc,
    api: PathBuf,
    vsock: Option<PathBuf>,
    caps: Capabilities,
}

impl ChVm {
    fn call(&self, path: &str, body: Option<Value>) -> Result<()> {
        let path = format!("/api/v1/{path}");
        let r = self.proc.request(&self.api, "PUT", &path, body.as_ref())?;
        if !(200..300).contains(&r.status) {
            return Err(Error::Api {
                backend: NAME,
                method: "PUT",
                path,
                status: r.status,
                body: r.body,
            });
        }
        Ok(())
    }

    fn configure(&mut self, spec: &VmSpec, console: &str) -> Result<()> {
        let mut cmdline = spec.cmdline.clone();
        cmdline.push(format!("console={console}"));
        let mut payload = json!({"kernel": spec.kernel, "cmdline": cmdline.join(" ")});
        if let Some(i) = &spec.initramfs {
            payload["initramfs"] = json!(i);
        }
        let mut config = json!({
            "payload": payload,
            "cpus": {"boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus},
            "memory": {"size": u64::from(spec.memory_mib) << 20},
            "disks": spec.disks.iter().map(|d| json!({"path": d.path, "readonly": d.read_only})).collect::<Vec<_>>(),
            // Guest serial on the VMM's stdout, which vmkit appends to the console log;
            // a `file=` serial would be truncated when the guest resets.
            "serial": {"mode": "Tty"},
            "console": {"mode": "Off"},
            "landlock_enable": true,
            "landlock_rules": landlock_rules(spec),
        });
        if let Some(v) = spec.vsock {
            let socket = spec.run_dir.join("vsock.sock");
            crate::process::clear_socket(&socket)?;
            config["vsock"] = json!({"cid": v.guest_cid, "socket": socket});
            self.vsock = Some(socket);
        }
        if let Some(n) = &spec.net {
            let mut net = json!({"tap": n.tap});
            if let Some(mac) = &n.guest_mac {
                net["mac"] = json!(mac);
            }
            config["net"] = json!([net]);
        }
        self.call("vm.create", Some(config))
    }
}

impl Vm for ChVm {
    fn start(&mut self) -> Result<()> {
        self.call("vm.boot", None)
    }

    fn pause(&mut self) -> Result<()> {
        self.call("vm.pause", None)
    }

    fn resume(&mut self) -> Result<()> {
        self.call("vm.resume", None)
    }

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
        Err(Error::Unsupported("snapshot"))
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }

    fn vsock_socket(&self) -> Option<&Path> {
        self.vsock.as_deref()
    }
}

impl Drop for ChVm {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait(Some(Duration::from_secs(5)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Disk, NetSpec};

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
            vcpus: 1,
            memory_mib: 128,
            vsock: None,
            net: None,
            console_log: "/run/vm/console.log".into(),
            run_dir: "/run/vm".into(),
        }
    }

    fn rules(spec: &VmSpec) -> Vec<(String, String)> {
        landlock_rules(spec)
            .iter()
            .map(|r| (r["path"].as_str().unwrap().into(), r["access"].as_str().unwrap().into()))
            .collect()
    }

    #[test]
    fn landlock_allows_only_the_vms_own_files() {
        let r = rules(&spec());
        let expected: Vec<(&str, &str)> = vec![
            ("/k/vmlinux", "r"),
            ("/k/initramfs", "r"),
            ("/d/ro.img", "r"),
            ("/d/rw.img", "rw"),
            ("/run/vm", "rw"),
        ];
        assert_eq!(
            r,
            expected
                .iter()
                .map(|(p, a)| (p.to_string(), a.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn landlock_allows_the_tap_device_when_there_is_a_nic() {
        let mut s = spec();
        s.net = Some(NetSpec {
            tap: "vmkt0".into(),
            guest_mac: None,
        });
        let r = rules(&s);
        assert!(r.contains(&("/dev/net/tun".into(), "rw".into())), "{r:?}");
        assert!(r.contains(&("/sys/class/net/vmkt0".into(), "r".into())), "{r:?}");
    }

    #[test]
    fn a_comma_in_the_run_dir_is_refused() {
        let mut s = spec();
        assert!(check_run_dir(&s).is_ok());
        s.run_dir = "/run/a,b".into();
        assert!(matches!(check_run_dir(&s), Err(Error::InvalidSpec(_))));
    }
}
