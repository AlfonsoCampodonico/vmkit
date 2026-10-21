//! The Cloud Hypervisor driver.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::binary::{self, Version};
use crate::bundle::{self, Expect, Layout, VmmId};
use crate::ch_config;
use crate::error::{Error, Result};
use crate::events;
use crate::net;
use crate::process::Proc;
use crate::sandbox::{self, Mount};
use crate::snapshot::{self, Restore, Shape};
use crate::spec::{Capabilities, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};
use crate::vmm::{Vm, Vmm};

pub const MIN_VERSION: Version = (53, 0, 0);
const NAME: &str = "cloud-hypervisor";
/// What a Cloud Hypervisor snapshot is made of.
pub(crate) const LAYOUT: Layout = Layout {
    state: &["config.json", "state.json"],
    memory: "memory-ranges",
};
/// Snapshot and restore move all of guest memory, slowly under nested virtualization.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(600);
/// The largest snapshot `config.json` read (a few KiB in practice).
const MAX_CONFIG: u64 = 1 << 20;

pub struct CloudHypervisor {
    binary: PathBuf,
    version: Version,
    /// How the VMM may use userfaultfd for an on-demand memory restore, if at all.
    uffd: Uffd,
    /// The sandbox helper every VMM runs under.
    sandbox: PathBuf,
    arch: &'static str,
}

impl CloudHypervisor {
    /// Finds the binary (`$VMKIT_CLOUD_HYPERVISOR`, else `PATH`) and checks its version.
    pub fn discover() -> Result<Self> {
        let binary = binary::find("cloud-hypervisor", "VMKIT_CLOUD_HYPERVISOR")?;
        let version = binary::check_version(&binary, NAME, MIN_VERSION)?;
        Ok(Self {
            binary,
            version,
            uffd: Uffd::detect(),
            sandbox: sandbox::find_helper()?,
            arch: std::env::consts::ARCH,
        })
    }

    fn id(&self) -> VmmId {
        VmmId {
            name: NAME.into(),
            version: binary::show(self.version),
        }
    }

    /// Starts Cloud Hypervisor in the sandbox for `spec` (plus `extra` mounts) with its reset
    /// backstop, ready for its API.
    fn spawn(&self, spec: &VmSpec, extra: &[Mount], shape: Shape) -> Result<ChVm> {
        let api = sandbox::host(spec, "cloud-hypervisor.sock");
        let events = sandbox::host(spec, "events.json");
        std::fs::create_dir_all(spec.run_dir.join("sock"))?;
        // A previous VM's events (say, its reset) must not reach this VM's backstop.
        match std::fs::remove_file(&events) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let args = vec![
            "--api-socket".into(),
            format!("path={}", sandbox::inside("cloud-hypervisor.sock")),
            "--event-monitor".into(),
            format!("path={}", sandbox::inside("events.json")),
            "--seccomp".into(),
            "true".into(),
        ];
        crate::process::clear_socket(&api)?;
        let proc = sandbox::spawn_vmm(
            &self.sandbox,
            &self.binary,
            &args,
            spec,
            &spec.run_dir.join("cloud-hypervisor.log"),
            extra,
        )?;
        // The backstop: a guest reset must end the VM, never reboot it (kiln spec §4.1).
        let watcher = proc.clone();
        let backstop_log = spec.run_dir.join("backstop.log");
        std::thread::spawn(move || run_backstop(watcher, events, backstop_log));
        let vm = ChVm {
            proc,
            api,
            vsock: None,
            caps: self.capabilities(),
            shape,
        };
        vm.proc.wait_for_socket(&vm.api)?;
        Ok(vm)
    }
}

/// Whether Cloud Hypervisor may create a userfaultfd that sees KVM's faults, which an
/// on-demand memory restore needs (lazy-restore design §3). It tries `/dev/userfaultfd`
/// first, then the syscall, which only `vm.unprivileged_userfaultfd=1` allows unprivileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Uffd {
    /// `/dev/userfaultfd` is readable and writable by the caller: bind it into the sandbox.
    Device,
    Syscall,
    None,
}

impl Uffd {
    fn detect() -> Self {
        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/userfaultfd")
            .is_ok();
        if device {
            Uffd::Device
        } else if std::fs::read_to_string("/proc/sys/vm/unprivileged_userfaultfd").is_ok_and(|v| v.trim() == "1") {
            Uffd::Syscall
        } else {
            Uffd::None
        }
    }
}

/// Reads a snapshot's `config.json`, a file the bundle may have made anything.
fn read_config(path: &std::path::Path) -> Result<Value> {
    use std::io::Read;
    let file = crate::process::open_vmm_file(path).map_err(|e| Error::Snapshot(format!("{}: {e}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONFIG {
        return Err(Error::Snapshot("config.json is over 1 MiB".into()));
    }
    serde_json::from_slice(&bytes).map_err(|e| Error::Snapshot(format!("config.json: {e}")))
}

/// The body of `vm.restore`: from the sandbox's snapshot directory, paused. Memory is
/// copied in before the call returns, or faulted in on demand.
fn restore_body(on_demand: bool) -> Value {
    json!({
        "source_url": format!("file://{}", sandbox::SNAPSHOT),
        "prefault": false,
        "memory_restore_mode": if on_demand { "OnDemand" } else { "Copy" },
        "resume": false,
    })
}

/// Landlock rules: Cloud Hypervisor may touch only the VM's own files (kiln spec §9.2).
fn landlock_rules(spec: &VmSpec) -> Vec<Value> {
    let rule = |path: &str, access: &str| json!({"path": path, "access": access});
    let mut rules = vec![rule(sandbox::KERNEL, "r")];
    if spec.initramfs.is_some() {
        rules.push(rule(sandbox::INITRAMFS, "r"));
    }
    for (n, d) in spec.disks.iter().enumerate() {
        rules.push(rule(&sandbox::disk(n), if d.read_only { "r" } else { "rw" }));
    }
    rules.push(rule(sandbox::SOCK, "rw"));
    if spec.net.is_some() {
        rules.push(rule(sandbox::TUN, "rw"));
    }
    rules
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
            // Cloud Hypervisor copies a snapshot's memory in before it resumes, unless it
            // may use userfaultfd (lazy-restore design §3).
            lazy_memory: self.uffd != Uffd::None,
            guest_exit: GuestExit::Poweroff,
            console: if self.arch == "aarch64" { "ttyAMA0" } else { "ttyS0" },
        }
    }

    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>> {
        spec.check(&self.capabilities())?;
        let mut vm = self.spawn(spec, &[], Shape::of(spec, self.id()))?;
        vm.configure(spec, self.capabilities().console)?;
        Ok(Box::new(vm))
    }

    fn restore(&self, bundle: &SnapshotBundle, rs: &RestoreSpec) -> Result<Box<dyn Vm>> {
        let version = binary::show(self.version);
        let expect = Expect {
            vmm: NAME,
            version: &version,
            arch: self.arch,
            layout: LAYOUT,
        };
        let mut restore = Restore::prepare(bundle, rs, &expect)?;
        restore.spec.check(&self.capabilities())?;
        // The snapshot's config is rewritten, never passed on (design §4.5).
        let config = ch_config::rewrite(
            &read_config(restore.source("config.json").expect("a CH bundle has a config"))?,
            &restore.info,
            landlock_rules(&restore.spec),
        )?;
        let rewritten = rs.run_dir.join("restore-config.json");
        std::fs::write(&rewritten, serde_json::to_vec(&config).expect("JSON serialises"))?;
        restore.replace("config.json", rewritten);
        if restore.spec.vsock.is_some() {
            // Cloud Hypervisor binds the socket again, and refuses an existing file.
            crate::process::clear_socket(&sandbox::host(&restore.spec, "vsock.sock"))?;
        }
        // Memory comes in on demand only when it is served lazily and the VMM may use
        // userfaultfd; otherwise Copy reads it (through the lazy layer, skipping zero chunks).
        let on_demand = restore.lazy_memory() && self.uffd != Uffd::None;
        if on_demand && self.uffd == Uffd::Device {
            restore.mounts.push(Mount::Bind {
                source: "/dev/userfaultfd".into(),
                target: "/dev/userfaultfd".into(),
                writable: true,
            });
        }
        let mut vm = self.spawn(&restore.spec, &restore.mounts, restore.shape())?;
        vm.slow_call("vm.restore", Some(restore_body(on_demand)))?;
        if restore.spec.vsock.is_some() {
            vm.vsock = Some(sandbox::host(&restore.spec, "vsock.sock"));
        }
        Ok(Box::new(vm))
    }
}

struct ChVm {
    proc: Proc,
    api: PathBuf,
    vsock: Option<PathBuf>,
    caps: Capabilities,
    shape: Shape,
}

impl ChVm {
    fn call(&self, path: &str, body: Option<Value>) -> Result<()> {
        self.call_timeout(path, body, None)
    }

    fn slow_call(&self, path: &str, body: Option<Value>) -> Result<()> {
        self.call_timeout(path, body, Some(SNAPSHOT_TIMEOUT))
    }

    fn call_timeout(&self, path: &str, body: Option<Value>, timeout: Option<Duration>) -> Result<()> {
        let path = format!("/api/v1/{path}");
        let r = match timeout {
            Some(t) => self.proc.request_timeout(&self.api, "PUT", &path, body.as_ref(), t)?,
            None => self.proc.request(&self.api, "PUT", &path, body.as_ref())?,
        };
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
        let mut payload = json!({"kernel": sandbox::KERNEL, "cmdline": cmdline.join(" ")});
        if spec.initramfs.is_some() {
            payload["initramfs"] = json!(sandbox::INITRAMFS);
        }
        let mut config = json!({
            "payload": payload,
            "cpus": {"boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus},
            "memory": {"size": u64::from(spec.memory_mib) << 20},
            "disks": spec
                .disks
                .iter()
                .enumerate()
                .map(|(n, d)| disk_config(n, d))
                .collect::<Vec<_>>(),
            // Guest serial on the VMM's stdout, which vmkit appends to the console log;
            // a `file=` serial would be truncated when the guest resets.
            "serial": {"mode": "Tty"},
            "console": {"mode": "Off"},
            "landlock_enable": true,
            "landlock_rules": landlock_rules(spec),
        });
        if let Some(v) = spec.vsock {
            let socket = sandbox::host(spec, "vsock.sock");
            crate::process::clear_socket(&socket)?;
            config["vsock"] = json!({"cid": v.guest_cid, "socket": sandbox::inside("vsock.sock")});
            self.vsock = Some(socket);
        }
        if spec.net.is_some() {
            config["net"] = json!([{"tap": net::TAP, "mac": net::GUEST_MAC}]);
        }
        self.call("vm.create", Some(config))
    }
}

/// One entry of the `vm.create` disks. vmkit only supports raw images, so say so: left to
/// autodetect, Cloud Hypervisor refuses writes to sector 0, which breaks ext4 superblocks.
fn disk_config(n: usize, d: &crate::spec::Disk) -> serde_json::Value {
    json!({"path": sandbox::disk(n), "readonly": d.read_only, "image_type": "Raw"})
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

    fn snapshot(&mut self, dest: &Path) -> Result<SnapshotBundle> {
        bundle::prepare_dest(dest)?;
        // Pausing a paused VM is an error in Cloud Hypervisor; a VM is paused before every
        // snapshot here, so a failure that leaves it paused is not one.
        let _ = self.pause();
        let made = self.shape.vmm_dir()?;
        self.slow_call(
            "vm.snapshot",
            Some(json!({"destination_url": format!("file://{}", snapshot::VMM_DIR)})),
        )?;
        self.shape.finish(LAYOUT, dest, made)
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
    use crate::net::NetSpec;
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
        let expected: Vec<(String, String)> = [
            ("/vm/kernel", "r"),
            ("/vm/initramfs", "r"),
            ("/vm/disk/0", "r"),
            ("/vm/disk/1", "rw"),
            ("/vm/sock", "rw"),
        ]
        .iter()
        .map(|(p, a)| (p.to_string(), a.to_string()))
        .collect();
        assert_eq!(rules(&spec()), expected);
    }

    #[test]
    fn every_disk_is_declared_raw() {
        let s = spec();
        let disks: Vec<_> = s.disks.iter().enumerate().map(|(n, d)| disk_config(n, d)).collect();
        assert_eq!(
            disks,
            [
                json!({"path": "/vm/disk/0", "readonly": true, "image_type": "Raw"}),
                json!({"path": "/vm/disk/1", "readonly": false, "image_type": "Raw"}),
            ]
        );
    }

    #[test]
    fn landlock_allows_the_tun_device_when_there_is_a_nic() {
        let mut s = spec();
        s.net = Some(NetSpec::default());
        assert!(rules(&s).contains(&("/dev/net/tun".into(), "rw".into())));
    }
}
