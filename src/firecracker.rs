//! The Firecracker driver.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::binary::{self, Version};
use crate::error::{Error, Result};
use crate::http;
use crate::process::{self, Proc};
use crate::spec::{Capabilities, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};
use crate::vmm::{Vm, Vmm};

pub const MIN_VERSION: Version = (1, 17, 0);
const NAME: &str = "firecracker";

pub struct Firecracker {
    binary: PathBuf,
    arch: &'static str,
}

impl Firecracker {
    /// Finds the binary (`$VMKIT_FIRECRACKER`, else `PATH`) and checks its version.
    pub fn discover() -> Result<Self> {
        let binary = binary::find("firecracker", "VMKIT_FIRECRACKER")?;
        binary::check_version(&binary, NAME, MIN_VERSION)?;
        Ok(Self {
            binary,
            arch: std::env::consts::ARCH,
        })
    }

    /// Kernel arguments Firecracker needs, because custom `boot_args` replace its defaults.
    fn backend_args(&self) -> Vec<String> {
        let mut args = vec![format!("console={}", self.capabilities().console)];
        if self.arch == "x86_64" {
            // x86_64 Firecracker exits only on a keyboard-controller reset.
            args.extend(["reboot=k", "i8042.noaux", "i8042.nomux", "i8042.dumbkbd"].map(String::from));
        }
        args
    }
}

impl Vmm for Firecracker {
    fn name(&self) -> &'static str {
        NAME
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_virtio_devices: if self.arch == "aarch64" { 92 } else { 17 },
            implicit_devices: 0,
            supports_diff_snapshot: true,
            supports_balloon: true,
            supports_drive_remap: true,
            guest_exit: GuestExit::Reboot,
            console: "ttyS0",
        }
    }

    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>> {
        spec.check(&self.capabilities())?;
        let api = spec.run_dir.join("firecracker.sock");
        let args = vec![
            "--api-sock".into(),
            api.display().to_string(),
            "--id".into(),
            "vmkit".into(),
        ];
        process::clear_socket(&api)?;
        let proc = process::spawn(
            &self.binary,
            &args,
            &spec.console_log,
            &spec.run_dir.join("firecracker.log"),
        )?;
        let vm = FirecrackerVm {
            proc,
            api,
            vsock: None,
            caps: self.capabilities(),
        };
        vm.proc.wait_for_socket(&vm.api)?;
        let mut vm = vm;
        vm.configure(spec, &self.backend_args())?;
        Ok(Box::new(vm))
    }

    fn restore(&self, _bundle: &SnapshotBundle, _spec: &RestoreSpec) -> Result<Box<dyn Vm>> {
        Err(Error::Unsupported("restore"))
    }
}

struct FirecrackerVm {
    proc: Proc,
    api: PathBuf,
    vsock: Option<PathBuf>,
    caps: Capabilities,
}

impl FirecrackerVm {
    fn call(&self, method: &'static str, path: &str, body: Value) -> Result<()> {
        let r = http::request(&self.api, method, path, Some(&body))?;
        if !(200..300).contains(&r.status) {
            return Err(Error::Api {
                backend: NAME,
                method,
                path: path.into(),
                status: r.status,
                body: r.body,
            });
        }
        Ok(())
    }

    fn configure(&mut self, spec: &VmSpec, backend_args: &[String]) -> Result<()> {
        self.call(
            "PUT",
            "/machine-config",
            json!({"vcpu_count": spec.vcpus, "mem_size_mib": spec.memory_mib}),
        )?;
        let mut boot = json!({
            "kernel_image_path": spec.kernel,
            "boot_args": spec.cmdline.iter().chain(backend_args).cloned().collect::<Vec<_>>().join(" "),
        });
        if let Some(initrd) = &spec.initramfs {
            boot["initrd_path"] = json!(initrd);
        }
        self.call("PUT", "/boot-source", boot)?;
        // Drives attach in this order: vda, vdb, ...
        for (i, d) in spec.disks.iter().enumerate() {
            let id = format!("disk{i}");
            self.call(
                "PUT",
                &format!("/drives/{id}"),
                json!({"drive_id": id, "path_on_host": d.path, "is_root_device": false, "is_read_only": d.read_only}),
            )?;
        }
        if let Some(v) = spec.vsock {
            let uds = spec.run_dir.join("vsock.sock");
            process::clear_socket(&uds)?;
            self.call("PUT", "/vsock", json!({"guest_cid": v.guest_cid, "uds_path": uds}))?;
            self.vsock = Some(uds);
        }
        if let Some(n) = &spec.net {
            let mut iface = json!({"iface_id": "eth0", "host_dev_name": n.tap});
            if let Some(mac) = &n.guest_mac {
                iface["guest_mac"] = json!(mac);
            }
            self.call("PUT", "/network-interfaces/eth0", iface)?;
        }
        Ok(())
    }
}

impl Vm for FirecrackerVm {
    fn start(&mut self) -> Result<()> {
        self.call("PUT", "/actions", json!({"action_type": "InstanceStart"}))
    }

    fn pause(&mut self) -> Result<()> {
        self.call("PATCH", "/vm", json!({"state": "Paused"}))
    }

    fn resume(&mut self) -> Result<()> {
        self.call("PATCH", "/vm", json!({"state": "Resumed"}))
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

impl Drop for FirecrackerVm {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait(Some(Duration::from_secs(5)));
    }
}
