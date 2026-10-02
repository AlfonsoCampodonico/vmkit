//! The Firecracker driver.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::binary::{self, Version};
use crate::error::{Error, Result};
use crate::net;
use crate::process::{self, Proc};
use crate::sandbox;
use crate::spec::{Capabilities, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};
use crate::vmm::{Vm, Vmm};

pub const MIN_VERSION: Version = (1, 17, 0);
const NAME: &str = "firecracker";

pub struct Firecracker {
    binary: PathBuf,
    /// The sandbox helper every VMM runs under.
    sandbox: PathBuf,
    arch: &'static str,
}

impl Firecracker {
    /// Finds the binary (`$VMKIT_FIRECRACKER`, else `PATH`) and checks its version.
    pub fn discover() -> Result<Self> {
        let binary = binary::find("firecracker", "VMKIT_FIRECRACKER")?;
        binary::check_version(&binary, NAME, MIN_VERSION)?;
        Ok(Self {
            binary,
            sandbox: sandbox::find_helper()?,
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
        let api = sandbox::host(spec, "firecracker.sock");
        // Without --log-path Firecracker logs to stdout, which is the guest console.
        // It does not open the file for appending, so stderr gets a file of its own.
        let log = sandbox::host(spec, "firecracker.log");
        let args = vec![
            "--api-sock".into(),
            sandbox::inside("firecracker.sock"),
            "--id".into(),
            "vmkit".into(),
            "--log-path".into(),
            sandbox::inside("firecracker.log"),
        ];
        std::fs::create_dir_all(spec.run_dir.join("sock"))?;
        process::clear_socket(&api)?;
        process::create_vmm_file(&log)?;
        let proc = sandbox::spawn(
            &self.sandbox,
            &self.binary,
            &args,
            spec,
            &spec.run_dir.join("firecracker.stderr"),
        )?
        .with_log(&log);
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
        let r = self.proc.request(&self.api, method, path, Some(&body))?;
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
            "kernel_image_path": sandbox::KERNEL,
            "boot_args": spec.cmdline.iter().chain(backend_args).cloned().collect::<Vec<_>>().join(" "),
        });
        if spec.initramfs.is_some() {
            boot["initrd_path"] = json!(sandbox::INITRAMFS);
        }
        self.call("PUT", "/boot-source", boot)?;
        // Drives attach in this order: vda, vdb, ...
        for (i, d) in spec.disks.iter().enumerate() {
            let id = format!("disk{i}");
            self.call(
                "PUT",
                &format!("/drives/{id}"),
                json!({"drive_id": id, "path_on_host": sandbox::disk(i), "is_root_device": false, "is_read_only": d.read_only}),
            )?;
        }
        if let Some(v) = spec.vsock {
            let uds = sandbox::host(spec, "vsock.sock");
            process::clear_socket(&uds)?;
            let inside = sandbox::inside("vsock.sock");
            self.call("PUT", "/vsock", json!({"guest_cid": v.guest_cid, "uds_path": inside}))?;
            self.vsock = Some(uds);
        }
        if spec.net.is_some() {
            self.call(
                "PUT",
                "/network-interfaces/eth0",
                json!({"iface_id": "eth0", "host_dev_name": net::TAP, "guest_mac": net::GUEST_MAC}),
            )?;
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
