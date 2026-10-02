//! Shared by the KVM test binaries: the test kernel and guest, and a VM under test.
// Each test binary compiles this module and uses a different part of it.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use vmkit::{Backend, GuestExit, Vm, VmEnd, VmSpec, Vmm};

/// How long any guest may take to end by itself.
pub const END: Duration = Duration::from_secs(60);

pub struct Env {
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
}

pub fn env() -> Option<Env> {
    let get = |k: &str| std::env::var_os(k).map(PathBuf::from);
    match (get("VMKIT_TEST_KERNEL"), get("VMKIT_TEST_INITRAMFS")) {
        (Some(kernel), Some(initramfs)) => Some(Env { kernel, initramfs }),
        _ => {
            assert!(
                std::env::var_os("VMKIT_REQUIRE_KVM_TESTS").is_none(),
                "VMKIT_REQUIRE_KVM_TESTS is set but VMKIT_TEST_KERNEL/VMKIT_TEST_INITRAMFS are not"
            );
            None
        }
    }
}

/// A VM under test with its private run directory.
pub struct Case {
    pub dir: tempfile::TempDir,
    pub vmm: Box<dyn Vmm>,
    pub env: Env,
}

impl Case {
    pub fn new(backend: Backend) -> Option<Self> {
        let env = env()?;
        let vmm = backend.discover().expect("VMM binary");
        Some(Self {
            dir: tempfile::tempdir().unwrap(),
            vmm,
            env,
        })
    }

    pub fn exit_arg(&self) -> &'static str {
        match self.vmm.capabilities().guest_exit {
            GuestExit::Reboot => "vmkit.exit=reboot",
            GuestExit::Poweroff => "vmkit.exit=poweroff",
        }
    }

    pub fn spec(&self, action: &str) -> VmSpec {
        VmSpec {
            kernel: self.env.kernel.clone(),
            initramfs: Some(self.env.initramfs.clone()),
            cmdline: [
                "panic=-1",
                "rdinit=/init",
                &format!("vmkit.test={action}"),
                self.exit_arg(),
            ]
            .map(String::from)
            .to_vec(),
            disks: Vec::new(),
            vcpus: 1,
            memory_mib: 256,
            vsock: None,
            net: None,
            console_log: self.dir.path().join("console.log"),
            run_dir: self.dir.path().to_path_buf(),
        }
    }

    pub fn console(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("console.log")).unwrap_or_default()
    }

    /// The end of the console, for failure messages.
    pub fn tail(&self) -> String {
        let console = self.console();
        let lines: Vec<&str> = console.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }

    pub fn run(&self, spec: &VmSpec) -> (Box<dyn Vm>, VmEnd) {
        let mut vm = self.vmm.create(spec).expect("create");
        vm.start().expect("start");
        let end = vm
            .wait_timeout(END)
            .unwrap()
            .unwrap_or_else(|| panic!("VM did not end; console tail:\n{}", self.tail()));
        (vm, end)
    }

    /// Waits until the console has `n` occurrences of `needle`.
    pub fn await_console(&self, needle: &str, n: usize) {
        let deadline = Instant::now() + END;
        while self.console().matches(needle).count() < n {
            assert!(
                Instant::now() < deadline,
                "no {needle:?} x{n}; console tail:\n{}",
                self.tail()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
