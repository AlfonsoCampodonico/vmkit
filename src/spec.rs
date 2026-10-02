//! What a VM is made of, what backends can do, and how a VM ends (kiln spec §4.1).

use std::path::PathBuf;

/// One block device, in boot order (`vda`, `vdb`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub path: PathBuf,
    pub read_only: bool,
}

/// A vsock device. Guest-initiated connections to host port `P` arrive on the Unix
/// socket `<Vm::vsock_socket()>_P` (both backends use this hybrid scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockSpec {
    pub guest_cid: u32,
}

/// A network interface backed by an existing tap device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSpec {
    pub tap: String,
    pub guest_mac: Option<String>,
}

/// A VM to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSpec {
    pub kernel: PathBuf,
    pub initramfs: Option<PathBuf>,
    /// Kernel arguments from the caller. The driver appends the console and its
    /// backend's own parameters; nothing else contributes (kiln spec §8.3).
    pub cmdline: Vec<String>,
    pub disks: Vec<Disk>,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub vsock: Option<VsockSpec>,
    pub net: Option<NetSpec>,
    /// Guest serial output is appended here.
    pub console_log: PathBuf,
    /// A private (0700) directory for this VM's sockets and logs; it must exist.
    pub run_dir: PathBuf,
}

/// How the guest must end itself so that the VMM process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestExit {
    /// `reboot(2)`; Firecracker exits on reboot on both arches.
    Reboot,
    /// Power off; Cloud Hypervisor exits on power-off and rebuilds the VM on reset.
    Poweroff,
}

/// What a backend supports. Callers decide from these, never from the backend's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Capabilities {
    /// Virtio devices the machine model allows in total.
    pub max_virtio_devices: u32,
    /// Devices the backend always adds itself (Cloud Hypervisor's RNG).
    pub implicit_devices: u32,
    pub supports_diff_snapshot: bool,
    pub supports_balloon: bool,
    pub supports_drive_remap: bool,
    pub guest_exit: GuestExit,
    /// The guest console device, e.g. `ttyS0`.
    pub console: &'static str,
}

impl Capabilities {
    /// Devices left for the caller's disks, vsock and network.
    pub fn available_devices(&self) -> u32 {
        self.max_virtio_devices.saturating_sub(self.implicit_devices)
    }
}

/// Why a VM ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// The VMM exited by itself (the guest ended, or the VMM failed).
    Exited,
    /// `Vm::kill` was called.
    Killed,
    /// The guest reset and `vmkit` stopped the VMM rather than let it reboot.
    ResetStopped,
    /// The reset backstop could not watch the VMM, so `vmkit` killed it; see `<run_dir>/backstop.log`.
    BackstopFailed,
}

/// How a VM ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmEnd {
    pub reason: EndReason,
    /// The VMM's exit code, if it exited normally.
    pub code: Option<i32>,
    /// The signal that ended the VMM, if any.
    pub signal: Option<i32>,
}

/// A snapshot on disk (implemented by project #2; the shape is fixed now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBundle {
    pub dir: PathBuf,
}

/// Where a restored VM's resources live (implemented by project #2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSpec {
    pub disks: Vec<Disk>,
    pub console_log: PathBuf,
    pub run_dir: PathBuf,
}

impl VmSpec {
    /// The virtio devices this VM needs: its disks, vsock and network.
    pub fn devices_needed(&self) -> u32 {
        self.disks.len() as u32 + u32::from(self.vsock.is_some()) + u32::from(self.net.is_some())
    }

    /// Rejects a spec the backend cannot run; drivers call this before starting anything.
    pub fn check(&self, caps: &Capabilities) -> crate::Result<()> {
        let requested = self.devices_needed();
        if requested > caps.available_devices() {
            return Err(crate::Error::TooManyDevices {
                requested,
                available: caps.available_devices(),
            });
        }
        if self.vcpus == 0 || self.memory_mib < 64 {
            return Err(crate::Error::InvalidSpec(
                "at least 1 vCPU and 64 MiB of memory are required".into(),
            ));
        }
        if self
            .cmdline
            .iter()
            .any(|a| a.is_empty() || a.contains(char::is_whitespace))
        {
            return Err(crate::Error::InvalidSpec(
                "kernel arguments must be single non-empty words".into(),
            ));
        }
        // Paths go to the VMMs as JSON strings, which cannot carry arbitrary bytes.
        let paths = [&self.kernel, &self.console_log, &self.run_dir]
            .into_iter()
            .chain(self.initramfs.as_ref())
            .chain(self.disks.iter().map(|d| &d.path));
        for path in paths {
            if path.to_str().is_none() {
                return Err(crate::Error::InvalidSpec(format!(
                    "path {} is not valid UTF-8",
                    path.display()
                )));
            }
        }
        if !self.run_dir.is_dir() {
            return Err(crate::Error::InvalidSpec(format!(
                "run_dir {} is not an existing directory",
                self.run_dir.display()
            )));
        }
        if let Some(n) = &self.net {
            // The kernel's interface names: 1-15 bytes, no `/`, NUL or whitespace (and not `.` or `..`,
            // which would widen the Landlock rule for the tap's sysfs directory).
            let ok = (1..=15).contains(&n.tap.len())
                && !n.tap.contains(|c: char| c == '/' || c == '\0' || c.is_whitespace())
                && n.tap != "."
                && n.tap != "..";
            if !ok {
                return Err(crate::Error::InvalidSpec(format!(
                    "tap name {:?} must be 1-15 bytes with no '/', NUL or whitespace",
                    n.tap
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An existing directory for `run_dir`.
    fn here() -> PathBuf {
        std::env::temp_dir()
    }

    fn spec(disks: usize) -> VmSpec {
        VmSpec {
            kernel: "k".into(),
            initramfs: None,
            cmdline: vec!["quiet".into()],
            disks: (0..disks)
                .map(|i| Disk {
                    path: format!("d{i}").into(),
                    read_only: true,
                })
                .collect(),
            vcpus: 1,
            memory_mib: 128,
            vsock: Some(VsockSpec { guest_cid: 3 }),
            net: None,
            console_log: "c".into(),
            run_dir: here(),
        }
    }

    const CAPS: Capabilities = Capabilities {
        max_virtio_devices: 31,
        implicit_devices: 1,
        supports_diff_snapshot: false,
        supports_balloon: true,
        supports_drive_remap: false,
        guest_exit: GuestExit::Poweroff,
        console: "ttyAMA0",
    };

    #[test]
    fn device_budget_counts_disks_vsock_net_and_implicit_devices() {
        assert!(spec(29).check(&CAPS).is_ok(), "29 disks + vsock + rng = 31");
        let err = spec(30).check(&CAPS).unwrap_err();
        assert!(
            matches!(
                err,
                crate::Error::TooManyDevices {
                    requested: 31,
                    available: 30,
                    ..
                }
            ),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn paths_must_be_valid_utf8() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bad = std::path::PathBuf::from(OsStr::from_bytes(b"/tmp/\xff.img"));
        let mut s = spec(1);
        s.disks[0].path = bad.clone();
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
        let mut s = spec(0);
        s.kernel = bad.clone();
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
        let mut s = spec(0);
        s.initramfs = Some(bad.clone());
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
        let mut s = spec(0);
        s.run_dir = bad;
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
        assert!(spec(1).check(&CAPS).is_ok());
    }

    #[test]
    fn the_run_dir_must_be_an_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = spec(0);
        s.run_dir = dir.path().to_path_buf();
        assert!(s.check(&CAPS).is_ok());
        s.run_dir = dir.path().join("missing");
        let err = s.check(&CAPS).unwrap_err();
        assert!(
            matches!(&err, crate::Error::InvalidSpec(m) if m.contains("missing")),
            "{err}"
        );
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();
        s.run_dir = file;
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
    }

    #[test]
    fn tap_names_are_valid_interface_names() {
        let tap = |name: &str| {
            let mut s = spec(0);
            s.net = Some(NetSpec {
                tap: name.into(),
                guest_mac: None,
            });
            s.check(&CAPS)
        };
        for good in ["t", "vmkt0", "123456789012345"] {
            assert!(tap(good).is_ok(), "{good}");
        }
        for bad in ["", "1234567890123456", "a/b", "a b", "a\tb", "a\nb", "a\0b", ".", ".."] {
            assert!(matches!(tap(bad), Err(crate::Error::InvalidSpec(_))), "{bad:?}");
        }
    }

    #[test]
    fn kernel_arguments_are_single_words() {
        let mut s = spec(0);
        s.cmdline.push("a b".into());
        assert!(matches!(s.check(&CAPS), Err(crate::Error::InvalidSpec(_))));
    }
}
