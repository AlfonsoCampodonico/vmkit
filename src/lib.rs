//! VMM-neutral microVM lifecycle for Firecracker and Cloud Hypervisor (kiln spec §4.1).
#![forbid(unsafe_code)]

mod binary;
mod error;
mod firecracker;
mod http;
mod process;
mod spec;
mod vmm;

pub use error::{Error, Result};
pub use firecracker::Firecracker;
pub use spec::{
    Capabilities, Disk, EndReason, GuestExit, NetSpec, RestoreSpec, SnapshotBundle, VmEnd, VmSpec, VsockSpec,
};
pub use vmm::{Vm, Vmm};

/// The backends `vmkit` drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Firecracker,
}

impl Backend {
    pub const ALL: [Backend; 1] = [Backend::Firecracker];

    /// Finds and version-checks the backend's binary.
    pub fn discover(self) -> Result<Box<dyn Vmm>> {
        Ok(match self {
            Backend::Firecracker => Box::new(Firecracker::discover()?),
        })
    }
}
