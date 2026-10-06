//! VMM-neutral microVM lifecycle for Firecracker and Cloud Hypervisor (kiln spec §4.1).
#![forbid(unsafe_code)]

mod binary;
mod cloud_hypervisor;
mod error;
mod events;
mod firecracker;
mod http;
pub mod net;
mod process;
#[doc(hidden)]
pub mod sandbox;
mod spec;
mod subid;
mod vmm;

pub use cloud_hypervisor::CloudHypervisor;
pub use error::{Error, Result};
pub use firecracker::Firecracker;
pub use net::NetSpec;
pub use sandbox::cgroups_available;
pub use spec::{Capabilities, Disk, EndReason, GuestExit, RestoreSpec, SnapshotBundle, VmEnd, VmSpec, VsockSpec};
pub use vmm::{Vm, Vmm};

/// The backends `vmkit` drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Firecracker,
    CloudHypervisor,
}

impl Backend {
    pub const ALL: [Backend; 2] = [Backend::Firecracker, Backend::CloudHypervisor];

    /// Finds and version-checks the backend's binary.
    pub fn discover(self) -> Result<Box<dyn Vmm>> {
        Ok(match self {
            Backend::Firecracker => Box::new(Firecracker::discover()?),
            Backend::CloudHypervisor => Box::new(CloudHypervisor::discover()?),
        })
    }
}
