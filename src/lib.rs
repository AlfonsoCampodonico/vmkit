//! VMM-neutral microVM lifecycle for Firecracker and Cloud Hypervisor (kiln spec §4.1).
#![forbid(unsafe_code)]

mod error;
mod spec;

pub use error::{Error, Result};
pub use spec::{
    Capabilities, Disk, EndReason, GuestExit, NetSpec, RestoreSpec, SnapshotBundle, VmEnd, VmSpec, VsockSpec,
};
