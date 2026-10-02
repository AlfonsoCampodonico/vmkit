//! The backend-neutral VM lifecycle (kiln spec §4.1).

use std::path::Path;
use std::time::Duration;

use crate::error::Result;
use crate::spec::{Capabilities, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};

/// A VMM backend. Create VMs from it; decide on `capabilities`, never on `name`.
pub trait Vmm: Send + Sync {
    /// For logs and diagnostics only.
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// Starts a VMM process and configures `spec` in it; the guest has not started.
    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>>;
    /// Restores a snapshot into a fresh VMM process (implemented by project #2).
    fn restore(&self, bundle: &SnapshotBundle, spec: &RestoreSpec) -> Result<Box<dyn Vm>>;
}

/// One VM. Dropping it kills the VMM if it is still running.
pub trait Vm: Send {
    /// Starts the guest.
    fn start(&mut self) -> Result<()>;
    fn pause(&mut self) -> Result<()>;
    fn resume(&mut self) -> Result<()>;
    /// Ends the VM now. Graceful shutdown goes through the guest instead.
    fn kill(&mut self) -> Result<()>;
    /// Blocks until the VMM exits.
    fn wait(&mut self) -> Result<VmEnd>;
    /// Like `wait`, but gives up after `timeout`.
    fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<VmEnd>>;
    /// Writes a snapshot to `dest` (implemented by project #2).
    fn snapshot(&mut self, dest: &Path) -> Result<SnapshotBundle>;
    fn capabilities(&self) -> Capabilities;
    /// The host side of the vsock device, if the spec had one.
    fn vsock_socket(&self) -> Option<&Path>;
}
