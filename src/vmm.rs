//! The backend-neutral VM lifecycle (kiln spec §4.1).

use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::EgressGate;
use crate::spec::{Capabilities, RestoreSpec, SnapshotBundle, VmEnd, VmSpec};

/// A VMM backend. Create VMs from it; decide on `capabilities`, never on `name`.
pub trait Vmm: Send + Sync {
    /// For logs and diagnostics only.
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// Starts a VMM process and configures `spec` in it; the guest has not started.
    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>>;
    /// Restores a snapshot into a fresh VMM process, paused: `Vm::resume` starts the guest.
    /// Only the VMM, version and architecture that took the snapshot restore it.
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
    /// Pauses the VM and writes a snapshot into `dest`, an empty or missing directory. The VM
    /// stays paused: resume it, or kill it.
    fn snapshot(&mut self, dest: &Path) -> Result<SnapshotBundle>;
    fn capabilities(&self) -> Capabilities;
    /// The host side of the vsock device, if the spec had one.
    fn vsock_socket(&self) -> Option<&Path>;
    /// Closes or reopens the guest's egress while the VM runs, without touching anything
    /// else: [`EgressGate::Closed`] refuses every new connection the guest opens through its
    /// namespace (DNS included), [`EgressGate::Policy`] puts the VM's own [`crate::NetSpec`]
    /// policy (`egress` and `allow`) back. The switch is one atomic `nft` transaction in the
    /// VM's network namespace: no packet sees a mix of the two. It is idempotent, may be
    /// repeated any number of times, and works from `create` on (before `start` too) and while
    /// the VM is paused. Connections that exist when the gate closes keep working, and port
    /// forwards keep reaching the guest. Every VM starts with `Policy`, a restored one too.
    ///
    /// Fails with [`Error::EgressUnavailable`] for a VM without a network of vmkit's own (no
    /// NIC, or a [`crate::TapAttach`] tap), and with [`Error::EgressFailed`] if the VM has
    /// ended or `nft` fails, leaving the policy in force as it was. The default
    /// implementation (for `Vm`s outside vmkit) is unavailable.
    fn set_egress(&mut self, gate: EgressGate) -> Result<()> {
        let _ = gate;
        Err(Error::EgressUnavailable("this Vm does not implement set_egress"))
    }
}
