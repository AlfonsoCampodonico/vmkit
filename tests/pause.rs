//! Pause and resume on both backends, run on an otherwise idle host.
//!
//! Cloud Hypervisor 53 on aarch64 can leave a guest stuck after a resume when other
//! VMs load the host (reproduced with plain `ch-remote` under nested virtualization;
//! Firecracker is unaffected), so this binary runs after the contract suite with
//! `--test-threads=1`. Same environment variables as `tests/contract.rs`.

mod common;

use std::time::Duration;

use common::Case;
use vmkit::Backend;

fn pause_stops_the_guest_and_resume_continues_it(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut vm = c.vmm.create(&c.spec("idle")).unwrap();
    vm.start().unwrap();
    c.await_console("VMKIT-GUEST-TICK", 3);
    vm.pause().unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let paused = c.console().matches("VMKIT-GUEST-TICK").count();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        c.console().matches("VMKIT-GUEST-TICK").count(),
        paused,
        "ticks while paused"
    );
    vm.resume().unwrap();
    c.await_console("VMKIT-GUEST-TICK", paused + 3);
    vm.kill().unwrap();
}

#[test]
fn firecracker() {
    pause_stops_the_guest_and_resume_continues_it(Backend::Firecracker)
}

#[test]
fn cloud_hypervisor() {
    pause_stops_the_guest_and_resume_continues_it(Backend::CloudHypervisor)
}
