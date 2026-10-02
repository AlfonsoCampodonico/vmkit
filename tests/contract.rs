//! The vmkit contract suite (kiln spec §11.3): every test runs against both backends.
//!
//! Needs KVM, the VMM binaries, and a test kernel and guest:
//!   VMKIT_TEST_KERNEL=<vmlinux or Image>  VMKIT_TEST_INITRAMFS=<initramfs.cpio.gz>
//! Without them each test is skipped, unless VMKIT_REQUIRE_KVM_TESTS=1 makes that a failure.
//! Pause and resume live in `tests/pause.rs`, which runs alone.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::time::{Duration, Instant};

use common::{Case, END};
use vmkit::{Backend, Disk, EndReason, Error, GuestExit, VsockSpec};

fn boots_and_ends_with_the_exit_method(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (_vm, end) = c.run(&c.spec("up"));
    assert_eq!(end.reason, EndReason::Exited, "{end:?}");
    assert_eq!(c.console().matches("VMKIT-GUEST-UP").count(), 1);
    assert!(
        !c.console().contains("Running Firecracker"),
        "VMM log lines in the guest console"
    );
}

fn a_guest_reset_ends_the_vm_once(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let (_vm, end) = c.run(&c.spec("reboot"));
    let expected = match c.vmm.capabilities().guest_exit {
        GuestExit::Reboot => EndReason::Exited,
        GuestExit::Poweroff => EndReason::ResetStopped,
    };
    assert_eq!(end.reason, expected, "{end:?}");
    // The workload must never run twice (kiln spec §4.1 backstop).
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(c.console().matches("VMKIT-GUEST-UP").count(), 1, "{}", c.console());
}

fn a_panic_ends_the_vm(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    for action in ["panic", "exit"] {
        let (_vm, end) = c.run(&c.spec(action));
        assert_ne!(end.reason, EndReason::Killed, "{action}: {end:?}");
    }
    assert_eq!(c.console().matches("VMKIT-GUEST-UP").count(), 2, "{}", c.console());
}

fn kill_ends_the_vmm_and_its_api(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut vm = c.vmm.create(&c.spec("idle")).unwrap();
    vm.start().unwrap();
    c.await_console("VMKIT-GUEST-TICK", 1);
    vm.kill().unwrap();
    let end = vm
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .expect("killed VMM is reaped");
    assert_eq!((end.reason, end.signal), (EndReason::Killed, Some(9)));
    let api = std::fs::read_dir(c.dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "sock") && !p.ends_with("vsock.sock"))
        .expect("API socket path");
    assert!(
        std::os::unix::net::UnixStream::connect(api).is_err(),
        "nobody serves the API any more"
    );
    vm.kill().unwrap();
    drop(vm);
}

fn disks_attach_in_order(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut spec = c.spec("disks");
    for (i, sectors) in [8u64, 16, 24].into_iter().enumerate() {
        let path = c.dir.path().join(format!("disk{i}.img"));
        std::fs::File::create(&path).unwrap().set_len(sectors * 512).unwrap();
        spec.disks.push(Disk {
            path,
            read_only: i != 1,
        });
    }
    let (_vm, end) = c.run(&spec);
    assert_eq!(end.reason, EndReason::Exited);
    let disks: Vec<String> = c
        .console()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("VMKIT-DISK ").map(String::from))
        .collect();
    assert_eq!(disks, ["vda 8", "vdb 16", "vdc 24"]);
}

fn device_budget_is_enforced_before_any_vmm_starts(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let available = c.vmm.capabilities().available_devices();
    let mut spec = c.spec("disks");
    spec.vsock = Some(VsockSpec { guest_cid: 3 });
    let disk = c.dir.path().join("disk.img");
    std::fs::File::create(&disk).unwrap().set_len(4096).unwrap();
    // vsock takes one device; fill the rest with disks, then one too many.
    spec.disks = (0..available)
        .map(|_| Disk {
            path: disk.clone(),
            read_only: true,
        })
        .collect();
    let err = c.vmm.create(&spec).err().expect("over budget");
    assert!(matches!(err, Error::TooManyDevices { .. }), "{err}");
    assert!(!c.dir.path().join("console.log").exists(), "no VMM was started");
    spec.disks.pop();
    let (_vm, end) = c.run(&spec);
    assert_eq!(end.reason, EndReason::Exited, "exactly the budget boots");
    assert_eq!(c.console().matches("VMKIT-DISK ").count(), available as usize - 1);
}

fn guest_vsock_connections_reach_the_host_socket(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut spec = c.spec("vsock");
    spec.vsock = Some(VsockSpec { guest_cid: 3 });
    let mut vm = c.vmm.create(&spec).unwrap();
    let host = vm.vsock_socket().expect("vsock socket").to_path_buf();
    // Guest-initiated connections to port P arrive on `<socket>_P` on both backends.
    let listener = UnixListener::bind(format!("{}_1234", host.display())).unwrap();
    vm.start().unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + END;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "the guest never connected; console tail:\n{}",
                    c.tail()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).unwrap();
    assert_eq!(line, "VMKIT-VSOCK-HELLO\n");
    (&stream).write_all(b"HOST-ACK\n").unwrap();
    let end = vm.wait_timeout(END).unwrap().expect("guest ends after the exchange");
    assert_eq!(end.reason, EndReason::Exited);
    assert!(c.console().contains("VMKIT-VSOCK-REPLY HOST-ACK"), "{}", c.console());
}

macro_rules! contract {
    ($($name:ident),* $(,)?) => {
        mod firecracker {
            $( #[test] fn $name() { super::$name(vmkit::Backend::Firecracker) } )*
        }
        mod cloud_hypervisor {
            $( #[test] fn $name() { super::$name(vmkit::Backend::CloudHypervisor) } )*
        }
    };
}

contract!(
    boots_and_ends_with_the_exit_method,
    a_guest_reset_ends_the_vm_once,
    a_panic_ends_the_vm,
    kill_ends_the_vmm_and_its_api,
    disks_attach_in_order,
    device_budget_is_enforced_before_any_vmm_starts,
    guest_vsock_connections_reach_the_host_socket,
);
