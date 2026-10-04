//! The vmkit contract suite (kiln spec §11.3): every test runs against both backends.
//!
//! Needs KVM, the VMM binaries, and a test kernel and guest:
//!   VMKIT_TEST_KERNEL=<vmlinux or Image>  VMKIT_TEST_INITRAMFS=<initramfs.cpio.gz>
//! Without them each test is skipped, unless VMKIT_REQUIRE_KVM_TESTS=1 makes that a failure.
//! Pause and resume live in `tests/pause.rs`, which runs alone.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
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
    // Both a panic and PID 1 exiting make the guest reset: Firecracker exits on it
    // (`reboot=k`), and Cloud Hypervisor's backstop stops the VMM. Never a plain kill.
    let expected = match c.vmm.capabilities().guest_exit {
        GuestExit::Reboot => EndReason::Exited,
        GuestExit::Poweroff => EndReason::ResetStopped,
    };
    for action in ["panic", "exit"] {
        let (_vm, end) = c.run(&c.spec(action));
        assert_eq!(end.reason, expected, "{action}: {end:?}");
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
    let api = std::fs::read_dir(c.dir.path().join("sock"))
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

fn a_guest_can_write_sector_0_of_a_writable_disk(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut spec = c.spec("sector0");
    let path = c.dir.path().join("disk.img");
    std::fs::File::create(&path).unwrap().set_len(1 << 20).unwrap();
    spec.disks.push(Disk {
        path: path.clone(),
        read_only: false,
    });
    let (_vm, end) = c.run(&spec);
    assert_eq!(end.reason, EndReason::Exited, "{end:?}\n{}", c.tail());
    assert!(c.console().contains("VMKIT-SECTOR0 ok"), "{}", c.tail());
    let pattern: Vec<u8> = b"VMKIT-SECTOR0-PATTERN\n".iter().copied().cycle().take(512).collect();
    let mut first = [0u8; 512];
    std::fs::File::open(&path).unwrap().read_exact(&mut first).unwrap();
    assert_eq!(first[..], pattern[..], "sector 0 on the host");
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

fn a_symlinked_disk_is_refused(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut spec = c.spec("disks");
    let real = c.dir.path().join("real.img");
    std::fs::File::create(&real).unwrap().set_len(4096).unwrap();
    let link = c.dir.path().join("link.img");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    spec.disks.push(Disk {
        path: link,
        read_only: true,
    });
    let err = c.vmm.create(&spec).err().expect("a symlink is never followed");
    assert!(matches!(&err, Error::EarlyExit(m) if m.contains("link.img")), "{err}");
}

fn a_run_dir_with_a_comma_boots(backend: Backend) {
    let Some(mut c) = Case::new(backend) else { return };
    // The VMM sees only /vm/sock, so host paths no longer reach Cloud Hypervisor's option parser.
    c.dir = tempfile::Builder::new().prefix("vm,dir").tempdir().unwrap();
    let (_vm, end) = c.run(&c.spec("up"));
    assert_eq!(end.reason, EndReason::Exited, "{end:?}\n{}", c.tail());
}

/// Every path under `dir`, relative to it, without descending into `/vm/sock`.
fn walk(dir: &std::path::Path, rel: &str, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = format!("{rel}/{}", entry.file_name().to_string_lossy());
        out.push(path.clone());
        if entry.file_type().unwrap().is_dir() && path != "/vm/sock" {
            walk(&entry.path(), &path, out);
        }
    }
}

fn status_field(status: &str, field: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .unwrap_or_else(|| panic!("no {field} in status"))
        .trim()
        .to_string()
}

fn the_vmm_sees_only_its_own_files_and_holds_no_privileges(backend: Backend) {
    let Some(c) = Case::new(backend) else { return };
    let mut spec = c.spec("idle");
    let disk = c.dir.path().join("disk.img");
    std::fs::File::create(&disk).unwrap().set_len(4096).unwrap();
    spec.disks.push(Disk {
        path: disk,
        read_only: true,
    });
    let mut vm = c.vmm.create(&spec).unwrap();
    vm.start().unwrap();
    c.await_console("VMKIT-GUEST-TICK", 1);
    let pid = std::fs::read_to_string(vmkit::sandbox::pid_file(c.dir.path())).unwrap();
    let proc_dir = std::path::PathBuf::from(format!("/proc/{}", pid.trim()));

    let mut seen = Vec::new();
    walk(&proc_dir.join("root"), "", &mut seen);
    seen.sort();
    let expected = [
        "/dev",
        "/dev/kvm",
        "/dev/null",
        "/dev/urandom",
        "/vm",
        "/vm/disk",
        "/vm/disk/0",
        "/vm/initramfs",
        "/vm/kernel",
        "/vm/sock",
        "/vmm",
    ];
    assert_eq!(seen, expected);

    let status = std::fs::read_to_string(proc_dir.join("status")).unwrap();
    let uid = rustix_free_uid();
    assert_eq!(status_field(&status, "Uid"), format!("{uid}\t{uid}\t{uid}\t{uid}"));
    for caps in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        assert_eq!(status_field(&status, caps), "0000000000000000", "{caps}");
    }
    assert_eq!(status_field(&status, "NoNewPrivs"), "1");
    assert!(
        status_field(&status, "NSpid").ends_with("\t1"),
        "PID 1 of its own namespace"
    );
    let limits = std::fs::read_to_string(proc_dir.join("limits")).unwrap();
    assert!(
        limits
            .lines()
            .any(|l| l.starts_with("Max open files") && l.split_whitespace().nth(3) == Some("1024")),
        "{limits}"
    );
    // Each backend filters some of its threads (Cloud Hypervisor per thread, not the main one).
    let filtered = std::fs::read_dir(proc_dir.join("task")).unwrap().any(|t| {
        let status = std::fs::read_to_string(t.unwrap().path().join("status")).unwrap_or_default();
        status_field(&status, "Seccomp") == "2"
    });
    assert!(filtered, "no VMM thread runs under seccomp");
    if vmkit::cgroups_available() {
        let cgroup = std::fs::read_to_string(proc_dir.join("cgroup")).unwrap();
        let path = cgroup.trim().strip_prefix("0::").expect("cgroup v2");
        let max = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/memory.max")).unwrap();
        assert_eq!(max.trim(), ((256u64 + 256) << 20).to_string());
    }
    vm.kill().unwrap();
    vm.wait().unwrap();
    assert!(!proc_dir.exists(), "the VMM is gone once the VM ended");
}

/// The invoking user's uid, from `/proc/self/status`.
fn rustix_free_uid() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status_field(&status, "Uid")
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
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
    a_guest_can_write_sector_0_of_a_writable_disk,
    device_budget_is_enforced_before_any_vmm_starts,
    guest_vsock_connections_reach_the_host_socket,
    the_vmm_sees_only_its_own_files_and_holds_no_privileges,
    a_symlinked_disk_is_refused,
    a_run_dir_with_a_comma_boots,
);
