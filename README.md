# vmkit

VMM-neutral microVM lifecycle for [Firecracker](https://github.com/firecracker-microvm/firecracker) and [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor), and the kernel they boot. It is the VM layer of [kiln](https://github.com/AlfonsoCampodonico/kiln) (design: kiln's `docs/superpowers/specs/2026-09-30-kiln-design.md`, §4.1, §8.2, §9 and §11.3).

```rust
use vmkit::{Backend, Disk, VmSpec, VsockSpec};

let vmm = Backend::Firecracker.discover()?;          // $VMKIT_FIRECRACKER, else PATH
let mut vm = vmm.create(&VmSpec {
    kernel: "vmlinux".into(),
    initramfs: None,
    cmdline: vec!["root=/dev/vda".into(), "ro".into(), "panic=-1".into()],
    disks: vec![Disk { path: "rootfs.erofs".into(), read_only: true }],
    vcpus: 2,
    memory_mib: 512,
    vsock: Some(VsockSpec { guest_cid: 3 }),
    net: None,
    console_log: "run/console.log".into(),
    run_dir: "run".into(),
})?;
vm.start()?;
let end = vm.wait()?;
```

- **Backends:** `Backend::Firecracker` and `Backend::CloudHypervisor`. Decide from `Vmm::capabilities()` (device budget, how the guest must exit, console device), never from the backend's name.
- **Guest exit:** the guest ends the VM with `capabilities().guest_exit`: `reboot` on Firecracker, `poweroff` on Cloud Hypervisor. A Cloud Hypervisor guest reset is stopped, not rebooted (`EndReason::ResetStopped`), so a workload never runs twice.
- **Kernel arguments:** the caller's `cmdline` plus the console and backend parameters vmkit appends. Nothing else contributes.
- **vsock:** guest-initiated connections to host port `P` arrive on the Unix socket `<vm.vsock_socket()>_P` on both backends.
- **Snapshots:** `Vm::snapshot` and `Vmm::restore` have their final shape but return `Error::Unsupported` until the snapshot work lands.

## Requirements

Linux with KVM (`/dev/kvm`, user in the `kvm` group) and the pinned VMMs:

```bash
scripts/install-vmms.sh ~/.local/bin    # Firecracker 1.17.0 and Cloud Hypervisor 53.0, SHA-256 checked
```

The library also builds on macOS (for kiln's non-run commands); creating VMs needs Linux. On a Mac, use the Lima template (Apple M3 or later, macOS 15 or later):

```bash
limactl start --name vmkit lima/vmkit.yaml
limactl shell vmkit -- "$PWD/scripts/install-vmms.sh"
```

## Kernel

`kernels/` holds the `base` profile: Firecracker's CI guest config for the pinned LTS (`kernels/VERSION`) plus vmkit's fragments (erofs, overlayfs, vsock, PL011 console, PVH, no netfilter). One binary per arch boots on both VMMs.

```bash
kernels/build.sh aarch64 out     # or x86_64 (cross-compiles when needed)
```

Tagging `kernels-<version>` builds both arches, boot-tests x86_64 on both VMMs, and publishes release assets and `ghcr.io/<owner>/vmkit-kernels/base:<version>-<arch>` (`.github/workflows/kernels.yml`). Boot-test aarch64 on the Lima template before tagging: hosted arm64 runners have no KVM.

## Tests

```bash
cargo test                                   # unit tests, any platform
testguest/build-initramfs.sh out/initramfs.cpio.gz
export VMKIT_TEST_KERNEL=out/vmlinux-6.18.54-aarch64 VMKIT_TEST_INITRAMFS=out/initramfs.cpio.gz VMKIT_REQUIRE_KVM_TESTS=1
cargo test --test contract -- --test-threads=4
cargo test --test pause -- --test-threads=1
```

The contract suite (`tests/contract.rs`) runs every test against both backends with a busybox guest: boot and exit method, reset backstop, panic, kill, disk order, device budget and guest-initiated vsock. Set VMKIT_TEST_TAP=<tap> (a tap device you own, e.g. created with `sudo ip tuntap add vmkt0 mode tap user $(id -u)`) to also boot a VM with a network interface. Pause and resume (`tests/pause.rs`) run alone: Cloud Hypervisor 53 on aarch64 can leave a guest stuck after a resume while other VMs load the host. That was reproduced with plain `ch-remote` under nested virtualization; Firecracker is unaffected. Keep the contract suite's `--test-threads` at about half the CPUs; under heavier load, Cloud Hypervisor guests also stalled occasionally on the same nested setup. A failing test prints the end of the guest console.

License: Apache-2.0.
