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
- **Sandbox:** every VMM runs as the invoking user inside its own user, PID, mount, network, IPC and UTS namespaces, in a read-only root holding only its devices, `/vmm`, `/vm/kernel`, `/vm/initramfs`, `/vm/disk/<n>` and `/vm/sock/` (which is `<run_dir>/sock`). It has no capabilities, `no_new_privs`, rlimits (no core dumps), a session keyring of its own, no descriptors but stdio, and cannot create user namespaces of its own. Files are attached by descriptor, and a symlink as the final path component is refused (`O_NOFOLLOW`; symlinks in the directories above it are followed). The library reads and creates the VMM's own files in `<run_dir>/sock` the same way, so a VMM cannot point them elsewhere. The helper refuses to run as root. With a systemd user session it also runs in a cgroup scope with memory, CPU and task limits (`vmkit::cgroups_available()` says whether; warn when not). The `vmkit-sandbox` helper does the namespace work: `$VMKIT_SANDBOX`, else next to the running program, else on `PATH`.
- **Network:** `VmSpec::net` gives the guest `eth0` at `172.30.0.2/30` (gateway and DNS `172.30.0.1`, `vmkit::net`) in the VM's own namespace: a tap, an nftables policy (`Egress::Restricted` by default: no link-local or cloud metadata, private, CGNAT, loopback, multicast or host addresses, where the host addresses are those present when the VM is created; `allow` exceptions, ignored under `Open`; `DenyAll` but DNS; `Open`), spoofed and IPv6 traffic dropped, and `pasta` for egress through host sockets and port forwards. The VMM itself opens no connections through `pasta`. Host ports below 1024 cannot be forwarded by an unprivileged `pasta` (unless the host lowers `net.ipv4.ip_unprivileged_port_start`): creating the VM fails with `pasta`'s message.
- **Snapshots:** `Vm::snapshot` and `Vmm::restore` have their final shape but return `Error::Unsupported` until the snapshot work lands.

## Sandboxing any program

`vmkit::sandbox::spawn` runs any program in the same helper, for example a build step (potter's namespace executor):

```rust
use vmkit::sandbox::{self, Command, Ids, Limits, Network, Program, Root, Spec, Stdio};

let spec = Spec {
    command: Command {
        program: Program::Path("/bin/sh".into()),
        arg0: None,
        args: vec!["-c".into(), "npm ci".into()],
        env: Some(vec![("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into())]),
        cwd: "/app".into(),
        user: None, // root inside: the caller on the host
    },
    root: Root::Overlay { lowers: vec![base.into()], upper: upper.into(), work: work.into() },
    mounts: vec![],
    ids: Ids::Subordinate { count: 65536 },
    network: Network::Egress(vmkit::NetSpec::default()),
    nest: true,
    seccomp: true,
    limits: Limits { open_files: 1 << 16, processes: 4096, cgroup: None },
    run_dir: run_dir.into(),
};
let status = sandbox::spawn(&spec, Stdio::inherit())?.wait()?;
```

- **Ids:** `Ids::Subordinate { count }` maps root to the caller and ids `1..=count` to the caller's `/etc/subuid` and `/etc/subgid` ranges through `newuidmap` and `newgidmap`, so files the program creates as uid 1000 belong to `subuid + 999` on the host. `Ids::Caller` is the VMM sandbox's single unprivileged id.
- **Roots:** `Root::Empty` (the VMM sandbox's tmpfs), `Root::Host` (the host tree, recursively read-only and nosuid, with the sandbox's own `/proc`; mount targets must exist), or `Root::Overlay` (an overlay mounted with `userxattr`, so whiteouts are 0/0 character devices and opaque directories carry `user.overlay.opaque`; it gets `/proc`, a read-only `/sys`, and a `/dev` with null, zero, full, random, urandom, tty, pts and shm). `Mount::Bind` and `Mount::Tmpfs` go on top; their writes never reach the upper.
- **Nesting:** with `nest`, the program runs in a user namespace of its own, mapped from outside with every id of the sandbox. It is still root over its files but holds no capability over the sandbox's mount and network namespaces: it cannot mount, change routes or the nftables policy, or create namespaces. `init` stays PID 1 and undumpable, so the program can neither signal nor inspect it.
- **Network:** `Network::None` (loopback only), `Network::Tap` (the VM network above), or `Network::Egress`: no tap, the namespace's own processes reach out through `pasta` under the same deny and allow sets, IPv6 and inbound connections are dropped, and DNS is answered at `vmkit::net::NAMESERVER` (put it in the root's `resolv.conf`).
- **Seccomp:** `seccomp` refuses mounts, namespace changes (including `clone` with namespace flags; `clone3` is `ENOSYS` so libc falls back to `clone`), keyrings, BPF, perf, userfaultfd, io_uring, modules, kexec, swap, reboot, clock changes and handle-based opens.
- **Process:** the program's stdin is `/dev/null`; `Stdio` sets its stdout and stderr. `init` supervises it as PID 1 and reaps everything; when the program ends, so does everything it started. The sandbox's exit mirrors the program's code or signal; a setup failure exits 125 with one `vmkit-sandbox: ...` line on stderr. `Sandbox::kill` ends everything in it.

## Requirements

Linux with KVM (`/dev/kvm`, user in the `kvm` group), the pinned VMMs, and the sandbox helper:

```bash
scripts/install-vmms.sh ~/.local/bin    # Firecracker 1.17.0 and Cloud Hypervisor 53.0, SHA-256 checked
cargo build --release --bin vmkit-sandbox
sudo install -m 0755 target/release/vmkit-sandbox /usr/local/bin/
scripts/install-apparmor.sh /usr/local/bin/vmkit-sandbox   # uses sudo; only acts where AppArmor restricts user namespaces
```

Sandboxing other programs with `Ids::Subordinate` also needs `newuidmap` and `newgidmap` (`uidmap` on Debian and Ubuntu) and a range of at least `count` ids for the user in `/etc/subuid` and `/etc/subgid`; overlay roots need Linux 5.12 or later (6.8 or later for many layers).

Ubuntu 23.10 and later restrict unprivileged user namespaces through AppArmor; the profile lets the helper create its own. The profile grants that to any binary at the given path, so install the helper to a root-owned path such as `/usr/local/bin`, not to a directory you can write. Networking also needs `pasta` (passt 2024-02-20 or later, as in Ubuntu 24.04 and Debian 13), `nft` and `ip`; `$VMKIT_PASTA` overrides the `pasta` found on `PATH`.

The library also builds on macOS (for kiln's non-run commands); creating VMs needs Linux. On a Mac, use the Lima template (Apple M3 or later, macOS 15 or later):

```bash
limactl start --name vmkit lima/vmkit.yaml
limactl shell vmkit -- "$PWD/scripts/install-vmms.sh"
```

The `kvm` group added by the template applies to new sessions only; run `limactl stop vmkit && limactl start vmkit` once after provisioning (or prefix commands with `sg kvm -c`).

The template mounts the Mac home read-only, so inside Lima build to guest paths and point the test variables there:

```bash
export CARGO_TARGET_DIR=~/target
kernels/build.sh aarch64 ~/out
testguest/build-initramfs.sh ~/out/initramfs.cpio.gz
export VMKIT_TEST_KERNEL=~/out/vmlinux-<version>-aarch64 VMKIT_TEST_INITRAMFS=~/out/initramfs.cpio.gz
```

## Kernel

`kernels/` holds the `base` profile: Firecracker's CI guest config for the pinned LTS (`kernels/VERSION`) plus vmkit's fragments (erofs, overlayfs, vsock, PL011 console, PVH, no netfilter). One binary per arch boots on both VMMs.

```bash
kernels/build.sh aarch64 out     # or x86_64 (cross-compiles when needed)
```

Tagging `kernels-<version>` builds both arches, boot-tests x86_64 on both VMMs, and publishes release assets and `ghcr.io/<owner>/vmkit-kernels/base:<version>-<arch>` (`.github/workflows/kernels.yml`). The ghcr package starts private; make it public in the package settings if kiln users should pull it anonymously.

Hosted arm64 runners have no KVM, so the aarch64 kernel is boot-tested by hand and the publish job refuses any aarch64 kernel that was not:

1. Run the `kernels` workflow by hand (`workflow_dispatch`) and download its `kernel-aarch64` artifact.
2. Run the contract suite on the Lima template with `VMKIT_TEST_KERNEL` pointing at that `vmlinux-<version>-aarch64`.
3. Commit `sha256sum vmlinux-<version>-aarch64` (run next to the file, so the line names it that way) as `kernels/tested-aarch64.sha256`.
4. Push the `kernels-<version>` tag. The cross-build is reproducible, so the tag's build produces the same hash; if the runner's toolchain changed, publishing refuses and you repeat the test.

## Tests

```bash
cargo test                                   # unit tests, any platform
cargo build --bin vmkit-sandbox && scripts/install-apparmor.sh "$PWD/target/debug/vmkit-sandbox"
testguest/build-initramfs.sh out/initramfs.cpio.gz
testguest/net-fixture.sh                     # fixture addresses for the network tests (sudo, once per boot)
export VMKIT_SANDBOX=$PWD/target/debug/vmkit-sandbox VMKIT_TEST_NET=1 VMKIT_REQUIRE_KVM_TESTS=1
export VMKIT_TEST_KERNEL=out/vmlinux-6.18.54-aarch64 VMKIT_TEST_INITRAMFS=out/initramfs.cpio.gz
cargo test --test sandbox                    # the helper alone, with busybox as the VMM (no KVM)
cargo test --test exec                       # any program: ids, roots, nesting, egress, seccomp (no KVM; needs uidmap and a subuid range)
cargo test --test contract -- --test-threads=4
cargo test --test network -- --test-threads=4
cargo test --test pause -- --test-threads=1
```

In the Lima VM, build into a guest path (`CARGO_TARGET_DIR=~/target`) and install the profile for `$HOME/target/debug/vmkit-sandbox`.

The contract suite (`tests/contract.rs`) runs every test against both backends with a busybox guest: boot and exit method, reset backstop, panic, kill, disk order, device budget, guest-initiated vsock, and the sandbox's contents and privileges. The network suite (`tests/network.rs`) is the hostile guest: cloud metadata, private and host addresses, the gateway, other VMs and spoofed sources must be unreachable, while allowed destinations, DNS and port forwards work. Set `VMKIT_TEST_TAP=<tap>` (a tap device you own, e.g. created with `sudo ip tuntap add vmkt0 mode tap user $(id -u)`) to also boot a VM with a network interface; the tap test must run alone because both backends would open the same tap: `VMKIT_TEST_TAP=vmkt0 cargo test --test contract a_tap_backed_nic_boots -- --test-threads=1`. Without `VMKIT_TEST_TAP` it returns early even under `VMKIT_REQUIRE_KVM_TESTS=1`, so CI does not cover it. Each VM's run directory also holds the VMM's own log (`firecracker.log`, `firecracker.stderr` or `cloud-hypervisor.log`) and, if Cloud Hypervisor's reset backstop ever fails, `backstop.log` saying why the VMM was killed (the VM then ends with `EndReason::BackstopFailed`). Pause and resume (`tests/pause.rs`) run alone: Cloud Hypervisor 53 on aarch64 can leave a guest stuck after a resume while other VMs load the host. That was reproduced with plain `ch-remote` under nested virtualization; Firecracker is unaffected. Keep the contract suite's `--test-threads` at about half the CPUs; under heavier load, Cloud Hypervisor guests also stalled occasionally on the same nested setup. A failing test prints the end of the guest console.

License: Apache-2.0.
