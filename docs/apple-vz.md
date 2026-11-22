# The Apple Virtualization backend

`Backend::AppleVz` runs vmkit VMs natively on macOS on Apple Silicon, through Apple's
Virtualization.framework (VZ). There is no Lima and no KVM in the loop. It exists only on macOS
(`#[cfg(target_os = "macos")]`). The spike behind it is [spikes/apple-vz.md](spikes/apple-vz.md).

## How it works

VZ is an Objective-C framework built around delegates and completion handlers, and vmkit is
`#![forbid(unsafe_code)]`. So each VM runs in `vmkit-vz`, a Swift helper (`vz/main.swift`, one
process per VM), and `src/apple_vz.rs` only does process and socket work:

1. `create` checks the spec. It writes `<run_dir>/vz.json` (kernel, initramfs, command line,
   disks, vCPUs, memory, vsock) and opens `console_log` for appending, as the Linux drivers do.
   It spawns `vmkit-vz --config <run_dir>/vz.json --api <run_dir>/sock/vz.sock` with the console
   file as the helper's stdout.
2. The helper builds the VM and binds `sock/vsock.sock`. It binds `sock/vz.sock` last, so the VM
   is created, not started, once that socket accepts connections. A configuration error (a
   symlinked disk, say) makes it exit 2 with one `vmkit-vz: ...` line, which `create` returns as
   `Error::EarlyExit`.
3. `start`, `pause` and `resume` each send one JSON line on `vz.sock`, `{"op": "start"}`. The
   helper answers `{"ok": true}` or `{"ok": false, "error": "..."}` once VZ's completion handler
   runs.
4. The helper exits 0 when the guest powers off (`guestDidStop`), and 1 when VZ stops the VM
   with an error. `kill` sends SIGKILL to the helper, and Apple's per-VM XPC process dies with
   it. `wait` reaps the helper. Its PID is in `<run_dir>/vmm.pid`, where the Linux backends
   record the VMM.

| Run directory file | Contents |
|---|---|
| `vz.json` | The helper's configuration. |
| `vz.stderr` | The helper's own messages. |
| `vmm.pid` | The helper's PID. |
| `sock/vz.sock` | The API socket. |
| `sock/vsock.sock`, `sock/vsock.sock_<port>` | The vsock bridge (below). |

The device mapping: an uncompressed arm64 `Image` through `VZLinuxBootLoader`; disks as virtio-blk
in order (`vda`, `vdb`, ...), raw images whose size is a multiple of 512; a virtio console on
`hvc0`; a virtio entropy device; and a virtio-vsock device when the spec has one. The guest has no
network device.

## Building the helper

```bash
scripts/build-vmkit-vz.sh [OUTDIR]          # default target/vmkit-vz; prints the path
export VMKIT_VZ=$PWD/target/vmkit-vz/vmkit-vz   # or put vmkit-vz on PATH
```

The script compiles `vz/main.swift` with `swiftc`, which needs the Xcode command-line tools. It
signs the result ad hoc with `vz/vmkit-vz.entitlements`, which holds only
`com.apple.security.virtualization`, an unrestricted entitlement that needs no developer
identity. `AppleVz::discover()` finds the helper, checks `vmkit-vz --version` (0.1.0 or later),
and checks the entitlement with `codesign --display --entitlements -`. Without the entitlement, it
returns `Error::Prerequisite`. `vmkit-vz --check` exits 0 when the Mac can run VMs.

## What works and what does not

| | State |
|---|---|
| create, start, kill, wait, wait_timeout | Works |
| pause, resume | Works (no Team ID needed) |
| Disks, console, guest-initiated vsock | Works |
| Host-initiated vsock (`CONNECT <port>`) | Implemented as in the spike; no vmkit test yet |
| Network | None. A spec with `net` or `tap` is refused with `Error::Unsupported`. The guest has no NIC, so its egress is always denied, and `set_egress` returns `Error::EgressUnavailable`. |
| Snapshot, restore | `Error::Unsupported`, and `Capabilities::supports_snapshot` is false. VZ's save fails for an ad-hoc signed helper (spike §7). |
| Balloon, diff snapshots, drive remap, lazy memory | false |

Points that differ from the Linux backends:

- **The kernel needs the reset patch.** VZ reboots a guest in place on a reset, and the host
  cannot see it. The driver appends `vmkit.reset=poweroff`, and vmkit's kernel, from the patched
  build on (`kernels/patches/0001-reset-poweroff.patch`), turns every reset into a power-off. So
  `reboot(2)`, a panic with `panic=-1`, and PID 1 exiting all end the VM, with
  `EndReason::Exited`. There is no backstop and no `ResetStopped` here. **With an unpatched kernel,
  a reset reboots the guest forever**; the contract suite's reset test catches that. The
  `kernels-6.18.54` release predates the patch, so a new kernel release must ship before anyone
  pins a kernel for this backend.
- **vsock.** VZ has no wildcard listener, so the helper registers every host port in
  `apple_vz::VSOCK_PORTS` (1024–65535) up front, which adds about 3 ms. A guest connection to a
  port outside that range is refused. VZ assigns the guest CID itself, so `VsockSpec::guest_cid`
  is ignored. Guests reach the host at CID 2 as usual.
- **Socket paths.** macOS limits a Unix socket path to 103 bytes. `create` refuses a `run_dir`
  where `sock/vsock.sock_65535` would be longer. `std::env::temp_dir()` paths (`/var/folders/...`)
  fit; deep directories do not.
- **Isolation is Apple's.** The guest runs in `com.apple.Virtualization.VirtualMachine`, an XPC
  service that Apple sandboxes, started per VM and owned by the user. The helper runs
  unprivileged. vmkit's Linux sandbox (namespaces, seccomp, cgroups, AppArmor, the nft helper) does
  not apply on macOS, and the contract test of the sandbox's contents is Linux-only.
- **Device budget.** 27 virtio devices in all, two of them implicit (console and entropy), so 25
  are left for disks and vsock.

## Tests

The contract and pause suites run against Apple VZ on macOS. The contract suite drops its Linux
sandbox test and adds `no_network_and_no_snapshots`.

```bash
scripts/build-vmkit-vz.sh
export VMKIT_VZ=$PWD/target/vmkit-vz/vmkit-vz VMKIT_REQUIRE_KVM_TESTS=1
export VMKIT_TEST_KERNEL=<patched vmlinux-6.18.54-aarch64> VMKIT_TEST_INITRAMFS=<initramfs-aarch64.cpio.gz>
cargo test --test contract
cargo test --test pause
```

The patched kernel is the `kernel-aarch64` artifact of a `kernels` workflow run after the patch
merged; its hash is in `kernels/tested-aarch64.sha256`. The test initramfs builds on Linux only
(`testguest/build-initramfs.sh` needs a static busybox and a static C compiler), so build it once
in Lima or on a Linux machine. Both suites take a few seconds: a VZ guest boots in about 0.3 s.

CI builds and signs the helper on `macos-15` and runs `vmkit-vz --check`. GitHub's arm64 macOS
runners are VMs without nested virtualization, so the check is expected to report that VZ is
unavailable there, and the VM suites run locally. The CI job prints a warning instead of failing.
Running them in CI would need a self-hosted Apple Silicon runner, plus a published patched kernel
and initramfs.

## What kiln needs to pick this backend

kiln's VM code is Linux-only today. `kiln_run::linux` holds `Run`, `BuildVm`, the session, the
console relay and signals, under `#[cfg(target_os = "linux")]`. On macOS, `kiln run` prints
`LIMA_INSTRUCTIONS`. To run natively:

1. **Pin a vmkit revision with `Backend::AppleVz`, and a kernel with the reset patch.** That needs
   a new `kernels-*` release. kiln's kernel pin must point at a patched aarch64 `Image`. kiln-init
   needs no change: with the patch, its pre-`Config` `reboot()` ends the VM.
2. **Add the backend to kiln's choice of VMM.** `VmmKind` gets an `AppleVz` variant (for example
   `--vmm apple-vz`), the default on macOS. `run::backend` maps it to `Backend::AppleVz`.
   `exit_method` already follows `Capabilities::guest_exit` (`Poweroff`).
3. **Split the platform-neutral runtime from the Linux-only parts.** Most of `linux/` is plain
   Unix: `session.rs`, `console.rs`, `signals.rs`, `tty.rs` and `build.rs` use `rustix` poll,
   pipes, FIFOs and signals, which all exist on macOS. The truly Linux-only pieces:
   - `run::vmm_identity` and `rundir::kill_identity` use `pidfd_open` and `/proc` start times to
     pin the VMM. On macOS, use `vmm.pid` (the helper) with `proc_pidinfo` or `kill(pid, 0)`
     plus a start-time check from `sysctl kern.proc.pid`, or skip orphan reaping there at first.
   - `rustix::io::ioctl_fionread` in `session.rs` exists on macOS but needs checking.
   - Anything under `/proc` or `/sys`.

   A `cfg(unix)` module for the shared runtime, with small `linux`/`macos` shims for process
   identity, is likely the least churn.
4. **No network on macOS for now.** `kiln run --net`, `-p` and any non-deny-all egress must be
   refused clearly on Apple VZ, since vmkit refuses `net` with `Error::Unsupported`. `BuildVm`
   with `network: true` must be refused or fall back to no network. vmkit's
   `set_egress(EgressGate::Closed)` returns `EgressUnavailable` there, so `BuildVm` must skip that
   call when the VM has no NIC: no NIC is already closed. Steps that need the network cannot run
   until a userspace network stack exists (spike §9).
5. **Run directory length.** kiln's run directory is `$XDG_RUNTIME_DIR/kiln/<run-id>`, else
   `/tmp/kiln-<uid>/<run-id>`. On macOS that stays well under 103 bytes; keep it that way. vmkit
   refuses a run directory that is too long.
6. **vsock ports.** kiln's fixed ports 1024–1029 are within `VSOCK_PORTS`. kiln never sets or
   reads the guest CID on the host side, so VZ choosing the CID is fine.
7. **Distribution.** kiln on macOS must ship or build `vmkit-vz` next to its binary, signed
   (`scripts/build-vmkit-vz.sh`), and set `VMKIT_VZ` or put it on `PATH`. A cargo `build.rs` that
   runs the script is possible, but it makes every macOS build need `swiftc`.
8. **Tests.** kiln's `boot.rs` macro instantiates per backend; add an `apple_vz` module on macOS,
   dropping the network and snapshot tests. Its `match backend` arms (memory sizes) need an
   `AppleVz` arm.

Snapshots (`kiln` persist or restore paths, if any use `Vm::snapshot`) stay Linux-only until a
Team-ID-signed helper is tested (spike §7). Check `Capabilities::supports_snapshot`.
