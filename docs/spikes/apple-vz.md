# Spike: kiln guests on Apple's Virtualization.framework

Status: spike, throwaway. Branch `spike/apple-vz`. Run on macOS 27.0.1 (26A434), Apple Silicon.

**Result: it works.** A static aarch64 musl `kiln-init` built from kiln `main`
(945e51c) boots under the `vmkit-vz` helper with no Lima in the loop. Its `Hello`
reaches the host over the bridged vsock in about 300 ms from process start. The
guest side did not change. The kernel, the init layer (erofs, built by
`kiln_image::init_layer`), `root=/dev/vda rootfstype=erofs init=/kiln-init` and
kiln-proto over vsock port 1024 all work as they are.

VZ reboots a guest in place on reset, so a guest reset never ended the VM. A small
opt-in kernel patch, `vmkit.reset=poweroff`, fixes that (§5).

The helper is `spike/vmkit-vz/` (`main.swift`, `vmkit-vz.entitlements`, `build.sh`).
It is not wired into vmkit's API.

## 1. Evidence

Boot command (vda is the init layer, vdb a 64 MiB scratch disk):

```sh
python3 -I spike/vmkit-vz/host.py "$RUN/v.sock" 30 &   # listens on $RUN/v.sock_1024, plays kiln-run's side
spike/vmkit-vz/out/vmkit-vz --kernel out/vmlinux-6.18.54-aarch64 \
  --cmdline "root=/dev/vda ro rootfstype=erofs init=/kiln-init panic=-1 console=hvc0" \
  --disk init.erofs:ro --disk scratch.raw --cpus 2 --memory-mib 512 \
  --console-log "$RUN/console.log" --vsock-uds "$RUN/v.sock" --vsock-listen 1024-1029
```

What the host received on `v.sock_1024`, kiln-proto frame `Hello`. The bytes are a
`u32` LE length (15), type 1, then the JSON payload:

```
0f 00 00 00 01 7b 22 70 72 6f 74 6f 63 6f 6c 22 3a 32 7d
len=15 type=1 payload={"protocol": 2}
```

The helper's timeline, run without `quiet` (timestamps are from the helper's start):

```
[    17.7 ms] starting
[   121.3 ms] started
[   374.6 ms] vsock guest->host port 1024: accepted (guest port 907033433)
[   688.4 ms] SIGTERM: stopping
```

The console log (`hvc0`) from the same run. VZ has no early UART, so lines before
the virtio console registers (about 0.17 s) are not in it:

```
[    0.171521] random: crng init done
[    0.174115] loop: module loaded
[    0.174331] virtio_blk virtio1: 1/0/0 default/read/poll queues
[    0.174598] virtio_blk virtio1: [vda] 2960 512-byte logical blocks (1.52 MB/1.45 MiB)
[    0.175014] virtio_blk virtio2: 1/0/0 default/read/poll queues
[    0.176810] virtio_blk virtio2: [vdb] 131072 512-byte logical blocks (67.1 MB/64.0 MiB)
[    0.177094] Loading iSCSI transport class v2.0-870.
[    0.177383] iscsi: registered transport (tcp)
[    0.177487] tun: Universal TUN/TAP device driver, 1.6
[    0.177724] rtc-pl031 20050000.pl031: registered as rtc0
[    0.177886] rtc-pl031 20050000.pl031: setting system clock to 2026-11-21T11:09:59 UTC (1795259399)
[    0.178128] Initializing XFRM netlink socket
[    0.178178] NET: Registered PF_INET6 protocol family
[    0.178356] watchdog: NMI not fully supported
[    0.178530] watchdog: Hard watchdog permanently disabled
[    0.178881] Segment Routing with IPv6
[    0.178961] In-situ OAM (IOAM) with IPv6
[    0.179119] NET: Registered PF_PACKET protocol family
[    0.179312] Key type dns_resolver registered
[    0.179399] NET: Registered PF_VSOCK protocol family
[    0.180492] registered taskstats version 1
[    0.180627] Loading compiled-in X.509 certificates
[    0.181527] Demotion targets for Node 0: null
[    0.181654] Key type .fscrypt registered
[    0.181677] Key type fscrypt-provisioning registered
[    0.182252] Key type encrypted registered
[    0.185979] clk: Disabling unused clocks
[    0.186728] check access for rdinit=/init failed: -2, ignoring
[    0.187115] erofs (device vda): mounted with root inode @ nid 1.
[    0.187273] VFS: Mounted root (erofs filesystem) readonly on device 254:0.
[    0.187717] devtmpfs: mounted
[    0.188388] Freeing unused kernel memory: 1344K
[    0.188487] Run /kiln-init as init process
```

kiln-init prints nothing on success, so the log stops at `Run /kiln-init`. When the
host closes the control connection, kiln-init prints `kiln-init: control: the host
closed the control connection before Config` and calls `reboot()`. On VZ that
loops, unless the kernel has the reset patch (§5).

The host-initiated path was checked with a small static vsock echo guest listening
on port 5000. `CONNECT 5000\n` got `OK 3830849844\n`, a line echoed back, and a
half-close from the host got EOF back from the guest. Then the guest powered off and
the helper exited 0.

## 2. Swift, not Rust

The helper is Swift, one file, built with `swiftc`. Swift was clearly simpler:

- VZ is delegate-and-completion-handler shaped (`VZVirtualMachineDelegate`,
  `VZVirtioSocketListenerDelegate`, `start`/`pause`/`save`/`connect` callbacks). It
  also requires main-queue affinity. In Swift that is plain code. With
  `objc2-virtualization` each delegate is a `define_class!`, each callback a
  `block2` block, and almost every call is `unsafe`.
- Nothing is lost. The helper is a separate signed binary that vmkit spawns, so
  vmkit keeps `#![forbid(unsafe_code)]` whatever the helper is written in. The
  entitlement stays on the helper binary only.
- The cost: building needs the Xcode command-line tools (`swiftc`) next to cargo.
  Any macOS host that can sign the binary already has them. If a cargo-only build
  ever matters, a port to objc2 is mechanical. The helper is about 350 lines.

## 3. Kernel format

**VZ needs an uncompressed arm64 `Image`. The current build output already is one,
so no new build output is needed.** `kernels/build.sh` copies
`arch/arm64/boot/Image` to `out/vmlinux-<version>-aarch64` for aarch64. That file is
not an ELF, despite its name. `file` reports `Linux kernel ARM64 boot executable
Image`, and VZ boots it as it is. A gzip-compressed copy (`Image.gz`) fails at
`start` with `VZErrorDomain Code=1 "The virtual machine failed to start."`. An ELF
`vmlinux` was not tested, since the build has no aarch64 ELF to hand.

The arm64 artifact name is misleading. A rename to `Image-…-aarch64`, or a note in
`kernels/`, would help. Firecracker and Cloud Hypervisor take the same file on
aarch64, so no other change is needed. The config needs nothing new.
`CONFIG_VIRTIO_PCI`, `CONFIG_VIRTIO_BLK`, `CONFIG_VIRTIO_CONSOLE`,
`CONFIG_VIRTIO_VSOCKETS`, `CONFIG_HW_RANDOM_VIRTIO`, `CONFIG_EROFS_FS` and
`CONFIG_RTC_DRV_PL031` are all already on.

## 4. Signing

The only entitlement is `com.apple.security.virtualization`. It is not restricted,
so an ad-hoc signature works and no developer identity is needed:

```sh
swiftc -O -o out/vmkit-vz main.swift
codesign --force --sign - --entitlements vmkit-vz.entitlements out/vmkit-vz
codesign --display --entitlements - out/vmkit-vz   # [Key] com.apple.security.virtualization
```

Without the entitlement, `VZVirtualMachine` creation fails. Hardened runtime
(`--options runtime`) changes nothing for booting. Snapshots are the exception: they
appear to need a real Team ID (§7).

## 5. Boot time and guest exit

Boot time, five runs with `quiet loglevel=3`, from `exec` of the helper:

| milestone | time |
|---|---|
| `start()` completes (VM process up, vCPUs running) | 94–99 ms |
| kiln-init's `Hello` arrives on `v.sock_1024` | 286–310 ms (median ~300 ms) |
| shell `exec` → `Hello`, wall clock | 291–314 ms |

Without `quiet` it takes about 375 ms, because the console costs time. The guest
reaches `Run /kiln-init` at 0.188 s guest time. The vmkit test initramfs
(`vmkit.test=up vmkit.exit=poweroff`) boots and powers off in about 270 ms, from
helper start to helper exit.

**A guest reset reboots the VM in place, and the host cannot see it.** `reboot(2)`,
a kernel panic with `panic=-1`, and PID 1 exiting all restart the guest through
`VZLinuxBootLoader` again:

- `guestDidStop` does not fire.
- `VZVirtualMachine.state` stays `running` (observed through KVO).
- No delegate method is called.

The test guest booted 21–27 times in 4 s. kiln-init looped too: it reboots before
`Config` when the host has gone, so it reconnected every ~320 ms. Only power-off
(PSCI `SYSTEM_OFF`) ends the VM, and then `guestDidStop` fires.

This is the problem vmkit's Cloud Hypervisor reset backstop solves (kiln spec §4.1:
a guest reset must end the VM). VZ gives the host nothing to watch, so the fix goes
in the guest kernel.

**Fixed: `kernels/patches/0001-reset-poweroff.patch`.** It adds the kernel argument
`vmkit.reset=poweroff`. With it, `do_kernel_restart()` runs the power-off handlers
(PSCI `SYSTEM_OFF` on arm64) before the restart handlers. Every reset path then ends
the VM:

- `reboot(2)`;
- a panic with `panic=-1` (`emergency_restart()`);
- PID 1 exiting.

Without the argument the kernel behaves as upstream does, so Firecracker and Cloud
Hypervisor are unaffected. The VZ backend appends the argument as one of "its
backend's own parameters" (kiln spec §8.3).

Checked with `spike/vmkit-vz/resettest.sh`, on the test initramfs with
`vmkit.reset=poweroff`. The patched build's sha256 is `ca49e968…`.

| guest action | unpatched kernel, 10 s | patched kernel |
|---|---|---|
| `reboot -f` | 52 boots, VM never ends | 1 boot, `guestDidStop` at 276 ms |
| panic (`sysrq c`) | 66 boots | 1 boot, ends at 217 ms |
| PID 1 exits | 64 boots | 1 boot, ends at 227 ms |
| `poweroff -f` | 1 boot, ends | 1 boot, ends at 267 ms |

kiln-init needs no change. With the patched kernel, its pre-`Config` `reboot()`
(host closed the control connection) ends the VM after one boot. The helper sees
`guestDidStop` 100 ms after the host closes and exits 0. With `vmkit.reset=poweroff`
appended, `Capabilities::guest_exit` can be `Poweroff` or `Reboot`. `Poweroff` is
still the natural value, since that is what VZ itself honours.

## 6. vsock bridge (Firecracker's hybrid scheme)

The bridge works as vmkit's `VsockSpec` documents:

- **Guest-initiated** (all kiln traffic, ports 1024–1029): the helper registers a
  `VZVirtioSocketListener` for each listed port. On a connection it connects to
  `<uds>_<port>`. If nobody listens there, it refuses, and the guest gets
  `ECONNRESET`. Firecracker does the same.
- **Host-initiated:** the helper listens on `<uds>`, reads `CONNECT <port>\n`, calls
  `VZVirtioSocketDevice.connect(toPort:)`, and replies `OK <n>\n`. Then it relays
  bytes.
- Relay: two threads per connection with blocking `read`/`write`. EOF is passed on
  as `shutdown(SHUT_WR)`, so half-close works both ways.
  `VZVirtioSocketConnection.fileDescriptor` belongs to the connection object. The
  helper keeps the object alive until both directions end, then calls `close()`.

Differences from Firecracker that a real backend must handle:

- **No wildcard listener.** VZ listens per port only, so the guest-initiated ports
  must be known when the VM is created. kiln uses a fixed set (1024–1029).
  `VsockSpec` would need a `host_ports: Vec<u32>` or a range. Alternatively, the
  backend registers a default range such as 1024–2047; registering a port is only a
  dictionary entry.
- **No guest CID choice.** VZ assigns the CID; there is no setting for it. kiln's
  guest connects to CID 2 (the host) and never needs its own CID, so this does not
  matter today. The guest-side CID was not read.
- In `OK <n>`, `n` is the port VZ assigned to the connection's host side, not a host
  socket's port. Nothing in kiln reads it.
- **`sun_path` is 104 bytes on macOS**, against 108 on Linux. The first try put the
  sockets in a deep scratch directory and failed with `AF_UNIX path too long`. The
  backend must check `<run_dir>/sock_<port>` against 103 bytes, or keep a short run
  dir.

## 7. Snapshots (save and restore, macOS 14+)

`validateSaveRestoreSupport()` passes for this configuration: the Linux boot loader,
generic platform, virtio-blk, virtio console (file handle), vsock and entropy. The
save itself fails, though:

```
VZErrorDomain Code=11 "The virtual machine failed to save with error “permission denied”."
```

The failure is the same with the console or entropy device removed, with a persisted
`VZGenericMachineIdentifier`, with the save file under `/private/tmp` or the repo,
with hardened runtime on, and from both the agent shell and the user's own terminal.
A save file that already exists fails with `File exists`, so VZ creates the file
itself.

The unified log shows the cause in the VM's XPC process:

```
com.apple.Virtualization.VirtualMachine: [com.apple.security:seckey] SecKeyCreateRandomKey_ios failed:
  Error Domain=NSOSStatusErrorDomain Code=-25308 "Failed to generate keypair" (errKCInteractionNotAllowed ...)
```

VZ encrypts and signs save files with a key it generates in the data-protection
keychain. Most likely that needs a client with a Team ID, meaning a Developer ID or
development certificate; an ad-hoc signature has none. No signing identity is
installed on this machine, so this is **not verified**. Next step: sign `vmkit-vz`
with a development certificate and rerun `spike/vmkit-vz/snaptest.sh`. It saves on
`SIGUSR1`, then restores with `--restore` and checks that the guest keeps ticking.

Even when save works, the VZ model differs from vmkit's bundle model:

- The save file holds device and memory state only. Disks are not captured, so the
  backend copies the writable disks into the bundle itself, as Firecracker's driver
  does.
- The restoring configuration must match the saved one, including the machine
  identifier. vmkit's "same VMM, version and arch" rule maps onto this.
- The file is encrypted and tied to the user's keychain key. A bundle cannot move to
  another user or another Mac. `supports_diff_snapshot`, `lazy_memory` and drive
  remap are all `false`.
- vsock connections are not expected to survive a restore, so the host must
  reconnect. Not tested here.

## 8. Mapping onto `VmSpec` and `Capabilities`

| vmkit | VZ |
|---|---|
| `kernel` | `VZLinuxBootLoader(kernelURL:)`: an uncompressed `Image` |
| `initramfs` | `VZLinuxBootLoader.initialRamdiskURL` (checked with the vmkit test initramfs) |
| `cmdline` + console | `commandLine`. The driver appends `console=hvc0 vmkit.reset=poweroff` (§5). |
| `disks[i]` | `VZVirtioBlockDeviceConfiguration(VZDiskImageStorageDeviceAttachment(url:readOnly:))`, in order `vda`, `vdb`, … Raw images; the size must be a multiple of 512. |
| `vcpus`, `memory_mib` | `cpuCount`, `memorySize` (bytes) |
| `vsock` | `VZVirtioSocketDeviceConfiguration` + the helper's bridge (§6) |
| `net: None` | `networkDevices = []`: the guest has no NIC at all |
| `net: Some` / `tap` | see §9; `TapAttach` has no VZ equivalent |
| `console_log` | `VZVirtioConsoleDeviceSerialPortConfiguration` + `VZFileHandleSerialPortAttachment(fileHandleForWriting:)`. The caller opens the file, so a FIFO works as it does today. |
| `run_dir` | the helper's sockets and logs. There is no jailer or sandbox plan: isolation is Apple's VM XPC process (§10). |

`Capabilities` for VZ:

- `max_virtio_devices: 27`, measured. The VM starts with console + entropy + vsock +
  24 disks, or console + entropy + 25 disks. One more device fails at `start` with
  `"The virtual machine configuration parameters were invalid."`.
- `implicit_devices: 2`: the console and entropy devices the helper always adds. That
  leaves 25 for disks, vsock and a NIC. The entropy device is optional;
  `random: crng init done` came at 0.17 s with it.
- `guest_exit: Poweroff` (§5).
- `console: "hvc0"`.
- `supports_balloon`: VZ has `VZVirtioTraditionalMemoryBalloonDevice`. It is
  unexercised, so `false` for now.
- `supports_diff_snapshot: false`, `supports_drive_remap: false`, `lazy_memory: false`.

## 9. Egress, for later

Each option was checked against the API, not built:

- **Deny-all:** no network device. This is what the spike does, and the guest has no
  `eth0`. It matches `Egress::DenyAll` exactly and needs no host privileges.
- **NAT:** `VZNATNetworkDeviceAttachment`. It needs nothing special, and the guest
  gets DHCP from the host's vmnet (typically 192.168.64.0/24). It is all-or-nothing: no
  allowlist, no per-VM policy, and the guest can reach the host and the LAN. That is
  acceptable for `Egress::Open` in a local sandbox and wrong for anything else.
  Port publishing goes to the guest's vmnet address.
- **Allowlist (`Egress::Restricted`) and `Vm::set_egress`:**
  `VZFileHandleNetworkDeviceAttachment` hands the helper one end of a datagram
  socketpair that carries raw Ethernet frames. A userspace network stack in the
  helper, or in vmkit on the other end of the socketpair, terminates the guest's
  traffic:
  - DHCP, ARP and DNS are answered locally;
  - TCP and UDP flows are proxied out through host sockets only when the destination
    passes the allowlist;
  - everything else is dropped.

  This is how gvisor-tap-vsock (Podman, Lima's user-v2) and passt work, so it can
  enforce the same CIDR allowlist as `NetSpec::allow`, and `set_egress` becomes a
  rule swap with no VM change. Port forwards become host listeners that open flows
  into the stack. Cost: a frame-level TCP/IP stack to own or embed, and throughput
  well below a kernel tap. In Rust, `smoltcp` or a `passt`-style splice. The stack
  should run in a separate process from the VZ helper so a stack bug cannot reach the
  VM handle. Size the socketpair buffers for the attachment's MTU (1500 unless
  `maximumTransmissionUnit` raises it).

## 10. Isolation

The guest runs inside `com.apple.Virtualization.VirtualMachine`, an XPC service that
launchd starts per VM. It is sandboxed by Apple and owned by the user. vmkit's Linux
jailer (namespaces, seccomp, subordinate ids) has no macOS equivalent and is not
needed; the helper itself runs unprivileged.

The VM process dies with its client. After `kill -9` of the helper, its VM process
was gone within a second, so `Vm::kill` = SIGKILL the helper is enough.

## 11. Sketch: `Backend::AppleVz`

The helper becomes a long-lived child, controlled like Firecracker's API socket. vmkit
stays `forbid(unsafe_code)` and only does process and socket work:

```rust
// src/lib.rs
pub enum Backend {
    Firecracker,
    CloudHypervisor,
    #[cfg(target_os = "macos")]
    AppleVz,
}

// src/apple_vz.rs  (cfg(target_os = "macos"))
pub struct AppleVz {
    helper: PathBuf,        // vmkit-vz, found like the firecracker binary; checked for the entitlement
    version: String,        // `vmkit-vz --version`: the helper and macOS build (snapshot compatibility)
}

impl Vmm for AppleVz {
    fn name(&self) -> &'static str { "apple-vz" }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_virtio_devices: 27, implicit_devices: 2,
            supports_diff_snapshot: false, supports_balloon: false,
            supports_drive_remap: false, lazy_memory: false,
            guest_exit: GuestExit::Poweroff, console: "hvc0",
        }
    }
    fn create(&self, spec: &VmSpec) -> Result<Box<dyn Vm>> {
        spec.check(&self.capabilities())?;
        // + sun_path: run_dir/sock_<port> must fit 103 bytes; reject tap (no VZ equivalent).
        // 1. Write run_dir/vz.json: kernel, initramfs, cmdline + "console=hvc0", disks,
        //    vcpus, memory, vsock listen ports, net mode (none | nat | filehandle).
        // 2. Open console_log in this process (create, append) and pass the fd to the helper.
        // 3. Spawn `vmkit-vz --config run_dir/vz.json --api run_dir/api.sock --vsock run_dir/sock`.
        //    The helper validates the configuration, creates the VZVirtualMachine (not started),
        //    binds both sockets, then prints "ready". Wait for that line, or the helper's exit.
        Ok(Box::new(AppleVzVm { proc, api, vsock: spec.vsock.map(|_| spec.run_dir.join("sock")) }))
    }
    fn restore(&self, bundle: &SnapshotBundle, spec: &RestoreSpec) -> Result<Box<dyn Vm>> {
        // Copy the captured disks to scratch, then spawn the helper with --restore bundle/vz.state.
        // The helper restores paused; Vm::resume starts the guest. Blocked on §7 (Team ID signing).
        todo!()
    }
}

struct AppleVzVm { proc: Proc, api: PathBuf, vsock: Option<PathBuf> }

impl Vm for AppleVzVm {
    fn start(&mut self) -> Result<()>  { api_call(&self.api, "start") }   // JSON line in, JSON line out
    fn pause(&mut self) -> Result<()>  { api_call(&self.api, "pause") }
    fn resume(&mut self) -> Result<()> { api_call(&self.api, "resume") }
    fn kill(&mut self) -> Result<()>   { self.proc.kill() }               // SIGKILL; VZ tears down the VM process
    fn wait(&mut self) -> Result<VmEnd> { self.proc.wait() }              // the helper exits 0 on guestDidStop
    fn wait_timeout(&mut self, t: Duration) -> Result<Option<VmEnd>> { self.proc.wait_timeout(t) }
    fn snapshot(&mut self, dest: &Path) -> Result<SnapshotBundle> {
        // pause → `save dest/vz.state` → copy the writable disks → bundle.json (vmm "apple-vz", helper + OS build)
        todo!()
    }
    fn capabilities(&self) -> Capabilities { /* as above */ todo!() }
    fn vsock_socket(&self) -> Option<&Path> { self.vsock.as_deref() }
}
```

Helper contract (the part not in the spike yet):

- a JSON config file instead of flags;
- a JSON-lines API socket for `start`, `pause`, `resume`, `save <path>`, `stop`;
- `ready` on stdout once configured;
- exit codes: 0 on `guestDidStop`, 1 on `didStopWithError`, 2 on a configuration
  error. kiln-run's `wait` maps them to `EndReason::Exited`.

The helper is built and ad-hoc signed by a script (`swiftc` + `codesign`) and shipped next to
vmkit's binary. Discovery checks its entitlement with
`codesign -d --entitlements`, the same way `binary.rs` checks VMM versions today.

## 12. Open items

1. Release a base kernel that carries the reset patch, so kiln can pin it. The patch
   is merged, but the `kernels-6.18.54` release predates it. The patched build needs
   a new release tag.
2. Snapshots: confirm that a Team ID signature fixes `SecKeyCreateRandomKey`
   (`snaptest.sh`).
3. `VsockSpec` grows a host port list, and the backend checks `sun_path` length.
4. Egress: decide between NAT-only for local sandboxes and a file-handle NIC with a
   userspace stack for `Restricted`.
5. kiln-run is `cfg(target_os = "linux")` in its VM driver (`src/linux/run.rs`). It
   needs a macOS path that skips the sandbox and pidfd parts. That work is in kiln,
   outside this spike.
