# Kernel patches

`build.sh` applies every `*.patch` here, in name order, with `patch -p1` on the
checked source tree before configuring it. Each patch is opt-in: without its kernel
argument, the kernel behaves as upstream does.

| Patch | Kernel argument | Why |
|---|---|---|
| `0001-reset-poweroff.patch` | `vmkit.reset=poweroff` | Turns every restart into a power-off: `reboot(2)`, a panic with `panic=-1`, and `emergency_restart()`. Apple's Virtualization.framework reboots a guest in place and tells the host nothing, so on that backend a guest reset could not end the VM otherwise. |
