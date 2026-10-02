#!/usr/bin/env bash
# Boots the test guest once on each VMM, without vmkit: checks a kernel and
# initramfs before the Rust drivers exist. Needs KVM and the VMMs on PATH.
# Usage: testguest/smoke.sh <kernel> <initramfs.cpio.gz>
set -euo pipefail
kernel=$1; initramfs=$2
case $(uname -m) in aarch64) ch_console=ttyAMA0 ;; *) ch_console=ttyS0 ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
args="panic=-1 rdinit=/init vmkit.test=up"
cat > "$work/fc.json" <<JSON
{"boot-source": {"kernel_image_path": "$kernel", "initrd_path": "$initramfs",
  "boot_args": "console=ttyS0 reboot=k $args vmkit.exit=reboot"},
 "drives": [], "machine-config": {"vcpu_count": 1, "mem_size_mib": 256}}
JSON
timeout 60 firecracker --no-api --config-file "$work/fc.json" > "$work/fc.log" 2>&1
grep -q VMKIT-GUEST-UP "$work/fc.log" && echo "firecracker: guest booted and exited"
timeout 60 cloud-hypervisor --kernel "$kernel" --initramfs "$initramfs" --cmdline "console=$ch_console $args vmkit.exit=poweroff" \
  --cpus boot=1 --memory size=256M --serial tty --console off > "$work/ch.log" 2>&1
grep -q VMKIT-GUEST-UP "$work/ch.log" && echo "cloud-hypervisor: guest booted and exited"
