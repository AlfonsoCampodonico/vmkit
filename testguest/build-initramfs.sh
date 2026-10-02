#!/usr/bin/env bash
# Builds the contract-suite guest: a busybox initramfs for the host's arch.
# Needs a static busybox (`busybox-static` on Debian/Ubuntu).
# Usage: testguest/build-initramfs.sh <out.cpio.gz>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$(realpath -m "$1")
mkdir -p "$(dirname "$out")"
busybox=$(command -v busybox)
file -L "$busybox" | grep -q "statically linked" || { echo "busybox must be static" >&2; exit 1; }
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root"/{bin,proc,sys,dev}
cp "$busybox" "$root/bin/busybox"
cp "$here/init" "$root/init"
"${CC:-cc}" -static -O2 -o "$root/bin/vsock-hello" "$here/vsock-hello.c"
chmod 0755 "$root/init" "$root/bin/busybox" "$root/bin/vsock-hello"
# Fixed ownership and mtimes, sorted entries: the image is reproducible.
(cd "$root" && find . -print0 | LC_ALL=C sort -z | xargs -0 touch -h -d @0 \
  && find . -print0 | LC_ALL=C sort -z | cpio --null -o -H newc -R 0:0 --reproducible --quiet) | gzip -n -9 > "$out"
