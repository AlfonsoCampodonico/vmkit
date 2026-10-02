#!/usr/bin/env bash
# Builds the vmkit kernel for one arch: Firecracker's CI guest config for the series
# plus vmkit's fragments (kiln spec §8.2). The source tarball is checked against SHA256SUMS.
# Usage: kernels/build.sh <aarch64|x86_64> <out-dir>
set -euo pipefail
arch=$1; out=$(realpath -m "$2")
here=$(cd "$(dirname "$0")" && pwd)
version=$(cat "$here/VERSION")
series=$(echo "$version" | cut -d. -f1-2)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -sfL -o "$work/linux-$version.tar.xz" "https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x/linux-$version.tar.xz"
(cd "$work" && grep " linux-$version.tar.xz\$" "$here/SHA256SUMS" | sha256sum -c --quiet -)
(cd "$here" && grep " microvm-kernel-ci-$arch-$series.config\$" SHA256SUMS | sha256sum -c --quiet -)
tar -xJf "$work/linux-$version.tar.xz" -C "$work"
src="$work/linux-$version"
case $arch in
  aarch64) karch=arm64; image=arch/arm64/boot/Image; cross=aarch64-linux-gnu- ;;
  x86_64) karch=x86; image=vmlinux; cross=x86_64-linux-gnu- ;;
esac
[ "$(uname -m)" = "$arch" ] && cross=
# Fixed build metadata, so the same tree and toolchain give the same binary.
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC" KBUILD_BUILD_USER=vmkit KBUILD_BUILD_HOST=vmkit
cp "$here/microvm-kernel-ci-$arch-$series.config" "$src/.config"
(cd "$src" && ARCH=$karch scripts/kconfig/merge_config.sh -m .config "$here/fragments/base.config" "$here/fragments/base-$arch.config" >/dev/null \
  && make -s ARCH=$karch CROSS_COMPILE=$cross olddefconfig \
  && make -s ARCH=$karch CROSS_COMPILE=$cross -j"$(nproc)" "$(basename $image)")
mkdir -p "$out"
cp "$src/$image" "$out/vmlinux-$version-$arch"
cp "$src/.config" "$out/config-$version-$arch"
# Every fragment line must have survived olddefconfig.
missing=0
for f in "$here/fragments/base.config" "$here/fragments/base-$arch.config"; do
  while IFS= read -r line; do
    case $line in CONFIG_*=*) grep -qx "$line" "$src/.config" || { echo "missing: $line"; missing=1; } ;; esac
  done < "$f"
done
exit $missing
