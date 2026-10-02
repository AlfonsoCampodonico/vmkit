#!/usr/bin/env bash
# Installs the pinned Firecracker and Cloud Hypervisor releases for this machine's
# arch into DIR (default ~/.local/bin), verifying each download's SHA-256.
# These are the versions vmkit's MIN_VERSION constants and contract suite are tested with.
set -euo pipefail
dir=${1:-$HOME/.local/bin}
arch=$(uname -m)
fc_version=1.17.0
ch_version=53.0
case $arch in
  aarch64)
    fc_sha=e351ebe4f7a16b5873bbd51005d2e6767103cff4d5ebc829df2d3f95a93e2256
    ch_asset=cloud-hypervisor-static-aarch64
    ch_sha=f192b510eea1c710cbc439d716bb0573c223fc463dbe3e6523788a2b7ef62850 ;;
  x86_64)
    fc_sha=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
    ch_asset=cloud-hypervisor-static
    ch_sha=448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc ;;
  *) echo "unsupported arch $arch" >&2; exit 1 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() { # url sha out
  curl -sfL --retry 3 --retry-delay 2 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet -
}
fetch "https://github.com/firecracker-microvm/firecracker/releases/download/v$fc_version/firecracker-v$fc_version-$arch.tgz" "$fc_sha" "$work/fc.tgz"
tar -xzf "$work/fc.tgz" -C "$work"
fetch "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v$ch_version/$ch_asset" "$ch_sha" "$work/cloud-hypervisor"
mkdir -p "$dir"
install -m 0755 "$work/release-v$fc_version-$arch/firecracker-v$fc_version-$arch" "$dir/firecracker"
install -m 0755 "$work/cloud-hypervisor" "$dir/cloud-hypervisor"
"$dir/firecracker" --version | head -1
"$dir/cloud-hypervisor" --version | head -1
