#!/bin/sh
# Builds the Apple Virtualization helper (vz/main.swift) and signs it ad hoc with the
# com.apple.security.virtualization entitlement, which needs no developer identity.
#
#   scripts/build-vmkit-vz.sh [OUTDIR]     (default: target/vmkit-vz)
#
# Prints the helper's path. Point vmkit at it with VMKIT_VZ=<path>, or put it on PATH.
# Needs macOS on Apple Silicon and the Xcode command-line tools (swiftc, codesign).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$root/target/vmkit-vz"}
case $(uname -s) in Darwin) ;; *) echo "build-vmkit-vz.sh: macOS only" >&2; exit 1 ;; esac
mkdir -p "$out"
xcrun swiftc -O -swift-version 5 -o "$out/vmkit-vz.tmp" "$root/vz/main.swift"
codesign --force --sign - --entitlements "$root/vz/vmkit-vz.entitlements" "$out/vmkit-vz.tmp"
if ! codesign --display --entitlements - "$out/vmkit-vz.tmp" 2>/dev/null | grep -q com.apple.security.virtualization; then
  echo "build-vmkit-vz.sh: the signed helper lacks com.apple.security.virtualization" >&2
  exit 1
fi
mv -f "$out/vmkit-vz.tmp" "$out/vmkit-vz"
echo "$out/vmkit-vz"
