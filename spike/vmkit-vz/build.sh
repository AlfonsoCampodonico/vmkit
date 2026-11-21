#!/bin/sh
# Builds and ad-hoc signs the vmkit-vz spike helper into spike/vmkit-vz/out/.
set -eu
cd "$(dirname "$0")"
mkdir -p out
swiftc -O -o out/vmkit-vz main.swift
codesign --force --sign - --entitlements vmkit-vz.entitlements out/vmkit-vz
codesign --display --entitlements - out/vmkit-vz
