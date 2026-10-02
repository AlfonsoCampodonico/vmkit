#!/usr/bin/env bash
# Adds the network tests' fixture addresses to the host's loopback (needs sudo).
# They do not survive a reboot. Then: export VMKIT_TEST_NET=1
set -euo pipefail
for a in 169.254.169.254 10.250.0.1 198.51.100.7; do
  ip -4 addr show dev lo | grep -q "inet $a/" || sudo ip addr add "$a/32" dev lo
done
