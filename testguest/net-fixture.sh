#!/usr/bin/env bash
# Adds the network tests' fixture addresses to the host's loopback (needs sudo).
# Without an IPv6 default route pasta has no template and the VM's namespace gets no IPv6
# egress, so a dummy interface (vmkt6) with a default route stands in, and `unreachable
# 2000::/3` makes the host's own traffic to the IPv6 internet fail at once instead of
# vanishing into the dummy. None of it survives a reboot. Then: export VMKIT_TEST_NET=1
set -euo pipefail
for a in 169.254.169.254 10.250.0.1 198.51.100.7; do
  ip -4 addr show dev lo | grep -F "inet $a/" >/dev/null || sudo ip addr add "$a/32" dev lo
done
for a in fd00:ec2::254 fd00:250::1 3ffe::7; do
  ip -6 addr show dev lo | grep -F "inet6 $a/" >/dev/null || sudo ip -6 addr add "$a/128" dev lo
done
if [ -z "$(ip -6 route show default)" ]; then
  ip link show vmkt6 >/dev/null 2>&1 || sudo ip link add vmkt6 type dummy
  sudo ip link set vmkt6 up
  sudo ip -6 addr replace 3ffe:0:0:1::1/64 dev vmkt6 nodad
  sudo ip -6 route replace default via 3ffe:0:0:1::fe dev vmkt6 metric 4096
  sudo ip -6 route replace unreachable 2000::/3 metric 4096
fi
