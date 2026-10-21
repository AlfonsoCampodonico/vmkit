#!/usr/bin/env bash
# The attached-tap tests' fixture (needs sudo): a network namespace `vmkit-attach` holding a
# tap `vmktap0` owned by the invoking user, at 10.251.0.1/24. It does not survive a reboot.
# Then run the tests inside it, as that user:
#   sudo ip netns exec vmkit-attach sudo -u "$USER" --preserve-env env VMKIT_TEST_ATTACH=1 \
#     PATH="$PATH" cargo test --test attach
set -euo pipefail
user=${SUDO_USER:-$USER}
uid=$(id -u "$user")
gid=$(id -g "$user")
ip netns list | grep -qw vmkit-attach || sudo ip netns add vmkit-attach
inside() { sudo ip netns exec vmkit-attach "$@"; }
inside ip link set lo up
inside ip link show vmktap0 >/dev/null 2>&1 || inside ip tuntap add vmktap0 mode tap user "$uid" group "$gid"
inside ip -4 addr show dev vmktap0 | grep -q 'inet 10.251.0.1/' || inside ip addr add 10.251.0.1/24 dev vmktap0
inside ip link set vmktap0 up
