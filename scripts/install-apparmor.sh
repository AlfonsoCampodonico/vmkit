#!/usr/bin/env bash
# Lets the vmkit-sandbox helper at PATH create user namespaces on hosts that restrict
# them through AppArmor (Ubuntu 23.10 and later: kernel.apparmor_restrict_unprivileged_userns=1).
# Elsewhere it does nothing. Needs sudo. PATH may be an AppArmor glob, for example
# '/home/*/target*/debug/vmkit-sandbox' for development builds; give a root-owned
# path in production, because any binary at PATH gets the permission.
set -euo pipefail
helper=${1:?usage: install-apparmor.sh <path to vmkit-sandbox>}
case $helper in
  /*) ;;
  *) echo "install-apparmor.sh: the path must be absolute" >&2; exit 1 ;;
esac
if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" != 1 ]; then
  echo "user namespaces are not restricted here; no profile needed"
  exit 0
fi
name=vmkit-sandbox-$(printf %s "$helper" | sha256sum | cut -c1-12)
profile=/etc/apparmor.d/$name
sudo tee "$profile" >/dev/null <<PROFILE
# vmkit-sandbox ($helper): may create the user namespace it runs a VMM in.
abi <abi/4.0>,
include <tunables/global>
profile $name "$helper" flags=(unconfined) {
  userns,
}
PROFILE
sudo apparmor_parser -r "$profile"
echo "loaded $profile"
