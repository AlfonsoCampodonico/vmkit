#!/bin/sh
# Checks that a guest reset ends the VM under vmkit-vz with vmkit.reset=poweroff.
# Usage: spike/vmkit-vz/resettest.sh <kernel> <vmkit test initramfs>
# Each case must end with the helper exiting 0 ("guest stopped the VM") after one boot.
set -u
cd "$(dirname "$0")/../.."
kernel=$1 initrd=$2
R=spike/vmkit-vz/out/run; mkdir -p $R; B=spike/vmkit-vz/out/vmkit-vz
fail=0
for t in "reboot" "panic" "exit" "up vmkit.exit=reboot" "up vmkit.exit=poweroff"; do
  rm -f $R/r.log
  $B --kernel "$kernel" --initrd "$initrd" --console-log $R/r.log \
    --cmdline "console=hvc0 quiet panic=-1 vmkit.reset=poweroff vmkit.test=$t" 2> $R/r.err &
  h=$!
  (sleep 10; kill $h 2>/dev/null) &
  w=$!
  wait $h; rc=$?
  kill $w 2>/dev/null
  boots=$(grep -c VMKIT-GUEST-UP $R/r.log)
  ended=$(grep -q "guest stopped the VM" $R/r.err && echo yes || echo no)
  printf '%-26s boots=%s guest-stopped=%s exit=%s %s\n' "$t" "$boots" "$ended" "$rc" \
    "$(sed -n 's/^\[ *\([0-9.]*\) ms\] guest stopped.*/(\1 ms)/p' $R/r.err)"
  [ "$boots" = 1 ] && [ "$ended" = yes ] && [ "$rc" = 0 ] || fail=1
done
exit $fail
