#!/bin/sh
# Save after 1.5 s, then restore and check the guest keeps ticking.
cd "$(dirname "$0")/../.."
R=spike/vmkit-vz/out/run; mkdir -p $R; B=spike/vmkit-vz/out/vmkit-vz; P=$PWD/$R/state.vzvmsave; rm -f $P
export VZ_MACHINE_ID=$PWD/$R/machine-id; rm -f $VZ_MACHINE_ID
A="--kernel out/vmlinux-6.18.54-aarch64 --initrd out/initramfs-aarch64.cpio.gz --memory-mib 512"
$B $A --cmdline "console=hvc0 quiet vmkit.test=idle" --console-log $R/s1.log --save-on-usr1 $P 2> $R/se1.log & H=$!
sleep 1.5; kill -USR1 $H; wait $H; echo "save exit=$?"; cat $R/se1.log | tail -3; ls -l $P
$B $A --cmdline "console=hvc0 quiet vmkit.test=idle" --console-log $R/s2.log --restore $P 2> $R/se2.log & H=$!
sleep 1.5; kill $H; wait $H; cat $R/se2.log; echo "ticks before save: $(grep -c TICK $R/s1.log), after restore: $(grep -c TICK $R/s2.log)"
echo SNAPTEST-DONE
