#!/bin/sh
# Boot one RouterOS CHR lab VM (lab use only; see tests/lab/README.md).
#
#   boot.sh fetch                      download the CHR image into $LAB_DIR
#   boot.sh new <name>                 fresh disk <name>.img from the image
#   boot.sh run <name> <base> [l2]     boot it (foreground; background it yourself)
#
# <base> picks the forwards on 127.0.0.1: base+22 -> 22, base+222 -> 222,
# base+728 -> 8728, base+729 -> 8729. [l2] links ether2 to another lab VM:
# "socket,listen=127.0.0.1:21234" on one, "socket,connect=127.0.0.1:21234"
# on the other. arm64 CHR under TCG: HVF cannot boot RouterOS on Apple M5
# ("No working init found"), TCG boots in about a minute.
set -eu
LAB_DIR=${LAB_DIR:-$HOME/.cache/netops/lab}
VERSION=${LAB_ROUTEROS_VERSION:-7.24.5}
IMAGE="$LAB_DIR/chr-$VERSION-arm64.img"
FIRMWARE=${LAB_FIRMWARE:-$(brew --prefix 2>/dev/null || echo /usr)/share/qemu/edk2-aarch64-code.fd}

case "${1:-}" in
fetch)
    mkdir -p "$LAB_DIR"
    [ -f "$IMAGE" ] && exit 0
    curl -fsSL -o "$IMAGE.zip" "https://download.mikrotik.com/routeros/$VERSION/chr-$VERSION-arm64.img.zip"
    unzip -o -d "$LAB_DIR" "$IMAGE.zip" && rm -f "$IMAGE.zip"
    ;;
new)
    cp "$IMAGE" "$LAB_DIR/$2.img"
    ;;
run)
    disk="$LAB_DIR/$2.img"; b=$3; l2=${4:-}
    # distinct MACs per VM: QEMU's default is the same for every VM, which
    # makes RoMON and neighbor discovery see themselves
    m=$(printf '%02x' $((b / 10000)))
    extra=""
    [ -n "$l2" ] && extra="-netdev $l2,id=n1 -device virtio-net-pci,netdev=n1,mac=52:54:00:$m:00:02"
    # shellcheck disable=SC2086 # $extra is a word list on purpose
    exec qemu-system-aarch64 -M virt -accel tcg,thread=multi -cpu cortex-a72 -smp 2 -m 1024 \
        -bios "$FIRMWARE" \
        -drive file="$disk",if=none,id=d0,format=raw -device virtio-blk-pci,drive=d0 \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$((b + 22))-:22,hostfwd=tcp:127.0.0.1:$((b + 222))-:222,hostfwd=tcp:127.0.0.1:$((b + 728))-:8728,hostfwd=tcp:127.0.0.1:$((b + 729))-:8729" \
        -device virtio-net-pci,netdev=n0,mac=52:54:00:$m:00:01 $extra \
        -nographic -serial file:"$disk.serial.log" -monitor none -display none
    ;;
*)
    sed -n '2,13p' "$0"
    exit 2
    ;;
esac
