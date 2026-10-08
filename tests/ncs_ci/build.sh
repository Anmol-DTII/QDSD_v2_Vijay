#!/bin/sh
# Full NCS 3.0 sysbuild check (MCUboot + Partition Manager + signed app), the
# same build as `west build -b nrf52840dk/nrf52840 . --sysbuild`, for machines
# without west. Uses the nRF52840 DK with the CI board overlay in place of the
# QDSD board.
#   NCS=<workspace with nrf, zephyr, nrfxlib, modules/...> \
#   CROSS=<.../arm-zephyr-eabi/bin/arm-zephyr-eabi-> PNT=<nano-package dir> \
#   tests/ncs_ci/build.sh
# Needs keys/fw_signing_DEV_ONLY.pem (keys/README.md) and imgtool's Python
# dependencies (intelhex, click, cbor2).
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
B=${BUILD:-$ROOT/build/ncs}
export ZEPHYR_BASE=$NCS/zephyr ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=$CROSS
export ZEPHYR_MODULES="$NCS/nrf;$NCS/nrfxlib;$NCS/modules/crypto/mbedtls;$NCS/modules/crypto/oberon-psa-crypto;$NCS/modules/hal/nordic;$NCS/modules/hal/cmsis;$NCS/modules/debug/segger;$NCS/modules/crypto/tinycrypt;$NCS/modules/lib/zcbor;$NCS/bootloader/mcuboot;$PNT"
APP=$(mktemp -d)/qdsd
cp -r "$ROOT" "$APP" && rm -rf "$APP/build"
mkdir -p "$APP/boards" && cp "$ROOT/tests/zephyr_ci/nrf52840dk_ci.overlay" "$APP/boards/nrf52840dk_nrf52840.overlay"
cmake -GNinja -S "$NCS/zephyr/share/sysbuild" -B "$B" -DAPP_DIR="$APP" \
  -DBOARD=nrf52840dk/nrf52840 -Dqdsd_EXTRA_CONF_FILE=prj_lab.conf
ninja -C "$B"
ls -l "$B/merged.hex" "$B/qdsd/zephyr/zephyr.signed.bin"
