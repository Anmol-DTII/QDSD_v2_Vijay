#!/bin/sh
# Cross-compile the firmware against upstream Zephyr (compile check, not NCS).
#   ZP=/path/to/workspace tests/zephyr_ci/build.sh
# Without firmware update (no MCUboot, as prj_noupdate.conf):
#   NOUPDATE=1 BUILD=build/ci-noupdate tests/zephyr_ci/build.sh
set -e
ZP=${ZP:-/home/claude/zp}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
export ZEPHYR_BASE=$ZP/zephyr
export PYTHONPATH=$ZP/pyelftools:$ZP/anytree:$ZP/pystubs:$PYTHONPATH
MODS="$ZP/modules/hal/nordic;$ZP/modules/hal/cmsis;$ZP/modules/lib/cmsis_6;$ZP/modules/crypto/mbedtls;$ZP/modules/crypto/tinycrypt;$ZP/modules/crypto/nano-package;$ZP/modules/debug/segger;$ZP/bootloader/mcuboot"
cmake -GNinja -S "$ROOT" -B "${BUILD:-$ROOT/build/ci}" \
  -DBOARD=nrf52840dk/nrf52840 \
  -DZEPHYR_TOOLCHAIN_VARIANT=cross-compile \
  -DCROSS_COMPILE=$ZP/arm-zephyr-eabi/bin/arm-zephyr-eabi- \
  -DZEPHYR_MODULES="$MODS" \
  -DCONF_FILE="$ROOT/tests/zephyr_ci/ci.conf${NOUPDATE:+;$ROOT/tests/zephyr_ci/ci_noupdate.conf;$ROOT/prj_noupdate.conf}" \
  -DDTC_OVERLAY_FILE="$ROOT/app.overlay;$ROOT/tests/zephyr_ci/nrf52840dk_ci.overlay;$ROOT/docs/board/qdsd_qspi_flash.overlay"
ninja -C "${BUILD:-$ROOT/build/ci}"
