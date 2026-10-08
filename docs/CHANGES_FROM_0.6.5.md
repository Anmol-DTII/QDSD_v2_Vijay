# Firmware 0.7.0 — changes from 0.6.5 (the developer's working copy)

New feature: the **install drive**. On boards with the 8 MB QSPI flash
(S25FL064L) the token is a composite USB device: the CCID reader as before,
plus a read-only USB disk with the Ascert.en installer. Full description:
`docs/INSTALL_DRIVE.md`. No change for middleware (GET_INFO minor stays 3).

## To build it for the QDSD board
Add `docs/board/qdsd_qspi_flash.overlay` to the QDSD board definition (or
pass it as an extra DTC overlay). The feature switches on by itself when the
devicetree has the `ext_flash` node and stays off otherwise; the build
command is unchanged (`west build -p ... --sysbuild ...`).

## New files
| File | Job |
|---|---|
| `src/usb/msc.c`, `include/usb/msc.h` | Read-only USB mass storage (Bulk-Only Transport + SCSI), host-tested |
| `src/usb/token_msc.c`, `include/usb/token_msc.h` | Zephyr glue: interface 1, endpoints, own work queue |
| `src/token/token_drive.c` | FACTORY_DRIVE (`80 E6`, MANUFACTURING only), boot check |
| `src/port/port_drive.c`, `src/port/port_drive_none.c` | QSPI flash access / no drive |
| `tools/make_drive_image.py` | Builds the FAT16 drive image from the MSI and README |
| `docs/INSTALL_DRIVE.md`, `docs/board/qdsd_qspi_flash.overlay` | Description, bring-up checks, devicetree |
| `tests/host/test_drive.py` | 19 tests |

## Changed files
`CMakeLists.txt`, `Kconfig` (`CONFIG_QDSD_INSTALL_DRIVE`), `src/main.c`
(drive init, never a fault), `src/token/token_engine.c` (dispatch, boot
check, card reset aborts an upload), `include/token/*.h`, `include/port/port.h`
(drive functions, SHA-256 in pieces), `src/port/port_crypto.c` (PSA
multi-part hash), `include/qdsd/qdsd_config.h` (0.7.0), `tools/qdsd_proto.py`
(`factory_drive_apdus`), docs, tests, CI scripts.

## Checked here
- NCS 3.0.0 full `--sysbuild` with the drive (nRF52840 DK + QDSD pin
  overlay): MCUboot + signed 0.7.0 image; 214.6 KB flash, 94 KB RAM.
- NCS 3.0.0 without the flash chip / without update; upstream Zephyr 4.1
  with and without update.
- 179 host tests; 12 of 12 planted bugs in the new code caught.
- The drive image checked with dosfstools `fsck.fat`.
Not checked: the real QDSD board and PCs (see docs/INSTALL_DRIVE.md,
Bring-up checks).
