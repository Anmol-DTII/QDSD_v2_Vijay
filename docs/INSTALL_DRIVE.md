# Install drive (firmware 0.7.0)

The token shows its external 8 MB QSPI flash to the PC as a **read-only USB
disk** carrying the Ascert.en installer, next to the CCID smart-card reader.
A new user plugs the token in, opens the drive and runs the installer; no
download is needed first.

Decisions (8 Oct 2026, project doc `qdsd-install-drive-design.md`):
- the drive stays visible after the middleware is installed;
- the Windows MSI must be under 7 MB; macOS and Linux packages are not on the
  drive (a README links to them);
- no content-signing key: the drive image is not signed, and the firmware does
  not check it at every boot. Protection comes from Authenticode on the MSI
  and from the drive being read-only;
- no field update of the drive: only the Factory Tool writes it, before
  FACTORY_CLOSE. The installer checks DTI Cloud for a newer middleware version
  when online.

## Hardware

Infineon **S25FL064LABMFM010**, 64 Mbit (8 MB) quad-SPI NOR, on the nRF52840
QSPI peripheral:

| Signal | Pin |
|---|---|
| SCK | P0.19 |
| CSN | P0.17 |
| IO0 | P0.22 |
| IO1 | P0.21 |
| IO2 / WP | P0.23 |
| IO3 / HOLD | P0.24 |

Devicetree for the QDSD board definition: `docs/board/qdsd_qspi_flash.overlay`
(node label `ext_flash`, JEDEC id `01 60 17`, quad read `EBh`, quad program
`32h`, 16 MHz). IO0 and IO3 are not on the nRF52840's recommended QSPI pins
(P0.20–P0.23), so the clock starts at 16 MHz, still several times what USB
full speed can carry. The whole chip is the drive; MCUboot's update slot stays
in internal flash.

## What the PC sees

A composite USB device:

| Interface | Class | Driver |
|---|---|---|
| 0 | `0B` smart card (CCID) | Windows usbccid.sys, macOS CryptoTokenKit, Linux pcsc-lite libccid |
| 1 | `08/06/50` mass storage, SCSI, Bulk-Only | the OS's own USB storage driver |

The disk: removable, 16,384 blocks of 512 bytes (8 MB), vendor `DTII`,
product `Ascert.en Setup`, FAT16 volume labelled `ASCERT-EN`, files marked
read-only. MODE SENSE reports write protection, so every OS mounts it
read-only; a WRITE that arrives anyway gets DATA PROTECT / WRITE PROTECTED
(`07/27/00`) and nothing is written. Each token has its own USB serial number
(from the nRF52840 device id), so Windows keeps two tokens' drives apart.

No image (new chip, failed upload): the drive shows as an empty removable
drive ("insert a disk"). The smart-card side is never affected; signing works
with or without the drive. Lab tokens closed under firmware 0.6.x and updated
to 0.7.0 stay that way, because FACTORY_DRIVE needs MANUFACTURING; rework
(FACTORY_WIPE, then the factory line again) gives them an image. Product
tokens are all made with 0.7.0 or later.

## Making the image

```
python3 tools/make_drive_image.py -o drive.img --date 2026-10-08 \
    AscertEN-Setup.msi README.txt
```

FAT16 without a partition table (the usual layout of USB sticks), files in
the root directory under their long names, marked read-only. The tool refuses
an MSI of 7 MB or more and prints the image size and SHA-256. Same input and
`--date` give the same image. The image is trimmed after the last file; the
rest of the chip is free space the PC never reads.

## Writing the image: FACTORY_DRIVE (PROTOCOL.md §4.3)

MANUFACTURING only; `6985` after FACTORY_CLOSE. `6D00` on a board or build
without the drive.

| APDU | Data | Does |
|---|---|---|
| `80 E6 00 00` BEGIN | `28` size (u32, multiple of 512), `29` SHA-256 | Starts an upload; the drive shows "no medium" meanwhile |
| `80 E6 01 00` WRITE | `2A` offset (u32, = bytes written so far), `25` chunk (≤ 2048) | Erases 64 KB blocks as needed and programs the chunk |
| `80 E6 02 00` FINISH | — | Reads the whole image back, checks the SHA-256, then writes the boot sector |

`tools/qdsd_proto.py factory_drive_apdus(image)` builds the sequence. Every
APDU must answer `9000`.

The SHA-256 is a transfer check, not a signature. The first 512 bytes (the
FAT boot sector) stay in token RAM until FINISH has checked the rest, so a
power cut, a card reset or a wrong hash leaves flash without a boot sector:
the PC sees "no medium", never a half-written disk. A good upload can simply
be repeated.

Timing: about 3,500 APDUs for 7 MB, plus erasing and programming the flash
(typically 20–40 s in total). Run it while other tests run on the station.

## Code

| File | Job |
|---|---|
| `src/usb/msc.c` | Bulk-Only Transport and the SCSI commands, read-only (shared with the host tests) |
| `src/usb/token_msc.c` | Zephyr glue: descriptors, endpoints, own work queue |
| `src/token/token_drive.c` | FACTORY_DRIVE, boot check |
| `src/port/port_drive.c` | QSPI flash (`ext_flash`); `port_drive_none.c` without it |
| `tools/make_drive_image.py` | FAT16 image builder |
| `tests/host/test_drive.py` | 19 tests: image checked by `fsck.fat`, upload, refusals, power cuts, the USB disk protocol, files read back through the disk |

`CONFIG_QDSD_INSTALL_DRIVE` is on whenever the board's devicetree has
`ext_flash`, off otherwise.

## Bring-up checks

- [ ] Boot log: QSPI flash ready (JEDEC id `01 60 17`). If the quad-enable
      setting (`S2B1v1`) does not match the chip's SFDP table, reads in quad
      mode fail: compare with `flash sfdp` in the Zephyr shell, or fall back
      to `readoc = "fastread"` to confirm wiring.
- [ ] FACTORY_DRIVE with a 7 MB image: time it; FINISH answers `9000`.
- [ ] Windows 10 and 11: drive letter appears, label ASCERT-EN, files open,
      delete or copy-to refused ("write protected"); the CCID reader still
      works at the same time (sign while copying the MSI off the drive).
- [ ] macOS and Linux: mounts read-only; `dmesg` on Linux shows
      "Write Protect is on".
- [ ] Two tokens at once: two separate drives.
- [ ] Raise the QSPI clock above 16 MHz only after checking signals on IO0
      and IO3 with a scope.
