#!/usr/bin/env python3
"""Build the QDSD install-drive image (docs/INSTALL_DRIVE.md).

The token shows its 8 MB QSPI flash to the PC as a read-only USB disk. This
tool makes that disk: a FAT16 volume without a partition table (the usual
"superfloppy" layout of USB sticks and smart-card tokens), with the given
files in the root directory, marked read-only, under long file names.

    python3 tools/make_drive_image.py -o drive.img \\
        AscertEN-Setup.msi README.txt

Prints the image size and SHA-256; FACTORY_DRIVE (PROTOCOL.md §4.3) writes
it with tools/qdsd_proto.py factory_drive_apdus(). The image is trimmed after
the last file: the rest of the chip is free space the PC never reads.

Pure Python 3, no dependencies, same output for the same input and --date.
"""
import argparse
import datetime
import hashlib
import os
import struct
import sys

SECTOR = 512
DRIVE_BYTES = 8 * 1024 * 1024          # S25FL064L
TOTAL_SECTORS = DRIVE_BYTES // SECTOR  # 16384
SPC = 1                                # sectors per cluster (FAT16 needs >= 4085 clusters)
RESERVED = 1
NUM_FATS = 2
ROOT_ENTRIES = 512
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR
MSI_LIMIT = 7 * 1000 * 1000            # agreed: MSI under 7 MB

ATTR_RO, ATTR_HIDDEN, ATTR_SYS, ATTR_VOL, ATTR_DIR, ATTR_ARCH = 1, 2, 4, 8, 16, 32
ATTR_LFN = ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOL


def fat_sectors():
    # Smallest FAT that covers every cluster of the volume.
    fs = 1
    while True:
        data = TOTAL_SECTORS - RESERVED - NUM_FATS * fs - ROOT_SECTORS
        clusters = data // SPC
        if (clusters + 2) * 2 <= fs * SECTOR:
            return fs, clusters
        fs += 1


FAT_SECTORS, CLUSTERS = fat_sectors()
FIRST_DATA = RESERVED + NUM_FATS * FAT_SECTORS + ROOT_SECTORS
assert 4085 <= CLUSTERS < 65525, "must be FAT16"

SHORT_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%'-_@~`!(){}^#&")


def dos_datetime(dt):
    d = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return t, d


def short_name(name, taken):
    """8.3 name; (name11, needs_lfn)."""
    base, dot, ext = name.rpartition(".")
    if not dot:
        base, ext = name, ""
    exact = (base.upper() == base and ext.upper() == ext and 1 <= len(base) <= 8 and
             len(ext) <= 3 and all(c in SHORT_OK for c in base + ext))
    if exact:
        n11 = base.ljust(8) + ext.ljust(3)
        if n11 not in taken:
            return n11, False

    def clean(s):
        return "".join(c for c in s.upper() if c in SHORT_OK)

    b, e = clean(base) or "FILE", clean(ext)[:3]
    for i in range(1, 1000):
        tail = "~%d" % i
        n11 = (b[:8 - len(tail)] + tail).ljust(8) + e.ljust(3)
        if n11 not in taken:
            return n11, True
    raise ValueError("too many similar names: " + name)


def lfn_checksum(n11):
    s = 0
    for c in n11.encode("ascii"):
        s = (((s & 1) << 7) + (s >> 1) + c) & 0xFF
    return s


def lfn_entries(name, n11):
    u = name.encode("utf-16-le")
    chars = [u[i:i + 2] for i in range(0, len(u), 2)] + [b"\x00\x00"]
    while len(chars) % 13:
        chars.append(b"\xff\xff")
    parts = [chars[i:i + 13] for i in range(0, len(chars), 13)]
    if len(parts) > 20:
        raise ValueError("file name too long: " + name)
    cks = lfn_checksum(n11)
    out = []
    for i in reversed(range(len(parts))):
        p = parts[i]
        seq = (i + 1) | (0x40 if i == len(parts) - 1 else 0)
        out.append(bytes([seq]) + b"".join(p[0:5]) + bytes([ATTR_LFN, 0, cks]) +
                   b"".join(p[5:11]) + b"\x00\x00" + b"".join(p[11:13]))
    return out


def dir_entry(n11, attr, cluster, size, t, d):
    return (n11.encode("ascii") + bytes([attr, 0, 0]) +
            struct.pack("<HHHHHHHI", t, d, d, 0, t, d, cluster, size))


def build(files, label="ASCERT-EN", when=None, serial=None):
    """files: list of (name, bytes). Returns the trimmed image bytes."""
    when = when or datetime.datetime(2026, 1, 1)
    t, d = dos_datetime(when)
    label11 = label.upper()[:11].ljust(11)
    serial = serial if serial is not None else int.from_bytes(
        hashlib.sha256(b"".join(n.encode() + c for n, c in files)).digest()[:4], "little")

    # Boot sector (BPB for a FAT16 superfloppy).
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xEB\x3C\x90"
    bs[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, SPC, RESERVED, NUM_FATS, ROOT_ENTRIES,
                     TOTAL_SECTORS, 0xF8, FAT_SECTORS, 32, 2, 0, 0)
    struct.pack_into("<BBBI", bs, 36, 0x80, 0, 0x29, serial)
    bs[43:54] = label11.encode("ascii")
    bs[54:62] = b"FAT16   "
    # Not bootable: "jmp $" after the BPB, message for anyone who tries.
    bs[62:64] = b"\xEB\xFE"
    msg = b"Ascert.en install drive - not a boot disk."
    bs[64:64 + len(msg)] = msg
    bs[510:512] = b"\x55\xAA"

    fat = bytearray(FAT_SECTORS * SECTOR)
    struct.pack_into("<HH", fat, 0, 0xFFF8, 0xFFFF)
    root = [dir_entry(label11, ATTR_VOL, 0, 0, t, d)]
    data = bytearray()
    taken = set()
    cluster = 2
    for name, content in files:
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            raise ValueError("bad file name: %r" % name)
        n11, need_lfn = short_name(name, taken)
        taken.add(n11)
        nclus = (len(content) + SPC * SECTOR - 1) // (SPC * SECTOR)
        if cluster - 2 + nclus > CLUSTERS:
            raise ValueError("files do not fit on the %d-byte drive" % DRIVE_BYTES)
        first = cluster if nclus else 0
        for i in range(nclus):
            nxt = 0xFFFF if i == nclus - 1 else cluster + i + 1
            struct.pack_into("<H", fat, (cluster + i) * 2, nxt)
        if need_lfn or name != name.upper():
            root += lfn_entries(name, n11)
        root.append(dir_entry(n11, ATTR_RO | ATTR_ARCH, first, len(content), t, d))
        data += content + b"\x00" * (nclus * SPC * SECTOR - len(content))
        cluster += nclus
    if len(root) > ROOT_ENTRIES:
        raise ValueError("too many files / names for the root directory")
    rootb = b"".join(root).ljust(ROOT_SECTORS * SECTOR, b"\x00")

    img = bytes(bs) + bytes(fat) * NUM_FATS + rootb + bytes(data)
    assert len(img) == FIRST_DATA * SECTOR + len(data)
    return img


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-o", "--out", required=True, help="image file to write")
    ap.add_argument("--label", default="ASCERT-EN", help="volume label (11 chars max)")
    ap.add_argument("--date", help="file date YYYY-MM-DD (default: today)")
    ap.add_argument("files", nargs="+", help="files for the root directory")
    a = ap.parse_args(argv)
    when = (datetime.datetime.strptime(a.date, "%Y-%m-%d") if a.date
            else datetime.datetime.now().replace(microsecond=0))
    files = []
    for path in a.files:
        with open(path, "rb") as f:
            content = f.read()
        name = os.path.basename(path)
        if name.lower().endswith(".msi") and len(content) >= MSI_LIMIT:
            sys.exit("%s is %d bytes; the agreed limit is under 7 MB" % (name, len(content)))
        files.append((name, content))
    img = build(files, a.label, when)
    with open(a.out, "wb") as f:
        f.write(img)
    print("image   %s" % a.out)
    print("size    %d bytes (%.2f MB of %d MB)" % (len(img), len(img) / 1e6, DRIVE_BYTES >> 20))
    print("sha256  %s" % hashlib.sha256(img).hexdigest())


if __name__ == "__main__":
    main()
