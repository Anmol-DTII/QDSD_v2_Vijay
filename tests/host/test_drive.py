"""Install drive (firmware 0.7.0): FACTORY_DRIVE and the read-only USB disk.

The token's 8 MB QSPI flash is shown to the PC as a write-protected USB disk
carrying the Ascert.en installer (docs/INSTALL_DRIVE.md). These tests drive
src/token/token_drive.c through APDUs and src/usb/msc.c through Bulk-Only
packets, as src/usb/token_msc.c moves them, over a NOR flash model where
programming can only clear bits.
"""
import ctypes
import datetime
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

import qdsd_proto as q
from test_flows import LIB, World

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import make_drive_image as mdi  # noqa: E402

LIB.sim_drive_none.argtypes = [ctypes.c_int]
LIB.sim_drive_mem.restype = ctypes.POINTER(ctypes.c_uint8)
LIB.sim_msc_blocks.restype = ctypes.c_uint32
LIB.sim_msc.restype = ctypes.c_size_t
LIB.sim_msc.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                        ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int)]

DRIVE = 8 * 1024 * 1024
BLOCKS = DRIVE // 512
FSCK = os.environ.get("FSCK_FAT") or shutil.which("fsck.fat") or \
    "/home/claude/pydeps/dosfstools/src/fsck.fat"

# SCSI
TUR, SENSE, INQ, MSENSE6, MSENSE10 = 0x00, 0x03, 0x12, 0x1A, 0x5A
RFC, RCAP, READ6, READ10, READ12 = 0x23, 0x25, 0x08, 0x28, 0xA8
WRITE10, VERIFY10, PREVENT, START_STOP, SYNC = 0x2A, 0x2F, 0x1E, 0x1B, 0x35


def drive_bytes(off, n):
    p = LIB.sim_drive_mem()
    return bytes(p[off:off + n])


class Usb:
    """The PC's side of the Bulk-Only pipe."""

    def __init__(self):
        self.tag = 0

    def cbw(self, cdb, length=0, din=True, lun=0, tag=None):
        self.tag = (self.tag + 1) & 0xFFFFFFFF
        return (b"USBC" + struct.pack("<IIBBB", self.tag if tag is None else tag, length,
                                      0x80 if din else 0x00, lun, len(cdb)) +
                bytes(cdb).ljust(16, b"\x00"))

    def cmd(self, cdb, length=0, din=True, dout=b"", lun=0, raw=None):
        c = raw if raw is not None else self.cbw(cdb, length, din, lun)
        out = ctypes.create_string_buffer(BLOCKS * 0 + 1 << 20)
        st = ctypes.c_int(0)
        n = LIB.sim_msc(c, len(c), dout, len(dout), out, len(out), ctypes.byref(st))
        if st.value:
            return None
        got = out.raw[:n]
        data, csw = got[:-13], got[-13:]
        sig, tag, residue, status = struct.unpack("<IIIB", csw)
        assert sig == 0x53425355, "CSW signature"
        if raw is None:
            assert tag == self.tag, "CSW echoes the tag"
        return data, residue, status

    def sense(self):
        d, _, s = self.cmd([SENSE, 0, 0, 0, 18, 0], 18)
        assert s == 0
        return d[2] & 0x0F, d[12], d[13]

    def read10(self, lba, count, length=None):
        return self.cmd([READ10, 0] + list(struct.pack(">I", lba)) + [0] +
                        list(struct.pack(">H", count)) + [0],
                        count * 512 if length is None else length)

    def sector(self, lba, count=1):
        d, res, s = self.read10(lba, count)
        assert s == 0 and res == 0, (s, res)
        return d


def read_files(usb):
    """Read the root directory and files through the USB disk, as an OS would."""
    bs = usb.sector(0)
    assert bs[510:512] == b"\x55\xAA"
    bps, spc, rsv, nf, roots, tot, _, fsz = struct.unpack_from("<HBHBHHBH", bs, 11)
    assert bps == 512 and tot == BLOCKS
    fat = usb.sector(rsv, fsz)
    root_lba = rsv + nf * fsz
    root = usb.sector(root_lba, roots * 32 // 512)
    data_lba = root_lba + roots * 32 // 512
    files, lfn = {}, []
    for i in range(0, len(root), 32):
        e = root[i:i + 32]
        if e[0] == 0:
            break
        attr = e[11]
        if attr == 0x0F:
            part = e[1:11] + e[14:26] + e[28:32]
            lfn.insert(0, part)
            continue
        if attr & 0x08:
            lfn = []
            continue
        name = (b"".join(lfn).decode("utf-16-le").split("\x00")[0] if lfn else
                e[0:8].decode().rstrip() + ("." + e[8:11].decode().rstrip()
                                            if e[8:11].strip() else ""))
        lfn = []
        clus, size = struct.unpack_from("<HI", e, 26)
        assert attr & 0x01, "files are read-only"
        content = b""
        while clus and clus < 0xFFF8:
            content += usb.sector(data_lba + (clus - 2) * spc, spc)
            clus = struct.unpack_from("<H", fat, clus * 2)[0]
        files[name] = content[:size]
    return files


def sample_files(msi_size=200_000):
    msi = bytes((i * 131 + (i >> 9)) & 0xFF for i in range(msi_size))
    readme = b"Ascert.en for macOS and Linux: https://example.invalid/download\r\n"
    return [("AscertEN-Setup.msi", msi), ("README.txt", readme)]


def upload(w, image, chunk=2048):
    sws = [w.tok.sw(a) for a in q.factory_drive_apdus(image, chunk)]
    return sws


class TestImageTool(unittest.TestCase):
    def test_fat16_layout_checked_by_fsck(self):
        img = mdi.build(sample_files(), when=datetime.datetime(2026, 10, 8))
        self.assertEqual(len(img) % 512, 0)
        if not os.path.exists(FSCK):
            self.skipTest("fsck.fat not available")
        for fill in (b"\x00", b"\xff"):   # zero-filled file / erased flash beyond the image
            with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as f:
                f.write(img + fill * (DRIVE - len(img)))
            try:
                r = subprocess.run([FSCK, "-n", "-v", "-l", f.name], capture_output=True,
                                   text=True)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("/AscertEN-Setup.msi", r.stdout)
                self.assertIn("/README.txt", r.stdout)
                self.assertIn("16384 sectors total", r.stdout)
            finally:
                os.unlink(f.name)

    def test_deterministic_and_limits(self):
        when = datetime.datetime(2026, 10, 8)
        self.assertEqual(mdi.build(sample_files(), when=when),
                         mdi.build(sample_files(), when=when))
        with self.assertRaises(ValueError):
            mdi.build([("big.bin", b"\x00" * DRIVE)])
        with self.assertRaises(ValueError):
            mdi.build([("a/b.txt", b"x")])
        with tempfile.TemporaryDirectory() as d:
            msi = os.path.join(d, "Big.msi")
            with open(msi, "wb") as f:
                f.write(b"\x00" * 7_000_000)
            with self.assertRaises(SystemExit):
                mdi.main(["-o", os.path.join(d, "x.img"), msi])

    def test_short_names(self):
        img = mdi.build([("SETUP.MSI", b"1"), ("Setup.msi", b"2"), ("long name.txt", b"3")])
        root = img[(1 + 2 * mdi.FAT_SECTORS) * 512:][:32 * 16]
        names = [root[i:i + 11] for i in range(0, len(root), 32) if root[i + 11] not in (0x0F, 0x08)
                 and root[i] != 0]
        self.assertEqual(names, [b"SETUP   MSI", b"SETUP~1 MSI", b"LONGNA~1TXT"])


class TestFactoryDrive(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.usb = Usb()
        self.files = sample_files()
        self.img = mdi.build(self.files, when=datetime.datetime(2026, 10, 8))

    def test_new_token_has_no_medium(self):
        self.assertEqual(LIB.sim_msc_present(), 0)
        _, _, s = self.usb.cmd([TUR, 0, 0, 0, 0, 0])
        self.assertEqual(s, 1)
        self.assertEqual(self.usb.sense(), (0x02, 0x3A, 0x00), "medium not present")

    def test_upload_and_read_back_through_usb(self):
        self.assertTrue(all(sw == q.SW_OK for sw in upload(self.w, self.img)))
        self.assertEqual(LIB.sim_msc_present(), 1)
        self.assertEqual(LIB.sim_msc_blocks(), BLOCKS)
        _, _, s = self.usb.cmd([TUR, 0, 0, 0, 0, 0])
        self.assertEqual((s, self.usb.sense()), (1, (0x06, 0x28, 0x00)),
                         "the PC is told once that the medium changed")
        self.assertEqual(self.usb.cmd([TUR, 0, 0, 0, 0, 0])[2], 0)
        d, _, s = self.usb.cmd([RCAP] + [0] * 9, 8)
        self.assertEqual(struct.unpack(">II", d), (BLOCKS - 1, 512))
        self.assertEqual(read_files(self.usb), dict(self.files))
        self.assertEqual(drive_bytes(0, len(self.img)), self.img)

    def test_drive_survives_reboot_and_close_locks_it(self):
        upload(self.w, self.img)
        self.w.factory()                         # FACTORY_CLOSE
        self.w.tok.boot()
        self.assertEqual(LIB.sim_msc_present(), 1, "boot check finds the image")
        self.w.tok.select()
        for a in q.factory_drive_apdus(self.img)[:2]:
            self.assertEqual(self.w.tok.sw(a), 0x6985, "nothing writes the drive after close")
        self.assertEqual(read_files(self.usb), dict(self.files))

    def test_refusals(self):
        t = self.w.tok
        begin = q.factory_drive_apdus(self.img)[0]
        bad = lambda size: q.apdu("FACTORY_DRIVE", q.tlv(q.T["IMAGE_SIZE"], struct.pack(">I", size)) +
                                  q.tlv(q.T["IMAGE_SHA256"], bytes(32)))  # noqa: E731
        self.assertEqual(t.sw(q.apdu("FACTORY_DRIVE", p1=1, data=q.tlv(q.T["CHUNK"], b"x"))), 0x6985,
                         "WRITE without BEGIN")
        self.assertEqual(t.sw(q.apdu("FACTORY_DRIVE", p1=2)), 0x6985, "FINISH without BEGIN")
        self.assertEqual(t.sw(q.apdu("FACTORY_DRIVE", p1=3)), 0x6A86)
        self.assertEqual(t.sw(q.apdu("FACTORY_DRIVE", p2=1)), 0x6A86)
        for size in (0, 100, 513, DRIVE + 512):
            self.assertEqual(t.sw(bad(size)), 0x6A80, size)
        self.assertEqual(t.sw(begin), q.SW_OK)
        wr = lambda off, data: q.apdu("FACTORY_DRIVE", p1=1, data=q.tlv(  # noqa: E731
            q.T["IMAGE_OFFSET"], struct.pack(">I", off)) + q.tlv(q.T["CHUNK"], data))
        self.assertEqual(t.sw(wr(512, b"x" * 512)), 0x6A80, "out of order")
        self.assertEqual(t.sw(wr(0, b"x" * 2049)), 0x6A80, "chunk too big")
        self.assertEqual(t.sw(q.apdu("FACTORY_DRIVE", p1=2)), 0x6985, "incomplete")
        small = bad(1024)
        self.assertEqual(t.sw(small), q.SW_OK)
        self.assertEqual(t.sw(wr(0, b"x" * 1536)), 0x6A80, "past the announced size")

    def test_hash_mismatch_shows_nothing(self):
        apdus = q.factory_drive_apdus(self.img)
        good = q.factory_drive_apdus(self.img)
        self.assertTrue(all(self.w.tok.sw(a) == q.SW_OK for a in good))
        self.assertEqual(LIB.sim_msc_present(), 1)
        # Second upload, one byte different from what the hash announces.
        other = bytearray(self.img)
        other[len(other) // 2] ^= 0x01
        lying = q.factory_drive_apdus(bytes(other))
        lying[0] = apdus[0]                      # BEGIN with the hash of the original
        sws = [self.w.tok.sw(a) for a in lying]
        self.assertTrue(all(sw == q.SW_OK for sw in sws[:-1]))
        self.assertEqual(sws[-1], 0x6A80)
        self.assertEqual(LIB.sim_msc_present(), 0)
        self.assertNotEqual(drive_bytes(510, 2), b"\x55\xAA", "no boot sector left")
        self.w.tok.boot()
        self.assertEqual(LIB.sim_msc_present(), 0, "and none after a reboot either")

    def test_reupload_replaces_image(self):
        upload(self.w, self.img)
        files2 = [("AscertEN-Setup.msi", b"v2" * 70_000), ("NEW.TXT", b"new")]
        img2 = mdi.build(files2, when=datetime.datetime(2026, 11, 1))
        self.assertTrue(all(sw == q.SW_OK for sw in upload(self.w, img2)),
                        "NOR flash is erased before it is programmed again")
        self.usb.cmd([TUR, 0, 0, 0, 0, 0])
        self.assertEqual(read_files(self.usb), dict(files2))

    def test_card_reset_aborts_upload(self):
        apdus = q.factory_drive_apdus(self.img)
        for a in apdus[:3]:
            self.assertEqual(self.w.tok.sw(a), q.SW_OK)
        self.w.replug()
        self.assertEqual(self.w.tok.sw(apdus[3]), 0x6985)
        self.assertEqual(LIB.sim_msc_present(), 0)

    def test_power_cut_never_shows_a_partial_image(self):
        apdus = q.factory_drive_apdus(self.img, chunk=2048)
        for budget in list(range(0, 12)) + [len(apdus) - 3, len(apdus) - 2, len(apdus) - 1,
                                            len(apdus), len(apdus) + 1, len(apdus) + 2]:
            w = World(seed=7)
            LIB.sim_set_power_budget(budget)
            for a in apdus:
                if w.tok.sw(a) != q.SW_OK:
                    break
            LIB.sim_reboot()
            w.tok.boot()
            if LIB.sim_msc_present():
                self.assertEqual(drive_bytes(0, len(self.img)), self.img, budget)
            else:
                self.assertNotEqual(drive_bytes(510, 2), b"\x55\xAA", budget)

    def test_board_without_drive(self):
        LIB.sim_drive_none(1)
        try:
            self.w.tok.boot()
            self.w.tok.select()
            self.assertEqual(self.w.tok.sw(q.factory_drive_apdus(self.img)[0]), 0x6D00)
            self.assertEqual(LIB.sim_msc_present(), 0)
        finally:
            LIB.sim_drive_none(0)


class TestReadOnlyDisk(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w = World(seed=3)
        cls.img = mdi.build(sample_files(50_000), when=datetime.datetime(2026, 10, 8))
        assert all(sw == q.SW_OK for sw in upload(cls.w, cls.img))

    def setUp(self):
        LIB.sim_msc_reset()
        self.usb = Usb()
        self.usb.cmd([TUR, 0, 0, 0, 0, 0])   # clear any pending unit attention

    def test_inquiry(self):
        d, res, s = self.usb.cmd([INQ, 0, 0, 0, 36, 0], 36)
        self.assertEqual((len(d), res, s), (36, 0, 0))
        self.assertEqual(d[1] & 0x80, 0x80, "removable")
        self.assertEqual(d[8:16], b"DTII    ")
        self.assertEqual(d[16:32], b"Ascert.en Setup ")
        d, res, s = self.usb.cmd([INQ, 0, 0, 0, 255, 0], 255)
        self.assertEqual((len(d), res, s), (36, 219, 0), "short data, residue reported")
        d, res, s = self.usb.cmd([INQ, 0, 0, 0, 5, 0], 5)
        self.assertEqual((len(d), res, s), (5, 0, 0))
        _, _, s = self.usb.cmd([INQ, 1, 0x80, 0, 255, 0], 255)
        self.assertEqual((s, self.usb.sense()), (1, (0x05, 0x24, 0x00)), "no VPD pages")

    def test_write_protected(self):
        d, _, s = self.usb.cmd([MSENSE6, 0, 0x3F, 0, 192, 0], 192)
        self.assertEqual((d[:4], s), (b"\x03\x00\x80\x00", 0), "WP bit in MODE SENSE(6)")
        d, _, s = self.usb.cmd([MSENSE10, 0, 0x3F, 0, 0, 0, 0, 0, 255, 0], 255)
        self.assertEqual((d[3] & 0x80, s), (0x80, 0), "WP bit in MODE SENSE(10)")
        before = drive_bytes(0, 4096)
        cdb = [WRITE10, 0, 0, 0, 0, 0, 0, 0, 2, 0]
        d, res, s = self.usb.cmd(cdb, 1024, din=False, dout=b"\x00" * 1024)
        self.assertEqual((d, res, s), (b"", 0, 1))
        self.assertEqual(self.usb.sense(), (0x07, 0x27, 0x00), "DATA PROTECT / WRITE PROTECTED")
        self.assertEqual(drive_bytes(0, 4096), before, "nothing written")
        self.assertEqual(self.usb.cmd([TUR, 0, 0, 0, 0, 0])[2], 0, "next command works")

    def test_capacity_and_reads(self):
        d, _, s = self.usb.cmd([RFC, 0, 0, 0, 0, 0, 0, 0, 252, 0], 252)
        self.assertEqual((s, struct.unpack(">I", d[4:8])[0], d[8]), (0, BLOCKS, 0x02))
        self.assertEqual(self.usb.sector(0, 9), self.img[:9 * 512])
        lba = len(self.img) // 512 - 3
        d, _, s = self.usb.cmd([READ12, 0] + list(struct.pack(">II", lba, 3)) + [0, 0], 1536)
        self.assertEqual((s, d), (0, self.img[lba * 512:]))
        d, _, s = self.usb.cmd([READ6, 0, 0, 1, 2, 0], 1024)
        self.assertEqual((s, d), (0, self.img[512:1536]))
        big = self.usb.sector(0, 128)                    # 64 KB in one command
        self.assertEqual(big, drive_bytes(0, 65536))
        for cdb in ([VERIFY10] + [0] * 9, [PREVENT, 0, 0, 0, 1, 0], [START_STOP, 0, 0, 0, 1, 0],
                    [SYNC] + [0] * 9):
            self.assertEqual(self.usb.cmd(cdb)[2], 0, hex(cdb[0]))

    def test_read_out_of_range(self):
        d, res, s = self.usb.read10(BLOCKS - 1, 2)
        self.assertEqual((s, res), (1, 1024))
        self.assertEqual(len(d), 1, "one padding byte ends the empty data phase")
        self.assertEqual(self.usb.sense(), (0x05, 0x21, 0x00))
        d, res, s = self.usb.read10(BLOCKS - 1, 1)
        self.assertEqual((s, res, len(d)), (0, 0, 512), "last block reads")

    def test_bad_commands(self):
        _, _, s = self.usb.cmd([0xFF] + [0] * 5)
        self.assertEqual((s, self.usb.sense()), (1, (0x05, 0x20, 0x00)))
        _, _, s = self.usb.cmd([TUR, 0, 0, 0, 0, 0], lun=1)
        self.assertEqual((s, self.usb.sense()), (1, (0x05, 0x25, 0x00)))

    def test_phase_errors(self):
        _, _, s = self.usb.cmd([INQ, 0, 0, 0, 36, 0], 0)
        self.assertEqual(s, 2, "Hn < Di")
        d, res, s = self.usb.read10(0, 2, length=512)
        self.assertEqual((len(d), s), (512, 2), "Hi < Di: what fits, then phase error")
        _, _, s = self.usb.cmd([READ10, 0, 0, 0, 0, 0, 0, 0, 1, 0], 512, din=False,
                               dout=b"\x00" * 512)
        self.assertEqual(s, 2, "Ho <> Di")
        self.assertEqual(self.usb.cmd([TUR, 0, 0, 0, 0, 0])[2], 0)

    def test_invalid_cbw_stalls_until_reset(self):
        good = self.usb.cbw([TUR, 0, 0, 0, 0, 0])
        self.assertIsNone(self.usb.cmd(None, raw=b"USBX" + good[4:]), "bad signature")
        self.assertIsNone(self.usb.cmd(None, raw=good), "stays stalled")
        LIB.sim_msc_reset()                                # Bulk-Only Mass Storage Reset
        self.assertEqual(self.usb.cmd([TUR, 0, 0, 0, 0, 0])[2], 0)
        self.assertIsNone(self.usb.cmd(None, raw=good[:30]), "short CBW")
        LIB.sim_msc_reset()
        self.assertIsNone(self.usb.cmd(None, raw=good[:14] + b"\x00" + good[15:]), "CB length 0")
        LIB.sim_msc_reset()


if __name__ == "__main__":
    unittest.main()
