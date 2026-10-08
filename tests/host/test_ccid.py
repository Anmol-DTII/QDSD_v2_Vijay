"""USB CCID transport (protocol v3.2): the message layer in src/usb/ccid.c.

The reader is driven exactly as the host smart-card stack drives it
(Windows usbccid.sys, pcsc-lite libccid, macOS CryptoTokenKit): power the
card, read the ATR, exchange whole APDUs in XfrBlock, power off.
"""
import ctypes
import struct
import unittest

import qdsd_proto as q
from qdsd_proto import CCID, F, T, LC
from test_flows import LIB, World

LIB.sim_ccid.restype = ctypes.c_size_t
LIB.sim_ccid.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
LIB.ccid_class_descriptor.restype = ctypes.POINTER(ctypes.c_uint8)
LIB.ccid_atr.restype = ctypes.POINTER(ctypes.c_uint8)
LIB.ccid_atr.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
LIB.ccid_msg_len.restype = ctypes.c_size_t
LIB.ccid_msg_len.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

APDU_MAX = 2048 + 64
OK_ACTIVE, OK_INACTIVE = 0x00, 0x01
FAILED = 0x40


class Reader:
    def __init__(self):
        LIB.sim_ccid_unplug()
        self.seq = 0

    def send(self, mtype, data=b"", slot=0, param=b"\x00\x00\x00", raw=None):
        self.seq = (self.seq + 1) & 0xFF
        msg = raw if raw is not None else q.ccid_msg(mtype, data, self.seq, slot, param)
        out = ctypes.create_string_buffer(4096)
        n = LIB.sim_ccid(msg, len(msg), out, 4096)
        r = q.ccid_parse(out.raw[:n])
        if raw is None:
            assert r[1] == self.seq, "bSeq echoed"
        return r

    def power_on(self):
        return self.send(CCID["POWER_ON"])

    def xfr(self, apdu):
        return self.send(CCID["XFR_BLOCK"], apdu)


class CcidToken:
    """Drop-in for test_flows.Token, carried over CCID XfrBlock."""

    def __init__(self, inner):
        self.inner = inner
        self.reader = Reader()
        mtype, _, status, _, _, atr = self.reader.power_on()
        assert mtype == CCID["DATA_BLOCK"] and status == OK_ACTIVE and atr

    def raw(self, apdu):
        mtype, _, status, err, _, data = self.reader.xfr(apdu)
        assert mtype == CCID["DATA_BLOCK"] and status == OK_ACTIVE, (status, err)
        return q.split_rsp(data)

    def __getattr__(self, k):
        return getattr(self.inner, k)

    sw = lambda self, a: self.raw(a)[1]  # noqa: E731

    def ok(self, apdu):
        data, sw = self.raw(apdu)
        if sw != q.SW_OK:
            raise AssertionError(f"SW {sw:04X}")
        return q.tlv_dict(data) if data else {}

    def select(self):
        assert self.sw(q.select()) == q.SW_OK

    def info(self):
        return self.ok(q.apdu("GET_INFO"))


class TestDescriptor(unittest.TestCase):
    def test_class_descriptor(self):
        d = bytes(LIB.ccid_class_descriptor()[:54])
        self.assertEqual(d[0], 54)
        self.assertEqual(d[1], 0x21)
        self.assertEqual(struct.unpack("<H", d[2:4])[0], 0x0110)
        self.assertEqual(d[4], 0, "one slot")
        self.assertEqual(struct.unpack("<I", d[6:10])[0], 0x2, "T=1")
        features = struct.unpack("<I", d[40:44])[0]
        self.assertEqual(features & 0x00070000, 0x00040000, "extended APDU level")
        self.assertFalse(features & 0x40 and features & 0x80, "one PPS mode only")
        max_msg = struct.unpack("<I", d[44:48])[0]
        self.assertGreaterEqual(max_msg, 10 + APDU_MAX, "largest APDU fits one message")
        self.assertGreaterEqual(max_msg, 10 + 2048, "largest response fits one message")
        self.assertEqual(d[53], 1, "bMaxCCIDBusySlots")

    def test_atr(self):
        n = ctypes.c_size_t(0)
        atr = bytes(LIB.ccid_atr(ctypes.byref(n))[:n.value])
        self.assertEqual(atr[0], 0x3B)
        k = atr[1] & 0x0F
        self.assertEqual(atr[4:4 + k], b"QDSDAscertEN")
        tck = 0
        for b in atr[1:]:
            tck ^= b
        self.assertEqual(tck, 0, "TCK makes the XOR of T0..TCK zero")
        self.assertLessEqual(len(atr), 33)
        self.assertEqual(atr.hex().upper(), "3B8C800151445344417363657274454E36",
                         "the ATR published in docs/USB_CCID.md")

    def test_message_length(self):
        hdr = q.ccid_msg(CCID["XFR_BLOCK"], b"\x00" * 300)
        self.assertEqual(LIB.ccid_msg_len(hdr[:9], 9), 0, "header incomplete")
        self.assertEqual(LIB.ccid_msg_len(hdr, 10), 310)
        big = bytes([0x6F]) + struct.pack("<I", 10_000) + b"\x00" * 5
        self.assertGreater(LIB.ccid_msg_len(big, 10), 10 + APDU_MAX)


class TestReader(unittest.TestCase):
    def setUp(self):
        self.w = World()  # gives a fresh token model
        self.r = Reader()

    def test_power_cycle_and_select(self):
        r = self.r
        mtype, _, status, err, _, _ = r.xfr(q.select())
        self.assertEqual((mtype, status, err), (CCID["DATA_BLOCK"], FAILED | OK_INACTIVE, 0xFE),
                         "card not powered: mute")
        self.assertEqual(r.send(CCID["GET_SLOT_STATUS"])[2], OK_INACTIVE)
        mtype, _, status, _, _, atr = r.power_on()
        self.assertEqual((mtype, status), (CCID["DATA_BLOCK"], OK_ACTIVE))
        self.assertEqual(atr[4:16], b"QDSDAscertEN")
        self.assertEqual(r.send(CCID["GET_SLOT_STATUS"])[2], OK_ACTIVE)
        _, _, _, _, _, data = r.xfr(q.select())
        self.assertEqual(q.split_rsp(data)[1], q.SW_OK)
        _, _, _, _, _, data = r.xfr(q.apdu("GET_INFO"))
        info = q.tlv_dict(q.split_rsp(data)[0])
        self.assertEqual(info[T["PROTO_MINOR"]], b"\x03")
        # Power off ends the session: like pulling the card.
        mtype, _, status, _, _, _ = r.send(CCID["POWER_OFF"])
        self.assertEqual((mtype, status), (CCID["SLOT_STATUS"], OK_INACTIVE))
        r.power_on()
        _, _, _, _, _, data = r.xfr(q.apdu("GET_INFO"))
        self.assertEqual(q.split_rsp(data)[1], 0x6982, "SELECT needed again")

    def test_errors(self):
        r = self.r
        r.power_on()
        mtype, _, status, err, _, _ = r.send(CCID["XFR_BLOCK"], q.select(), slot=1)
        self.assertEqual((status, err), (FAILED | 0x02, 0x05), "no such slot")
        mtype, _, status, err, _, _ = r.send(CCID["XFR_BLOCK"], q.select(), param=b"\x00\x01\x00")
        self.assertEqual((status, err), (FAILED, 0x08), "APDU chaining not used")
        bad = bytes([0x6F]) + struct.pack("<I", 20) + b"\x00\x09\x00\x00\x00" + q.select()
        mtype, _, status, err, _, _ = r.send(0, raw=bad)
        self.assertEqual((mtype, status, err), (CCID["DATA_BLOCK"], FAILED, 0x01))
        mtype, _, status, err, _, _ = r.send(CCID["ESCAPE"], b"\x01")
        self.assertEqual((mtype, status, err), (0x83, FAILED, 0x00), "not supported")
        mtype, _, status, _, _, _ = r.send(0x6E)  # IccClock
        self.assertEqual((mtype, status), (CCID["SLOT_STATUS"], FAILED))
        mtype, _, status, err, _, _ = r.xfr(b"")
        self.assertEqual((status, err), (FAILED, 0x01), "empty block")

    def test_parameters(self):
        r = self.r
        r.power_on()
        for m in (CCID["GET_PARAMETERS"], CCID["RESET_PARAMETERS"], CCID["SET_PARAMETERS"]):
            mtype, _, status, _, proto, data = r.send(m, b"\x11\x10\x00\x4D\x00\xFE\x00"
                                                     if m == CCID["SET_PARAMETERS"] else b"")
            self.assertEqual((mtype, status, proto), (CCID["PARAMETERS"], OK_ACTIVE, 1))
            self.assertEqual(len(data), 7)

    def test_abort(self):
        r = self.r
        r.power_on()
        mtype, _, status, _, _, _ = r.send(CCID["ABORT"])
        self.assertEqual((mtype, status), (CCID["SLOT_STATUS"], OK_ACTIVE))


def big_cert(pub, ca):
    """A certificate near the 2 KB limit (many SAN entries)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    now = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    names = [x509.DNSName("host%03d.example.gov.in" % i) for i in range(68)]
    c = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Big")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")]))
         .public_key(q.load_spki(pub)).serial_number(7)
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.SubjectAlternativeName(names), critical=False)
         .sign(ca, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


class TestFlowsOverCcid(unittest.TestCase):
    def test_all_flows(self):
        w = World()
        w.tok = CcidToken(w.tok)
        w.tok.select()
        w.factory()
        w.pair()
        slot, pub, cert = w.issue_dsc(alg="RSA2048")   # 2 KB APDUs and responses
        h, _, sig, rec = w.sign(slot)
        self.assertTrue(q.verify_dsc(pub, sig, h))
        r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
        self.assertEqual(r[T["CHUNK"]], cert)
        self.assertEqual(w.tok.lc, LC["READY"])

    def test_largest_messages(self):
        w = World()
        w.tok = CcidToken(w.tok)
        w.tok.select()
        w.factory()
        w.pair()
        slot, pub = w.keygen()
        cert = big_cert(pub, w.ca)
        self.assertGreater(len(cert), 1900)
        # One WRITE_CERT APDU of ~2 KB in a single XfrBlock.
        self.assertEqual(w.write_cert(slot, cert, chunk=2040), q.SW_OK)
        got = b""
        while True:
            r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], struct.pack(">H", len(got))),
                                p1=slot))
            self.assertLessEqual(len(r[T["CHUNK"]]), 1024)
            got += r[T["CHUNK"]]
            if len(got) == struct.unpack(">H", r[T["TOTAL"]])[0]:
                break
        self.assertEqual(got, cert)


if __name__ == "__main__":
    unittest.main()
