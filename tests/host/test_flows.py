"""End-to-end host tests for the QDSD token against Ascert.en Flows v3.4 (protocol v3.2).

The token subsystem (src/token, src/protocol, ...) + software hardware model run
in-process (libqdsd_host.so).
Python plays Factory Tool, DTI Cloud, Subscriber App and CA, using the
independent reference encoder in tools/qdsd_proto.py and real X.509.
"""
import ctypes
import datetime
import os
import random
import struct
import unittest
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.x509.oid import NameOID

import qdsd_proto as q
from qdsd_proto import F, T, LC

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = ctypes.CDLL(os.path.join(HERE, "libqdsd_host.so"))
LIB.token_engine_process.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
LIB.sim_reset_all.argtypes = [ctypes.c_uint32]
LIB.sim_fw_none.argtypes = [ctypes.c_int]
LIB.sim_set_power_budget.argtypes = [ctypes.c_long]
LIB.sim_advance_ms.argtypes = [ctypes.c_uint64]
LIB.token_engine_lifecycle.restype = ctypes.c_uint8
LIB.sim_state_get.restype = ctypes.c_size_t
LIB.sim_state_get.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
LIB.sim_state_set.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

EVT_UPDATE_REBOOT = 3
CTR_BINDING, CTR_KEYGEN, CTR_SIGN, CTR_POLICY = 0, 1, 2, 3
M = q.METHOD
LOGIN_REQ = q.POLICY_LOGIN_REQUIRED
HOUR = 3600 * 1000
SLOTS = 4


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(subject_pub, issuer_key, cn="Subscriber", serial=None) -> bytes:
    now = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name(cn)).issuer_name(name("Test CA"))
            .public_key(q.load_spki(subject_pub))
            .serial_number(serial or x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=730))
            .sign(issuer_key, hashes.SHA256()))
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.DER)


class TokenError(AssertionError):
    pass


class Token:
    """The token as the middleware sees it (APDUs in, responses out)."""

    def __init__(self, seed=1):
        LIB.sim_reset_all(seed)
        self.boot()

    def boot(self):
        return LIB.token_engine_init()

    def raw(self, apdu: bytes):
        out = ctypes.create_string_buffer(2048)   # QDSD_RSP_MAX, as the CCID layer passes
        n = ctypes.c_size_t(0)
        LIB.token_engine_process(apdu, len(apdu), out, 2048, ctypes.byref(n))
        return q.split_rsp(out.raw[:n.value])

    def sw(self, apdu: bytes) -> int:
        return self.raw(apdu)[1]

    def ok(self, apdu: bytes) -> dict:
        data, sw = self.raw(apdu)
        if sw != q.SW_OK:
            raise TokenError(f"SW {sw:04X} for INS {apdu[1]:02X}")
        return q.tlv_dict(data) if data else {}

    def select(self):
        assert self.sw(q.select()) == q.SW_OK

    def info(self):
        return self.ok(q.apdu("GET_INFO"))

    @property
    def lc(self):
        return LIB.token_engine_lifecycle()


class World:
    """Factory, cloud, phone and CA keys plus helpers for every flow."""

    def __init__(self, seed=1):
        self.tok = Token(seed)
        self.device_ca = new_key()
        self.cmd = new_key()          # DTI command key (cloud HSM)
        self.phone = new_key()        # Subscriber activation key
        self.ca = new_key()           # Certifying Authority
        self.seqs = {}                # slot -> keygen_seq of the key in it (cloud's view)
        self.tok.select()

    # Flow 1
    def factory(self):
        t = self.tok
        r = t.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        self.device_id = r[F["DEVICE_ID"]]
        self.device_pub = r[F["DEVICE_PUB"]]
        assert r[T["VENDOR_ATT"]].startswith(b"SIMATT" + b"F" * 16)
        self.device_cert = make_cert(self.device_pub, self.device_ca, "QDSD device")
        t.ok(q.apdu("FACTORY_PERSONALISE", self.personalise_data()))
        rc = t.ok(q.apdu("FACTORY_CLOSE"))
        return q.open_signed(rc, self.device_pub, "FACTORY_RECEIPT")

    # Per-device FACTORY_RESET secrets (DTI derives them from a master key).
    WIPE_DEV = bytes(range(0x10, 0x20))
    WIPE_DSC = bytes(range(0x30, 0x40))

    def personalise_data(self, cert=None, cmd=None):
        return (q.tlv(T["DEVICE_CERT"], cert or self.device_cert) +
                q.tlv(T["CMD_PUB"], q.pub_bytes(cmd or self.cmd)) +
                q.tlv(T["WIPE_SECRET_DEV"], self.WIPE_DEV) +
                q.tlv(T["WIPE_SECRET_DSC"], self.WIPE_DSC))

    # Counters are read through ATTEST: signed, and allowed while logged out.
    def attest(self, challenge=b"A" * 16):
        r = self.tok.ok(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], challenge)))
        return q.open_signed(r, self.device_pub, "ATTEST")

    def binding_no(self):
        return self.attest()["BINDING_NO"]

    def keygen_ctr(self):
        return self.attest()["KEYGEN_COUNTER"]

    def policy_no(self):
        return self.attest()["POLICY_NO"]

    def session(self):
        return self.tok.info()[F["SESSION"]][0]

    def replug(self):
        LIB.token_engine_session_reset()
        self.tok.select()

    # Flow 2
    def bind_apdu(self, phone=None, binding=None, signer=None, device_id=None,
                  flags=LOGIN_REQ):
        phone = phone or self.phone
        st = q.stmt_build("BIND", DEVICE_ID=device_id or self.device_id,
                          BINDING_NO=self.binding_no() + 1 if binding is None else binding,
                          ACTIVATION_PUB=q.pub_bytes(phone), POLICY_FLAGS=flags)
        return q.apdu("BIND", q.signed(st, signer or self.cmd))

    def pair(self):
        r = self.tok.ok(self.bind_apdu())
        return q.open_signed(r, self.device_pub, "BIND_RECEIPT")

    # Flow 3
    def consent_apdu(self, seq=None, signer=None, der=True, method=M["BIOMETRIC"]):
        st = q.stmt_build("KEYGEN_CONSENT", DEVICE_ID=self.device_id,
                          KEYGEN_SEQ=self.keygen_ctr() + 1 if seq is None else seq,
                          VALID_UNTIL=1_800_000_000_000, METHOD=method)
        return q.apdu("KEYGEN", q.signed(st, signer or self.phone, der=der))

    def envelope_apdu(self, seq=None, signer=None):
        st = q.stmt_build("KEYGEN_ENVELOPE", DEVICE_ID=self.device_id,
                          KEYGEN_SEQ=self.keygen_ctr() + 1 if seq is None else seq,
                          SETTING_REF=q.sha256(b"subscriber setting"))
        return q.apdu("KEYGEN", q.signed(st, signer or self.cmd))

    def keygen(self, via="consent", alg="P256"):
        a = self.consent_apdu() if via == "consent" else self.envelope_apdu()
        a = a[:2] + bytes([q.ALG[alg]]) + a[3:]
        r = self.tok.ok(a)
        att = q.open_signed(r, self.device_pub, "KEY_ATTEST")
        slot = r[F["KEY_SLOT"]][0]
        assert att["KEY_SLOT"] == slot and att["DSC_PUB"] == r[F["DSC_PUB"]]
        self.seqs[slot] = att["KEYGEN_SEQ"]
        return slot, r[F["DSC_PUB"]]

    def csr(self, slot, pub, digest_mode=False):
        cri = q.build_cri(name("Subscriber").public_bytes(), pub)
        rsa_key = q.is_rsa(pub)
        if digest_mode:
            r = self.tok.ok(q.apdu("SIGN_CSR", q.tlv(T["CSR_DIGEST"], q.sha256(cri)),
                                   p1=slot, p2=1))
        else:
            r = self.tok.ok(q.apdu("SIGN_CSR", q.tlv(T["CRI"], cri), p1=slot))
        sig = r[T["DSC_SIG_RAW"]] if rsa_key else r[T["DSC_SIG_DER"]]
        return q.build_csr(cri, sig, rsa_key)

    def write_cert(self, slot, cert, chunk=200):
        first = True
        for i in range(0, len(cert), chunk):
            part = cert[i:i + chunk]
            data = (q.tlv(T["TOTAL"], struct.pack(">H", len(cert))) if first else b"") + \
                q.tlv(T["CHUNK"], part)
            sw = self.tok.sw(q.apdu("WRITE_CERT", data, p1=slot, p2=0 if first else 1))
            if sw != q.SW_OK:
                return sw
            first = False
        return q.SW_OK

    def issue_dsc(self, via="consent", alg="P256", digest_mode=False):
        slot, pub = self.keygen(via, alg)
        csr = x509.load_der_x509_csr(self.csr(slot, pub, digest_mode))
        assert csr.is_signature_valid
        cert = make_cert(pub, self.ca)
        assert self.write_cert(slot, cert) == q.SW_OK
        return slot, pub, cert

    def setup_ready(self):
        self.factory()
        self.pair()
        return self.issue_dsc()

    # Flow 4
    def nonce(self):
        return self.tok.ok(q.apdu("GET_SESSION_NONCE"))[F["NONCE"]]

    def sign_apdu(self, nonce, h_tbs, slot, h_ctx=None, rid=None, signer=None,
                  override=None, plain_override=None, keygen_seq=None):
        h_ctx = h_ctx or q.sha256(b"context")
        rid = rid or bytes(range(16))
        seq = self.seqs.get(slot, 0) if keygen_seq is None else keygen_seq
        f = dict(DEVICE_ID=self.device_id, NONCE=nonce, H_TBS=h_tbs, H_CTX=h_ctx,
                 REQUEST_ID=rid, TIME=1_790_000_000_000, KEYGEN_SEQ=seq, KEY_SLOT=slot,
                 METHOD=M["BIOMETRIC"])
        f.update(override or {})
        st = q.stmt_build("SIGN_ASSERTION", **f)
        plain = dict(H_TBS=h_tbs, H_CTX=h_ctx, REQUEST_ID=rid, KEY_SLOT=bytes([slot]))
        plain.update(plain_override or {})
        data = (q.tlv(F["H_TBS"], plain["H_TBS"]) + q.tlv(F["H_CTX"], plain["H_CTX"]) +
                q.tlv(F["REQUEST_ID"], plain["REQUEST_ID"]) +
                q.tlv(F["KEY_SLOT"], plain["KEY_SLOT"]) +
                q.signed(st, signer or self.phone, der=True))
        return q.apdu("SIGN", data)

    def sign(self, slot, h_tbs=None, phone=None):
        h_tbs = h_tbs or q.sha256(os.urandom(8))
        n = self.nonce()
        r = self.tok.ok(self.sign_apdu(n, h_tbs, slot, signer=phone))
        rec = q.open_signed(r, self.device_pub, "SIGN_RECEIPT")
        return h_tbs, n, r[T["DSC_SIG_RAW"]], rec

    # Flow 2b and QDSD settings
    def login_apdu(self, nonce, signer=None, method=M["BIOMETRIC"], device_id=None):
        st = q.stmt_build("LOGIN_ASSERTION", DEVICE_ID=device_id or self.device_id,
                          NONCE=nonce, TIME=1_790_000_000_000, METHOD=method)
        return q.apdu("LOGIN", q.signed(st, signer or self.phone, der=True))

    def login(self):
        n = self.nonce()
        r = self.tok.ok(self.login_apdu(n))
        rec = q.open_signed(r, self.device_pub, "LOGIN_RECEIPT")
        assert rec["NONCE"] == n and rec["SESSION"] == 1
        return rec

    def policy_apdu(self, flags, policy_no=None, signer=None, method=M["BIOMETRIC"]):
        st = q.stmt_build("POLICY", DEVICE_ID=self.device_id, TIME=1_790_000_000_000,
                          POLICY_NO=self.policy_no() + 1 if policy_no is None else policy_no,
                          POLICY_FLAGS=flags, METHOD=method)
        return q.apdu("POLICY", q.signed(st, signer or self.phone, der=True))


# ═════════════════════════════════════════════════════════════════════

class TestTransportAndSelect(unittest.TestCase):
    def test_select_required(self):
        t = Token()
        self.assertEqual(t.sw(q.apdu("GET_INFO")), 0x6982)
        for old in ("01", "02"):
            self.assertEqual(t.sw(bytes.fromhex("00A404000AA0000000445449494C" + old)),
                             0x6A82, f"v{old} AID must be refused")
        t.select()
        self.assertEqual(t.info()[T["PROTO_VER"]], b"\x03")
        self.assertEqual(t.info()[T["PROTO_MINOR"]], b"\x03",
                         "3: SIGN_ASSERTION carries keygen_seq (0.6.0 lab tokens report 2)")

    def test_bad_apdus(self):
        t = Token()
        t.select()
        self.assertEqual(t.sw(b"\x80"), 0x6700)
        self.assertEqual(t.sw(b"\x00\xC1\x00\x00"), 0x6E00)
        self.assertEqual(t.sw(b"\x80\x99\x00\x00"), 0x6D00)
        self.assertEqual(t.sw(b"\x80\xC1\x00\x00\x05\x01"), 0x6700)  # Lc lies

    def test_random_apdus_never_crash(self):
        w = World()
        w.setup_ready()
        rnd = random.Random(7)
        ins = list(q.INS.values())
        for _ in range(3000):
            body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 300)))
            a = bytes([0x80, rnd.choice(ins), rnd.getrandbits(8), rnd.getrandbits(8)])
            if body:
                a += bytes([min(len(body), 255)]) + body[:255]
            if a[1] == q.INS["RESET"]:
                continue
            _, sw = w.tok.raw(a)
            self.assertNotEqual(sw, q.SW_OK if a[1] in (q.INS["SIGN"], q.INS["BIND"]) else -1)
        self.assertEqual(w.tok.lc, LC["READY"])


class TestFactory(unittest.TestCase):
    def test_factory_flow(self):
        w = World()
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        self.assertEqual(w.tok.sw(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"c" * 16))), 0x6985)
        rec = w.factory()
        self.assertEqual(rec["STATE"], LC["UNASSIGNED"])
        self.assertEqual(rec["BINDING_NO"], 0)
        self.assertEqual(rec["CMD_KEY_HASH"], q.sha256(q.pub_bytes(w.cmd)))
        self.assertEqual(rec["DEVICE_CERT_HASH"], q.sha256(w.device_cert))
        # Personalisation is closed for good.
        for ins in ("FACTORY_INIT", "FACTORY_PERSONALISE", "FACTORY_CLOSE"):
            self.assertEqual(w.tok.sw(q.apdu(ins, q.tlv(F["CHALLENGE"], b"x" * 16))), 0x6985)
        # Device certificate readable in chunks.
        r = w.tok.ok(q.apdu("GET_DEVICE_CERT", q.tlv(T["OFFSET"], b"\x00\x00")))
        self.assertEqual(r[T["CHUNK"]], w.device_cert)

    def test_personalise_rejects_foreign_cert(self):
        w = World()
        r = w.tok.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        other = make_cert(q.pub_bytes(new_key()), w.device_ca)
        sw = w.tok.sw(q.apdu("FACTORY_PERSONALISE", q.tlv(T["DEVICE_CERT"], other) +
                             q.tlv(T["CMD_PUB"], q.pub_bytes(w.cmd))))
        self.assertEqual(sw, 0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_CLOSE")), 0x6985)
        # v3.2: the id covers the device key too, so a wiped and re-made token
        # gets a new id and nothing signed for its previous life applies.
        self.assertEqual(r[F["DEVICE_ID"]], q.sha256(b"QDSD-DEVID" + r[T["CHIP_UID"]] +
                                                     r[F["DEVICE_PUB"]])[:16])

    def test_close_requires_personalisation(self):
        w = World()
        w.tok.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_CLOSE")), 0x6985)


class TestPairing(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.factory()

    def test_attest(self):
        w = self.w
        r = w.tok.ok(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"C" * 32)))
        st = q.open_signed(r, w.device_pub, "ATTEST")
        self.assertEqual(st["CHALLENGE"], b"C" * 32)
        self.assertEqual(st["STATE"], LC["UNASSIGNED"])
        self.assertEqual(st["ACT_KEY_HASH"], b"\x00" * 32)
        self.assertEqual(w.tok.sw(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"C" * 8))), 0x6A80)

    def test_bind_checks(self):
        w = self.w
        self.assertEqual(w.tok.sw(w.bind_apdu(binding=5)), 0x6984)
        self.assertEqual(w.tok.sw(w.bind_apdu(signer=new_key())), 0x6982)
        self.assertEqual(w.tok.sw(w.bind_apdu(device_id=b"\x00" * 16)), 0x6A80)
        self.assertEqual(w.tok.lc, LC["UNASSIGNED"])
        rec = w.pair()
        self.assertEqual(rec["BINDING_NO"], 1)
        self.assertEqual(rec["STATE"], LC["BOUND"])
        self.assertEqual(rec["ACT_KEY_HASH"], q.sha256(q.pub_bytes(w.phone)))
        self.assertEqual((rec["POLICY_FLAGS"], rec["POLICY_NO"]), (LOGIN_REQ, 0))
        # BIND only while UNASSIGNED: the cloud cannot silently move a live token.
        self.assertEqual(w.tok.sw(w.bind_apdu(phone=new_key())), 0x6985)

    def test_bind_rejects_invalid_point(self):
        w = self.w
        st = q.stmt_build("BIND", DEVICE_ID=w.device_id, BINDING_NO=1,
                          ACTIVATION_PUB=b"\x04" + b"\x01" * 64, POLICY_FLAGS=1)
        self.assertEqual(w.tok.sw(q.apdu("BIND", q.signed(st, w.cmd))), 0x6A80)

    def test_non_canonical_statements_rejected(self):
        w = self.w
        good = q.stmt_build("BIND", DEVICE_ID=w.device_id, BINDING_NO=1,
                            ACTIVATION_PUB=q.pub_bytes(w.phone), POLICY_FLAGS=1)
        body = good[5:]
        items = q.tlv_parse(body)
        swapped = good[:5] + q.tlv(*items[1]) + q.tlv(*items[0]) + b"".join(
            q.tlv(*i) for i in items[2:])
        extra = good + q.tlv(0x26, b"\x01")
        dup = good + q.tlv(*items[2])
        wrong_purpose = good[:4] + b"\x06" + body
        for bad in (swapped, extra, dup, wrong_purpose, b"QDS2" + good[4:]):
            self.assertEqual(w.tok.sw(q.apdu("BIND", q.signed(bad, w.cmd))), 0x6A80)


class TestDscIssuance(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.factory()
        self.w.pair()

    def test_consent_path_csr_and_cert(self):
        w = self.w
        slot, pub, cert = w.issue_dsc("consent")
        self.assertEqual(w.tok.lc, LC["READY"])
        r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
        self.assertEqual(r[T["CHUNK"]], cert)
        # CSR signing is only for keys still waiting for a certificate.
        cri = q.build_cri(name("x").public_bytes(), pub)
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CRI"], cri), p1=slot)), 0x6986)

    def test_envelope_path(self):
        slot, _, _ = self.w.issue_dsc("envelope")
        self.assertEqual(self.w.keygen_ctr(), 1)

    def test_authorisation_cannot_be_replayed(self):
        w = self.w
        a = w.consent_apdu()
        w.tok.ok(a)
        self.assertEqual(w.tok.sw(a), 0x6984)
        self.assertEqual(w.tok.sw(w.consent_apdu(seq=5)), 0x6984)

    def test_wrong_signer_per_purpose(self):
        w = self.w
        self.assertEqual(w.tok.sw(w.consent_apdu(signer=w.cmd)), 0x6982)
        self.assertEqual(w.tok.sw(w.envelope_apdu(signer=w.phone)), 0x6982)
        self.assertEqual(w.keygen_ctr(), 0)

    def test_csr_must_carry_slot_key(self):
        w = self.w
        slot, _ = w.keygen()
        cri = q.build_cri(name("x").public_bytes(), q.pub_bytes(new_key()))
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CRI"], cri), p1=slot)), 0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CRI"], b"\x30\x00"), p1=slot)),
                         0x6A80)

    def test_cert_must_match_key(self):
        w = self.w
        slot, pub = w.keygen()
        self.assertEqual(w.write_cert(slot, make_cert(q.pub_bytes(new_key()), w.ca)), 0x6A80)
        self.assertEqual(w.tok.lc, LC["BOUND"])
        self.assertEqual(w.write_cert(slot + 1, make_cert(pub, w.ca)), 0x6986)  # empty slot
        self.assertEqual(w.write_cert(slot, make_cert(pub, w.ca)), q.SW_OK)
        self.assertEqual(w.tok.lc, LC["READY"])

    def test_cert_upload_sequence(self):
        w = self.w
        slot, pub = w.keygen()
        more = q.apdu("WRITE_CERT", q.tlv(T["CHUNK"], b"\x00" * 10), p1=slot, p2=1)
        self.assertEqual(w.tok.sw(more), 0x6985)
        too_big = q.tlv(T["TOTAL"], struct.pack(">H", 5000)) + q.tlv(T["CHUNK"], b"\x30")
        self.assertEqual(w.tok.sw(q.apdu("WRITE_CERT", too_big, p1=slot)), 0x6A80)

    def test_slots_full_and_pending_reuse(self):
        w = self.w
        for _ in range(SLOTS):
            w.issue_dsc()
        self.assertEqual(w.tok.sw(w.consent_apdu()), 0x6A84)
        info = w.tok.info()
        self.assertEqual(info[T["SLOT_COUNT"]], bytes([SLOTS]))

    def test_abandoned_download_slot_is_reused(self):
        w = self.w
        s1, _ = w.keygen()
        for _ in range(SLOTS - 1):
            w.keygen()
        s_new, _ = w.keygen()  # all pending -> oldest pending reused
        self.assertEqual(s_new, s1)


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.slot, self.pub, self.cert = self.w.setup_ready()

    def test_sign_happy_path(self):
        w = self.w
        h_tbs, n, sig, rec = w.sign(self.slot)
        self.assertTrue(q.verify_dsc(self.pub, sig, h_tbs))
        self.assertEqual(rec["NONCE"], n)
        self.assertEqual(rec["H_TBS"], h_tbs)
        self.assertEqual(rec["SIGN_COUNTER"], 1)
        self.assertEqual(rec["SIG_HASH"], q.sha256(sig))
        self.assertEqual(rec["STATUS"], 0)
        _, _, _, rec2 = w.sign(self.slot)
        self.assertEqual(rec2["SIGN_COUNTER"], 2)

    def test_nonce_single_use(self):
        w = self.w
        n = w.nonce()
        a = w.sign_apdu(n, q.sha256(b"doc"), self.slot)
        w.tok.ok(a)
        self.assertEqual(w.tok.sw(a), 0x6984)

    def test_new_nonce_keeps_old(self):
        """v3.1: a second request does not cancel an approval already in progress."""
        w = self.w
        n1 = w.nonce()
        n2 = w.nonce()
        w.tok.ok(w.sign_apdu(n1, q.sha256(b"doc1"), self.slot))
        w.tok.ok(w.sign_apdu(n2, q.sha256(b"doc2"), self.slot))

    def test_nonce_expires(self):
        w = self.w
        n = w.nonce()
        LIB.sim_advance_ms(600_001)
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"doc"), self.slot)), 0x6984)

    def test_hash_substitution_refused(self):
        """WYSIWYS: the PC cannot swap H_tbs after the phone approved."""
        w = self.w
        n = w.nonce()
        a = w.sign_apdu(n, q.sha256(b"approved"), self.slot,
                        plain_override=dict(H_TBS=q.sha256(b"evil")))
        self.assertEqual(w.tok.sw(a), 0x6A80)
        a = w.sign_apdu(n, q.sha256(b"approved"), self.slot,
                        plain_override=dict(H_CTX=q.sha256(b"other ctx")))
        self.assertEqual(w.tok.sw(a), 0x6A80)
        # Nonce survives a mismatch and still works for the honest request.
        w.tok.ok(w.sign_apdu(n, q.sha256(b"approved"), self.slot))

    def test_wrong_signer_and_nonce_burn(self):
        w = self.w
        n = w.nonce()
        for _ in range(3):
            self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot,
                                                  signer=w.cmd)), 0x6982)
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot)), 0x6984)

    def test_slot_and_device_binding(self):
        w = self.w
        n = w.nonce()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), 3)), 0x6986)
        a = w.sign_apdu(n, q.sha256(b"d"), self.slot, override=dict(KEY_SLOT=3))
        self.assertEqual(w.tok.sw(a), 0x6A80)
        a = w.sign_apdu(n, q.sha256(b"d"), self.slot, override=dict(DEVICE_ID=b"\x11" * 16))
        self.assertEqual(w.tok.sw(a), 0x6A80)

    def test_se_failure_still_reports_counter(self):
        w = self.w
        LIB.sim_fail_dsc_sign(1)
        n = w.nonce()
        data, sw = w.tok.raw(w.sign_apdu(n, q.sha256(b"d"), self.slot))
        LIB.sim_fail_dsc_sign(0)
        self.assertEqual(sw, 0x6F00)
        r = q.tlv_dict(data)
        self.assertNotIn(T["DSC_SIG_RAW"], r)
        rec = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
        self.assertEqual((rec["STATUS"], rec["SIGN_COUNTER"]), (1, 1))
        _, _, _, rec2 = w.sign(self.slot)
        self.assertEqual(rec2["SIGN_COUNTER"], 2)

    def test_usb_reset_drops_session(self):
        w = self.w
        n = w.nonce()
        LIB.token_engine_session_reset()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot)), 0x6982)
        w.tok.select()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot)), 0x6984)

    def test_sign_needs_ready(self):
        w = World()
        w.factory()
        w.pair()
        n = w.nonce()  # v3: nonces exist in BOUND too (login before the first DSC)
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), 0)), 0x6985)

    def test_method_is_required_and_in_range(self):
        w = self.w
        for bad in (0, 6, 0xFF):
            n = w.nonce()
            a = w.sign_apdu(n, q.sha256(b"d"), self.slot, override=dict(METHOD=bad))
            self.assertEqual(w.tok.sw(a), 0x6A80)
        for good in range(1, 6):
            n = w.nonce()
            w.tok.ok(w.sign_apdu(n, q.sha256(b"d"), self.slot, override=dict(METHOD=good)))
        self.assertEqual(w.tok.sw(w.consent_apdu(method=0)), 0x6A80)

    def test_skipped_context_marker(self):
        w = self.w
        n = w.nonce()
        r = w.tok.ok(w.sign_apdu(n, q.sha256(b"d"), self.slot, h_ctx=q.H_CTX_SKIPPED))
        rec = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
        self.assertEqual(rec["H_CTX"], q.H_CTX_SKIPPED)


class TestLoginSession(unittest.TestCase):
    """Flow 2b: logged-out by default, login by phone assertion over a token nonce."""

    def setUp(self):
        self.w = World()
        self.slot, self.pub, self.cert = self.w.setup_ready()

    def test_pairing_session_lasts_until_unplug(self):
        w = self.w
        self.assertEqual(w.session(), 1)
        w.tok.select()                      # re-SELECT on the same plug-in
        self.assertEqual(w.session(), 1)
        LIB.sim_advance_ms(9 * HOUR)        # pairing session has no idle timeout
        self.assertEqual(w.session(), 1)
        w.replug()
        self.assertEqual(w.session(), 0)

    def test_logged_out_hides_device_info_only(self):
        w = self.w
        w.replug()
        info = w.tok.info()
        self.assertEqual(sorted(info), sorted([T["PROTO_VER"], T["PROTO_MINOR"],
                                              F["DEVICE_ID"], F["STATE"],
                                              F["SESSION"], F["POLICY_FLAGS"],
                                              F["FW_VERSION"], T["SESSION_EPOCH"]]))
        self.assertEqual(info[F["SESSION"]], b"\x00")
        self.assertEqual(info[F["POLICY_FLAGS"]], bytes([LOGIN_REQ]))
        # Signing, DSC download, certificates and attestation need no login (v3.3).
        w.sign(self.slot)
        w.issue_dsc()
        r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\0\0"), p1=self.slot))
        self.assertEqual(r[T["CHUNK"]], self.cert)
        w.attest()
        self.assertEqual(w.session(), 0, "signing must not log in")
        # Firmware update needs the login while login approval is on.
        self.assertEqual(w.tok.sw(q.apdu("UPDATE_BEGIN", q.tlv(T["IMAGE_SIZE"], b"\0\0\1\0") +
                                         q.tlv(T["IMAGE_SHA256"], bytes(32)))), 0x6983)

    def test_login_logout(self):
        w = self.w
        w.replug()
        rec = w.login()
        self.assertEqual(rec["POLICY_NO"], 0)
        info = w.tok.info()
        self.assertEqual(info[F["SESSION"]], b"\x01")
        self.assertIn(F["SIGN_COUNTER"], info)
        self.assertEqual(q.tlv_dict(w.tok.raw(q.apdu("LOGOUT"))[0])[F["SESSION"]], b"\x00")
        self.assertNotIn(F["SIGN_COUNTER"], w.tok.info())

    def test_login_checks(self):
        w = self.w
        w.replug()
        self.assertEqual(w.tok.sw(w.login_apdu(b"\x00" * 32)), 0x6984)  # no nonce yet
        n = w.nonce()
        self.assertEqual(w.tok.sw(w.login_apdu(b"\x01" * 32)), 0x6984)  # wrong nonce
        self.assertEqual(w.tok.sw(w.login_apdu(n, method=0)), 0x6A80)
        self.assertEqual(w.tok.sw(w.login_apdu(n, device_id=b"\x09" * 16)), 0x6A80)
        a = w.login_apdu(n)
        w.tok.ok(a)
        self.assertEqual(w.tok.sw(a), 0x6984, "login replay")
        self.assertEqual(w.session(), 1)

    def test_login_wrong_signer_burns_nonce(self):
        w = self.w
        w.replug()
        n = w.nonce()
        for _ in range(3):
            self.assertEqual(w.tok.sw(w.login_apdu(n, signer=w.cmd)), 0x6982)
        self.assertEqual(w.tok.sw(w.login_apdu(n)), 0x6984)
        self.assertEqual(w.session(), 0)

    def test_login_nonce_cannot_sign(self):
        """A login assertion is a different purpose; it can't stand in for SIGN."""
        w = self.w
        w.replug()
        n = w.nonce()
        st = q.stmt_build("LOGIN_ASSERTION", DEVICE_ID=w.device_id, NONCE=n,
                          TIME=1, METHOD=1)
        data = (q.tlv(F["H_TBS"], q.sha256(b"d")) + q.tlv(F["H_CTX"], q.sha256(b"c")) +
                q.tlv(F["REQUEST_ID"], bytes(16)) + q.tlv(F["KEY_SLOT"], bytes([self.slot])) +
                q.signed(st, w.phone))
        self.assertEqual(w.tok.sw(q.apdu("SIGN", data)), 0x6A80)

    def test_idle_timeout(self):
        w = self.w
        w.replug()
        w.login()
        LIB.sim_advance_ms(7 * HOUR)
        w.tok.info()                         # activity resets the idle timer
        LIB.sim_advance_ms(7 * HOUR)
        self.assertEqual(w.session(), 1)
        LIB.sim_advance_ms(8 * HOUR + 1)
        self.assertEqual(w.session(), 0)

    def test_login_works_before_first_dsc(self):
        w = World()
        w.factory()
        w.pair()
        w.replug()
        self.assertEqual(w.tok.lc, LC["BOUND"])
        w.login()
        self.assertEqual(w.session(), 1)


class TestPolicy(unittest.TestCase):
    """QDSD settings: login approval flag, signed by the activation key and numbered."""

    def setUp(self):
        self.w = World()
        self.slot, _, _ = self.w.setup_ready()

    def test_turn_login_approval_off_and_on(self):
        w = self.w
        w.replug()
        r = w.tok.ok(w.policy_apdu(0))
        rec = q.open_signed(r, w.device_pub, "POLICY_RECEIPT")
        self.assertEqual((rec["POLICY_NO"], rec["POLICY_FLAGS"]), (1, 0))
        self.assertEqual(w.session(), 1, "turning approval off logs in")
        w.replug()
        self.assertEqual(w.session(), 1, "session opens on plug-in")
        # LOGOUT can't log out while approval is off.
        self.assertEqual(q.tlv_dict(w.tok.raw(q.apdu("LOGOUT"))[0])[F["SESSION"]], b"\x01")
        # LOGIN is still accepted.
        w.login()
        w.tok.ok(w.policy_apdu(LOGIN_REQ))
        self.assertEqual(w.session(), 0, "turning approval on logs out at once")
        self.assertEqual(w.policy_no(), 2)

    def test_policy_unchanged_flag_keeps_session(self):
        w = self.w
        w.replug()
        w.login()
        w.tok.ok(w.policy_apdu(LOGIN_REQ))
        self.assertEqual(w.session(), 1)

    def test_policy_checks(self):
        w = self.w
        a = w.policy_apdu(0)
        self.assertEqual(w.tok.sw(w.policy_apdu(0, signer=w.cmd)), 0x6982,
                         "the cloud cannot change a setting")
        self.assertEqual(w.tok.sw(w.policy_apdu(0, policy_no=2)), 0x6984)
        self.assertEqual(w.tok.sw(w.policy_apdu(0x02)), 0x6A80, "reserved bit")
        self.assertEqual(w.tok.sw(w.policy_apdu(0, method=9)), 0x6A80)
        w.tok.ok(a)
        self.assertEqual(w.tok.sw(a), 0x6984, "policy replay")
        self.assertEqual(w.policy_no(), 1)

    def test_policy_needs_paired_token(self):
        w = World()
        w.factory()
        st = q.stmt_build("POLICY", DEVICE_ID=w.device_id, TIME=1, POLICY_NO=1,
                          POLICY_FLAGS=0, METHOD=1)
        self.assertEqual(w.tok.sw(q.apdu("POLICY", q.signed(st, w.phone))), 0x6985)

    def test_bind_sets_initial_policy(self):
        w = World()
        w.factory()
        self.assertEqual(w.tok.sw(w.bind_apdu(flags=0x80)), 0x6A80)
        w.tok.ok(w.bind_apdu(flags=0))
        w.replug()
        self.assertEqual(w.session(), 1)
        self.assertEqual(w.policy_no(), 0, "BIND does not count as a policy change")

    def test_reset_clears_flags_keeps_counter(self):
        w = self.w
        w.tok.ok(w.policy_apdu(0))
        st = q.stmt_build("RESET", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1)
        w.tok.ok(q.apdu("RESET", q.signed(st, w.cmd)))
        a = w.attest()
        self.assertEqual((a["POLICY_FLAGS"], a["POLICY_NO"]), (0, 1))
        self.assertEqual(w.tok.sw(q.apdu("LOGIN")), 0x6985)
        w.phone = new_key()
        w.pair()
        w.replug()
        self.assertEqual(w.session(), 0, "re-paired token starts with login approval on")
        self.assertEqual(w.tok.sw(w.policy_apdu(0, policy_no=1)), 0x6984,
                         "old policy number cannot be reused after RESET")
        w.tok.ok(w.policy_apdu(0, policy_no=2))

    def test_rebind_keeps_policy(self):
        w = self.w
        w.tok.ok(w.policy_apdu(0))
        new = new_key()
        st = q.stmt_build("REBIND", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1,
                          NEW_KEY_HASH=q.sha256(q.pub_bytes(new)), METHOD=4)
        w.tok.ok(q.apdu("REBIND", q.tlv(F["ACTIVATION_PUB"], q.pub_bytes(new)) +
                        q.signed(st, w.phone)))
        a = w.attest()
        self.assertEqual((a["POLICY_FLAGS"], a["POLICY_NO"]), (0, 1))
        self.assertEqual(w.tok.sw(w.policy_apdu(LOGIN_REQ)), 0x6982, "old phone key")
        w.tok.ok(w.policy_apdu(LOGIN_REQ, signer=new))


class TestMigrationFromV2(unittest.TestCase):
    """A token personalised and paired by firmware 0.3 (protocol v2)."""

    def test_v1_record_and_missing_policy_counter(self):
        w = World()
        slot, _, _ = w.setup_ready()
        b = bytearray(b"QS\x01") + bytes([LC["READY"], 1]) + w.device_id + bytes(2 + 4 + 65)
        b += struct.pack(">I", zlib.crc32(bytes(b)))
        self.assertEqual(len(b), 96)
        LIB.sim_state_set(bytes(b), len(b))
        LIB.sim_counter_remove(CTR_POLICY)
        self.assertEqual(w.tok.boot(), 0)
        w.tok.select()
        self.assertEqual(w.session(), 0, "migrated token requires login approval")
        a = w.attest()
        self.assertEqual((a["POLICY_FLAGS"], a["POLICY_NO"], a["STATE"]),
                         (LOGIN_REQ, 0, LC["READY"]))
        buf = ctypes.create_string_buffer(128)
        n = LIB.sim_state_get(buf, 128)
        self.assertEqual(buf.raw[:2], b"Q\x02", "record rewritten in v2 layout")
        self.assertEqual(n, 96)
        w.sign(slot)
        w.login()


class TestNoncePool(unittest.TestCase):
    """Concern 1: several apps can wait for phone approval at the same time."""

    def setUp(self):
        self.w = World()
        self.slot, self.pub, _ = self.w.setup_ready()

    def test_concurrent_login_and_signatures(self):
        w = self.w
        n_sign1, n_login, n_sign2 = w.nonce(), w.nonce(), w.nonce()
        w.tok.ok(w.sign_apdu(n_sign2, q.sha256(b"b"), self.slot))
        w.tok.ok(w.login_apdu(n_login))
        w.tok.ok(w.sign_apdu(n_sign1, q.sha256(b"a"), self.slot))
        self.assertEqual(w.tok.sw(w.sign_apdu(n_sign1, q.sha256(b"a"), self.slot)), 0x6984)

    def test_fifth_nonce_evicts_oldest(self):
        w = self.w
        ns = [w.nonce() for _ in range(5)]
        self.assertEqual(w.tok.sw(w.sign_apdu(ns[0], q.sha256(b"d"), self.slot)), 0x6984)
        for n in ns[1:]:
            w.tok.ok(w.sign_apdu(n, q.sha256(b"d"), self.slot))

    def test_failures_count_per_nonce(self):
        w = self.w
        n1, n2 = w.nonce(), w.nonce()
        for _ in range(3):
            self.assertEqual(w.tok.sw(w.sign_apdu(n1, q.sha256(b"d"), self.slot,
                                                  signer=w.cmd)), 0x6982)
        self.assertEqual(w.tok.sw(w.sign_apdu(n1, q.sha256(b"d"), self.slot)), 0x6984)
        w.tok.ok(w.sign_apdu(n2, q.sha256(b"d"), self.slot))

    def test_each_nonce_expires(self):
        w = self.w
        n1 = w.nonce()
        LIB.sim_advance_ms(400_000)
        n2 = w.nonce()
        LIB.sim_advance_ms(300_000)
        self.assertEqual(w.tok.sw(w.sign_apdu(n1, q.sha256(b"d"), self.slot)), 0x6984)
        w.tok.ok(w.sign_apdu(n2, q.sha256(b"d"), self.slot))

    def test_logout_keeps_nonces_reset_and_rebind_drop_them(self):
        w = self.w
        n = w.nonce()
        w.tok.raw(q.apdu("LOGOUT"))
        w.tok.ok(w.sign_apdu(n, q.sha256(b"d"), self.slot))
        n = w.nonce()
        w.replug()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot)), 0x6984)
        n = w.nonce()
        new = new_key()
        st = q.stmt_build("REBIND", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1,
                          NEW_KEY_HASH=q.sha256(q.pub_bytes(new)), METHOD=1)
        w.tok.ok(q.apdu("REBIND", q.tlv(F["ACTIVATION_PUB"], q.pub_bytes(new)) +
                        q.signed(st, w.phone)))
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot, signer=new)), 0x6984)


class TestCsrDigestMode(unittest.TestCase):
    """Concern 2: CA tools that hand the token only a hash (CNG, CKM_ECDSA)."""

    def setUp(self):
        self.w = World()
        self.w.factory()
        self.w.pair()

    def digest_apdu(self, slot, data=b"x"):
        return q.apdu("SIGN_CSR", q.tlv(T["CSR_DIGEST"], q.sha256(data)), p1=slot, p2=1)

    def test_digest_mode_issues_dsc(self):
        w = self.w
        slot, pub, cert = w.issue_dsc(digest_mode=True)
        self.assertEqual(w.tok.lc, LC["READY"])
        w.sign(slot)

    def test_digest_mode_is_the_keys_only_signature(self):
        w = self.w
        slot, pub = w.keygen()
        w.tok.ok(self.digest_apdu(slot, b"first"))
        self.assertEqual(w.tok.sw(self.digest_apdu(slot, b"second")), 0x6986)
        cri = q.build_cri(name("S").public_bytes(), pub)
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CRI"], cri), p1=slot)), 0x6986)

    def test_no_digest_after_full_request(self):
        """Otherwise: honest CSR gets certified, then the PC gets a document hash signed."""
        w = self.w
        slot, pub = w.keygen()
        w.csr(slot, pub)
        w.csr(slot, pub)                       # full mode stays repeatable (CA retry)
        self.assertEqual(w.tok.sw(self.digest_apdu(slot)), 0x6986)

    def test_digest_mode_checks(self):
        w = self.w
        slot, _ = w.keygen()
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CSR_DIGEST"], bytes(31)),
                                         p1=slot, p2=1)), 0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CSR_DIGEST"], bytes(32)),
                                         p1=slot, p2=2)), 0x6A86)
        self.assertEqual(w.tok.sw(self.digest_apdu(slot + 1)), 0x6986, "empty slot")

    def test_legacy_slot_refuses_digest_mode(self):
        """A key generated by firmware 0.3/0.4 may already have signed a CSR."""
        w = self.w
        slot, pub = w.keygen()
        point = pub[-65:]
        legacy = bytes([1]) + struct.pack(">I", 1) + point
        self.assertEqual(len(legacy), 70)
        LIB.sim_nvs_put(0x0110 + slot, legacy, len(legacy))
        # Firmware 0.6 moves the 0.4 record into the SE052F at boot.
        self.assertEqual(w.tok.boot(), 0)
        w.tok.select()
        self.assertEqual(LIB.sim_nvs_count(), 0)
        self.assertEqual(w.tok.sw(self.digest_apdu(slot)), 0x6986)
        w.csr(slot, pub)
        self.assertEqual(w.write_cert(slot, make_cert(pub, w.ca)), q.SW_OK)


class TestRsa(unittest.TestCase):
    """Concern 3: RSA-2048 DSC keys, as most Indian CAs and portals expect."""

    @classmethod
    def setUpClass(cls):
        w = World(seed=77)
        w.factory()
        w.pair()
        cls.w = w
        cls.slot, cls.pub = w.keygen(alg="RSA2048")

    def test_1_keygen_attests_rsa_spki(self):
        w = self.w
        self.assertTrue(q.is_rsa(self.pub))
        self.assertEqual(len(self.pub), 294)
        self.assertEqual(q.load_spki(self.pub).key_size, 2048)
        self.assertEqual(q.load_spki(self.pub).public_numbers().e, 65537)
        info = [v for t, v in q.tlv_parse(w.tok.raw(q.apdu("GET_INFO"))[0])
                if t == T["SLOT_ENTRY"]]
        self.assertEqual(info[self.slot][2], q.ALG["RSA2048"])

    def test_2_csr_full_mode_and_cert_checks(self):
        w = self.w
        csr = x509.load_der_x509_csr(w.csr(self.slot, self.pub))
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(w.write_cert(self.slot, make_cert(q.pub_bytes(new_key()), w.ca)),
                         0x6A80, "P-256 certificate on an RSA slot")
        other = q.spki_of(rsa.generate_private_key(65537, 2048))
        self.assertEqual(w.write_cert(self.slot, make_cert(other, w.ca)), 0x6A80)
        self.assertEqual(w.write_cert(self.slot, make_cert(self.pub, w.ca)), q.SW_OK)
        self.assertEqual(w.tok.lc, LC["READY"])

    def test_3_rsa_signature_and_receipt(self):
        w = self.w
        h_tbs, n, sig, rec = w.sign(self.slot)
        self.assertEqual(len(sig), 256)
        self.assertTrue(q.verify_dsc(self.pub, sig, h_tbs))
        self.assertFalse(q.verify_dsc(self.pub, sig, q.sha256(b"other")))
        self.assertEqual(rec["SIG_HASH"], q.sha256(sig))

    def test_4_rsa_digest_mode_csr(self):
        w = self.w
        slot, pub = w.keygen(alg="RSA2048")
        csr = x509.load_der_x509_csr(w.csr(slot, pub, digest_mode=True))
        self.assertTrue(csr.is_signature_valid)

    def test_5_bad_algorithm(self):
        w = self.w
        a = w.consent_apdu()
        self.assertEqual(w.tok.sw(a[:2] + b"\x02" + a[3:]), 0x6A86)


class TestFirmwareUpdate(unittest.TestCase):
    """Concern 4: update over the normal token interface, no second USB device."""

    def setUp(self):
        self.w = World()
        self.w.setup_ready()

    def image(self, ver=(0, 7, 0), size=5000):
        body = bytes((i * 7) & 0xFF for i in range(size - 32))
        return q.mcuboot_header(*ver) + body

    def begin(self, img, sha=None):
        return self.w.tok.sw(q.apdu("UPDATE_BEGIN",
                                    q.tlv(T["IMAGE_SIZE"], struct.pack(">I", len(img))) +
                                    q.tlv(T["IMAGE_SHA256"], sha or q.sha256(img))))

    def write(self, img, off, n):
        return self.w.tok.sw(q.apdu("UPDATE_WRITE",
                                    q.tlv(T["IMAGE_OFFSET"], struct.pack(">I", off)) +
                                    q.tlv(T["CHUNK"], img[off:off + n])))

    def send(self, img, chunk=1024):
        for off in range(0, len(img), chunk):
            sw = self.write(img, off, chunk)
            if sw != q.SW_OK:
                return sw
        return self.w.tok.sw(q.apdu("UPDATE_FINISH"))

    def test_update_happy_path(self):
        img = self.image((0, 7, 1))
        before = LIB.sim_event_count(EVT_UPDATE_REBOOT)
        self.assertEqual(self.begin(img), q.SW_OK)
        self.assertEqual(self.send(img), q.SW_OK)
        self.assertEqual(LIB.sim_fw_pending(), 1)
        self.assertEqual(LIB.sim_event_count(EVT_UPDATE_REBOOT), before + 1)

    def test_same_version_reinstall_allowed(self):
        img = self.image((0, 7, 0))
        self.assertEqual(self.begin(img), q.SW_OK)
        self.assertEqual(self.send(img), q.SW_OK)

    def test_downgrade_and_bad_image_refused_early(self):
        for img in (self.image((0, 6, 5)), b"\x00" * 32 + self.image()[32:]):
            self.assertEqual(self.begin(img), q.SW_OK)
            self.assertEqual(self.write(img, 0, 1024), 0x6A80)
            self.assertEqual(self.write(img, 0, 1024), 0x6985, "update abandoned")
        self.assertEqual(LIB.sim_fw_pending(), 0)

    def test_hash_mismatch_installs_nothing(self):
        img = self.image()
        self.assertEqual(self.begin(img, sha=q.sha256(b"something else")), q.SW_OK)
        self.assertEqual(self.send(img), 0x6A80)
        self.assertEqual(LIB.sim_fw_pending(), 0)

    def test_order_size_and_completion_checks(self):
        img = self.image()
        self.assertEqual(self.begin(img), q.SW_OK)
        self.assertEqual(self.write(img, 1024, 1024), 0x6A80, "out of order")
        self.assertEqual(self.write(img, 0, 1024), q.SW_OK)
        self.assertEqual(self.w.tok.sw(q.apdu("UPDATE_FINISH")), 0x6985, "incomplete")
        self.assertEqual(self.begin(b"\x00" * (700 * 1024)), 0x6A80, "larger than slot")

    def test_unplug_aborts(self):
        img = self.image()
        self.assertEqual(self.begin(img), q.SW_OK)
        self.assertEqual(self.write(img, 0, 1024), q.SW_OK)
        self.w.replug()
        self.w.login()
        self.assertEqual(self.write(img, 1024, 1024), 0x6985)

    def test_lifecycle_and_login_rules(self):
        img = self.image()
        self.w.replug()
        self.assertEqual(self.begin(img), 0x6983, "logged out")
        self.w.login()
        self.assertEqual(self.begin(img), q.SW_OK)
        w = World()
        self.assertEqual(w.tok.sw(q.apdu("UPDATE_BEGIN",
                                         q.tlv(T["IMAGE_SIZE"], struct.pack(">I", 5000)) +
                                         q.tlv(T["IMAGE_SHA256"], bytes(32)))), 0x6985,
                         "factory loads firmware over SWD")

    def test_built_without_update(self):
        """CONFIG_QDSD_FW_UPDATE=n (bring-up build without MCUboot): the
        update commands are refused with 6D00 and everything else works."""
        img = self.image()
        LIB.sim_fw_none(1)
        try:
            self.assertEqual(self.begin(img), 0x6D00)
            self.assertEqual(self.write(img, 0, 1024), 0x6D00)
            self.assertEqual(self.w.tok.sw(q.apdu("UPDATE_FINISH")), 0x6D00)
            self.assertEqual(LIB.sim_fw_pending(), 0)
            slot, pub = self.w.keygen()
            self.assertIsNotNone(pub)
        finally:
            LIB.sim_fw_none(0)
        self.assertEqual(self.begin(img), q.SW_OK, "same token, update build")


class TestPhoneChange(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.slot, self.pub, _ = self.w.setup_ready()

    def rebind_apdu(self, new, signer=None, binding=None, key_hash=None, method=M["BIOMETRIC"]):
        w = self.w
        st = q.stmt_build("REBIND", DEVICE_ID=w.device_id,
                          BINDING_NO=w.binding_no() + 1 if binding is None else binding,
                          NEW_KEY_HASH=key_hash or q.sha256(q.pub_bytes(new)), METHOD=method)
        return q.apdu("REBIND", q.tlv(F["ACTIVATION_PUB"], q.pub_bytes(new)) +
                      q.signed(st, signer or w.phone, der=True))

    def test_planned_phone_change_keeps_dsc(self):
        w = self.w
        new_phone = new_key()
        self.assertEqual(w.tok.sw(self.rebind_apdu(new_phone, signer=new_phone)), 0x6982)
        self.assertEqual(w.tok.sw(self.rebind_apdu(new_phone, key_hash=b"\x00" * 32)), 0x6A80)
        a = self.rebind_apdu(new_phone)
        rec = q.open_signed(w.tok.ok(a), w.device_pub, "REBIND_RECEIPT")
        self.assertEqual(rec["BINDING_NO"], 2)
        self.assertEqual(w.tok.sw(a), 0x6984, "REBIND replay must fail")
        # Old phone can no longer approve; new phone can, with the same DSC.
        n = w.nonce()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"d"), self.slot)), 0x6982)
        w.sign(self.slot, phone=new_phone)
        self.assertEqual(w.tok.lc, LC["READY"])

    def test_lost_phone_reset_erases_everything(self):
        w = self.w
        reset = q.apdu("RESET", q.signed(
            q.stmt_build("RESET", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1), w.cmd))
        stale_bind = w.bind_apdu(binding=1)
        rec = q.open_signed(w.tok.ok(reset), w.device_pub, "RESET_RECEIPT")
        self.assertEqual((rec["STATE"], rec["BINDING_NO"]), (LC["UNASSIGNED"], 2))
        self.assertEqual(w.tok.lc, LC["UNASSIGNED"])
        self.assertFalse(any(LIB.sim_dsc_present(i) for i in range(SLOTS)))
        self.assertEqual(w.tok.sw(reset), 0x6985)
        self.assertEqual(w.tok.sw(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\0\0"))), 0x6985)
        # The original BIND (binding 1) cannot be replayed; a fresh one (3) works.
        self.assertEqual(w.tok.sw(stale_bind), 0x6984)
        w.phone = new_key()
        self.assertEqual(w.pair()["BINDING_NO"], 3)
        st = q.open_signed(w.tok.ok(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"z" * 16))),
                           w.device_pub, "ATTEST")
        self.assertEqual(st["SIGN_COUNTER"], 0)  # never signed in this test
        w.issue_dsc()
        w.sign(0)

    def test_reset_needs_cloud_key(self):
        w = self.w
        st = q.stmt_build("RESET", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1)
        self.assertEqual(w.tok.sw(q.apdu("RESET", q.signed(st, w.phone))), 0x6982)
        self.assertEqual(w.tok.lc, LC["READY"])


class TestPowerLoss(unittest.TestCase):
    """Cut power after every possible persistent write and check recovery."""

    def _cut_and_recover(self, prepare, command, check_old, check_new, max_writes=40):
        saw_old = saw_new = False
        for budget in range(max_writes):
            w = World(seed=budget + 11)
            ctx = prepare(w)
            a = command(w, ctx)
            LIB.sim_set_power_budget(budget)
            w.tok.raw(a)
            completed = not LIB.sim_powered_off()
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0, f"boot failed after cut at write {budget}")
            w.tok.select()
            if check_new(w, ctx):
                saw_new = True
            else:
                self.assertTrue(check_old(w, ctx), f"inconsistent after cut at {budget}")
                saw_old = True
            if completed:
                break
        self.assertTrue(saw_old and saw_new)

    def test_bind(self):
        def prep(w):
            w.factory()

        self._cut_and_recover(
            prep, lambda w, c: w.bind_apdu(),
            check_old=lambda w, c: w.tok.lc == LC["UNASSIGNED"] and w.binding_no() == 0,
            check_new=lambda w, c: w.tok.lc == LC["BOUND"] and w.binding_no() == 1)

    def test_rebind(self):
        def prep(w):
            w.setup_ready()
            return new_key()

        def cmd(w, new):
            st = q.stmt_build("REBIND", DEVICE_ID=w.device_id, BINDING_NO=2,
                              NEW_KEY_HASH=q.sha256(q.pub_bytes(new)), METHOD=1)
            return q.apdu("REBIND", q.tlv(F["ACTIVATION_PUB"], q.pub_bytes(new)) +
                          q.signed(st, w.phone))

        def is_new(w, new):
            if w.binding_no() != 2:
                return False
            w.sign(0, phone=new)
            return True

        def is_old(w, new):
            w.sign(0)
            return w.binding_no() == 1

        self._cut_and_recover(prep, cmd, is_old, is_new)

    def test_reset(self):
        def prep(w):
            w.setup_ready()
            w.issue_dsc()

        def cmd(w, _):
            st = q.stmt_build("RESET", DEVICE_ID=w.device_id, BINDING_NO=2)
            return q.apdu("RESET", q.signed(st, w.cmd))

        def is_new(w, _):
            return (w.tok.lc == LC["UNASSIGNED"] and w.binding_no() == 2 and
                    not any(LIB.sim_dsc_present(i) for i in range(SLOTS)))

        def is_old(w, _):
            return w.tok.lc == LC["READY"] and w.binding_no() == 1 and LIB.sim_dsc_present(0)

        self._cut_and_recover(prep, cmd, is_old, is_new)

    def test_policy(self):
        def prep(w):
            w.setup_ready()

        def cmd(w, _):
            return w.policy_apdu(0, policy_no=1)

        def is_new(w, _):
            a = w.attest()
            return (a["POLICY_NO"], a["POLICY_FLAGS"]) == (1, 0) and w.session() == 1

        def is_old(w, _):
            a = w.attest()
            return (a["POLICY_NO"], a["POLICY_FLAGS"]) == (0, LOGIN_REQ) and w.session() == 0

        self._cut_and_recover(prep, cmd, is_old, is_new)

    def test_sign_and_keygen_never_replayable(self):
        for budget in range(4):
            w = World(seed=50 + budget)
            slot, _, _ = w.setup_ready()
            n = w.nonce()
            a = w.sign_apdu(n, q.sha256(b"doc"), slot)
            LIB.sim_set_power_budget(budget)
            w.tok.raw(a)
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            self.assertEqual(w.tok.sw(a), 0x6984)  # nonce gone after reboot
            w.sign(slot)

            ka = w.consent_apdu()
            LIB.sim_set_power_budget(budget)
            w.tok.raw(ka)
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            sw = w.tok.sw(ka)
            self.assertIn(sw, (0x6984, q.SW_OK))
            if LIB.sim_counter(CTR_KEYGEN) >= 2:
                self.assertEqual(w.tok.sw(ka), 0x6984)


class TestMisc(unittest.TestCase):
    def test_crypto_selftest(self):
        Token()
        self.assertEqual(LIB.qdsd_crypto_selftest(), 0)

    def test_get_info_ready(self):
        w = World()
        slot, _, _ = w.setup_ready()
        info = w.tok.info()
        self.assertEqual(info[F["STATE"]], bytes([LC["READY"]]))
        self.assertEqual(info[F["DEVICE_ID"]], w.device_id)
        entries = [v for t, v in q.tlv_parse(w.tok.raw(q.apdu("GET_INFO"))[0])
                   if t == T["SLOT_ENTRY"]]
        self.assertEqual(entries[slot][:3], bytes([slot, 2, q.ALG["P256"]]))
        self.assertEqual(entries[slot][7], 1)

    def test_corrupt_state_is_fault(self):
        w = World()
        w.setup_ready()
        LIB.sim_corrupt_state()
        self.assertNotEqual(w.tok.boot(), 0)
        self.assertEqual(w.tok.lc, LC["FAULT"])
        w.tok.select()
        self.assertEqual(w.tok.info()[F["STATE"]], bytes([LC["FAULT"]]))
        self.assertEqual(w.tok.sw(q.apdu("GET_SESSION_NONCE")), 0x6F00)
        self.assertEqual(w.tok.sw(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"c" * 16))), 0x6F00)


if __name__ == "__main__":
    unittest.main()
