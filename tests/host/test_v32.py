"""Protocol v3.2 tests: the review points batched into firmware 0.6.

  1. Signing receipts kept on the token (GET_RECEIPT), power-loss safe.
  2. (CCID transport: test_ccid.py)
  3. Certificates and slot records inside the secure elements, not MCU flash;
     migration of tokens made by firmware 0.3-0.5.
  4. Separate DSC key attestation (SE052F) from device attestation (SE050).
  5. Factory reset of both secure elements (FACTORY_WIPE).
  6. Custom object ids / UserIDs: the FACTORY_RESET UserID objects.
  7. Phone and cloud signatures checked inside the SE050.
  8. User certificates: upload, retrieve, delete (revocation is at the CA).
  9. Institutional certificates imported from .pfx.
"""
import struct
import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import qdsd_proto as q
from qdsd_proto import F, T, LC
from test_flows import LIB, M, LOGIN_REQ, World, make_cert, new_key, name

import ctypes

LIB.sim_obj_get.restype = ctypes.c_long
LIB.sim_obj_get.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
LIB.sim_obj_put.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
LIB.sim_obj_flip.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
LIB.sim_nvs_put.argtypes = [ctypes.c_uint16, ctypes.c_char_p, ctypes.c_size_t]
LIB.sim_dsc_att_pub.argtypes = [ctypes.c_char_p]

OBJ_DEVICE_CERT, OBJ_RECEIPT, OBJ_SLOT_REC, OBJ_SLOT_CERT = 0, 1, 2, 3
SE_DEV, SE_DSC = 0, 1
RING = 16
ST = q.RCPT_STATUS
ORIGIN = q.ORIGIN


def obj(kind, idx=0):
    buf = ctypes.create_string_buffer(4096)
    n = LIB.sim_obj_get(kind, idx, buf, 4096)
    return None if n < 0 else buf.raw[:n]


def slots(info_rsp_raw):
    """Slot entries (tag 20, 9 bytes in v3.2) from a raw GET_INFO body."""
    out = {}
    for tag, val in q.tlv_parse(info_rsp_raw):
        if tag == T["SLOT_ENTRY"]:
            out[val[0]] = dict(status=val[1], alg=val[2], seq=struct.unpack(">I", val[3:7])[0],
                               has_cert=val[7], origin=val[8])
    return out


class V32World(World):
    """World plus the v3.2 commands."""

    def factory(self):
        rec = super().factory()
        return rec

    @property
    def chip_uid(self):
        # FACTORY_INIT reported it; the model derives it from the seed.
        return bytes((0xC0 + i + 1) & 0xFF for i in range(18))

    def info_slots(self):
        data, sw = self.tok.raw(q.apdu("GET_INFO"))
        assert sw == q.SW_OK
        return slots(data)

    def sign_ctr(self):
        return self.attest()["SIGN_COUNTER"]

    def get_receipt(self, ctr=None):
        body = b"" if ctr is None else q.tlv(F["SIGN_COUNTER"], struct.pack(">I", ctr))
        return self.tok.raw(q.apdu("GET_RECEIPT", body))

    def delete_apdu(self, slot, seq, signer=None, slot_in_stmt=None):
        st = q.stmt_build("DELETE_KEY", DEVICE_ID=self.device_id, TIME=1_790_000_000_000,
                          KEYGEN_SEQ=seq,
                          KEY_SLOT=slot if slot_in_stmt is None else slot_in_stmt,
                          METHOD=M["BIOMETRIC"])
        return q.apdu("DELETE_KEY", q.signed(st, signer or self.phone, der=True), p1=slot)

    def slot_seq(self, slot):
        return self.info_slots()[slot]["seq"]

    def key_attestation(self, slot, challenge=b"K" * 24):
        r = self.tok.ok(q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], challenge), p1=slot))
        return r, q.open_signed(r, self.device_pub, "KEY_STATUS")

    def wipe_apdu(self, dev=None, dsc=None, stmt=True, binding=None, signer=None,
                  device_id=None):
        body = (q.tlv(T["WIPE_SECRET_DEV"], dev or self.WIPE_DEV) +
                q.tlv(T["WIPE_SECRET_DSC"], dsc or self.WIPE_DSC))
        if stmt:
            st = q.stmt_build("WIPE", DEVICE_ID=device_id or self.device_id,
                              BINDING_NO=self.binding_no() if binding is None else binding)
            body = q.signed(st, signer or self.cmd) + body
        return q.apdu("FACTORY_WIPE", body)

    # .pfx import
    def import_consent_apdu(self, cert, alg, seq=None, signer=None):
        st = q.stmt_build("IMPORT_CONSENT", DEVICE_ID=self.device_id,
                          KEYGEN_SEQ=self.keygen_ctr() + 1 if seq is None else seq,
                          VALID_UNTIL=1_800_000_000_000, METHOD=M["BIOMETRIC"],
                          CERT_HASH=q.sha256(cert), KEY_ALG=q.ALG[alg])
        return q.apdu("IMPORT_BEGIN", q.signed(st, signer or self.phone, der=True))

    def import_begin(self, cert, alg):
        r = self.tok.ok(self.import_consent_apdu(cert, alg))
        return q.open_signed(r, self.device_pub, "IMPORT_OFFER")

    def import_send(self, package, chunk=700):
        last = None
        for a in q.chunked("IMPORT_DATA", package, chunk):
            last = self.tok.raw(a)
            if last[1] != q.SW_OK:
                return last
        return last

    def import_pfx(self, key, cert, alg):
        offer = self.import_begin(cert, alg)
        pkg = q.import_wrap(offer, self.device_id, key, cert)
        data, sw = self.import_send(pkg)
        assert sw == q.SW_OK, hex(sw)
        r = q.tlv_dict(data)
        att = q.open_signed(r, self.device_pub, "KEY_ATTEST")
        self.seqs[r[F["KEY_SLOT"]][0]] = att["KEYGEN_SEQ"]
        return r[F["KEY_SLOT"]][0], att


def institutional(alg="P256"):
    """An institutional key + certificate as a CA would put them in a .pfx."""
    ca = new_key()
    key = (ec.generate_private_key(ec.SECP256R1()) if alg == "P256"
           else rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return key, make_cert(q.spki_of(key), ca, "DTI Institution Signer"), ca


# ═════════════════════════════════════════════════════════════════════
# 1. Signing receipts kept on the token

class TestReceipts(unittest.TestCase):
    def setUp(self):
        self.w = V32World()
        self.slot, self.pub, _ = self.w.setup_ready()

    def test_lost_reply_recovered(self):
        w = self.w
        h, _, sig, rec = w.sign(self.slot)
        # The middleware lost the reply: fetch it again by counter, or latest.
        for ctr in (rec["SIGN_COUNTER"], None):
            data, sw = w.get_receipt(ctr)
            self.assertEqual(sw, q.SW_OK)
            r = q.tlv_dict(data)
            again = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
            self.assertEqual(again.raw, rec.raw)
            self.assertEqual(r[T["DSC_SIG_RAW"]], sig)
            self.assertTrue(q.verify_dsc(self.pub, sig, h))
            self.assertEqual(again["STATUS"], ST["OK"])
            self.assertEqual(again["SIG_HASH"], q.sha256(sig))
            self.assertEqual(again["KEY_ORIGIN"], ORIGIN["GENERATED"])

    def test_lookup_by_request_id(self):
        """Lost reply (nonce status 05): find the receipt by the cloud's request id,
        even after other signatures were made in between."""
        w = self.w
        rid = bytes(range(100, 116))
        n = w.nonce()
        h = q.sha256(b"the lost one")
        a = w.sign_apdu(n, h, self.slot, rid=rid)
        w.tok.ok(a)                                   # reply lost on the way back
        for i in range(5):                            # other apps keep signing
            w.sign(self.slot, h_tbs=q.sha256(bytes([i])))
        data, sw = w.tok.raw(a)                       # agent retries
        self.assertEqual(sw, 0x6984)
        self.assertEqual(q.tlv_dict(data)[T["NONCE_STATUS"]], bytes([q.NONCE_WHY["USED"]]))
        w.replug()                                    # also works logged out
        data, sw = w.tok.raw(q.apdu("GET_RECEIPT", q.tlv(F["REQUEST_ID"], rid)))
        self.assertEqual(sw, q.SW_OK)
        r = q.tlv_dict(data)
        rec = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
        self.assertEqual((rec["REQUEST_ID"], rec["H_TBS"]), (rid, h))
        self.assertTrue(q.verify_dsc(self.pub, r[T["DSC_SIG_RAW"]], h))

    def test_lookup_by_request_id_details(self):
        w = self.w
        rid = b"R" * 16
        w.sign(self.slot)
        first = w.tok.ok(w.sign_apdu(w.nonce(), q.sha256(b"a"), self.slot, rid=rid))
        second = w.tok.ok(w.sign_apdu(w.nonce(), q.sha256(b"b"), self.slot, rid=rid))
        r = w.tok.ok(q.apdu("GET_RECEIPT", q.tlv(F["REQUEST_ID"], rid)))
        self.assertEqual(r[T["STMT"]], second[T["STMT"]], "same id twice: the newest")
        self.assertNotEqual(r[T["STMT"]], first[T["STMT"]])
        self.assertEqual(w.tok.sw(q.apdu("GET_RECEIPT", q.tlv(F["REQUEST_ID"], b"?" * 16))),
                         0x6A88)
        self.assertEqual(w.tok.sw(q.apdu("GET_RECEIPT", q.tlv(F["REQUEST_ID"], b"?" * 15))),
                         0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("GET_RECEIPT", q.tlv(F["SIGN_COUNTER"], b"\0\0\0\1") +
                                         q.tlv(F["REQUEST_ID"], rid))), 0x6A80, "one selector")
        # Pushed out of the ring: gone.
        for i in range(16):
            w.sign(self.slot, h_tbs=q.sha256(bytes([i, 1])))
        self.assertEqual(w.tok.sw(q.apdu("GET_RECEIPT", q.tlv(F["REQUEST_ID"], rid))), 0x6A88)

    def test_allowed_while_logged_out(self):
        w = self.w
        _, _, _, rec = w.sign(self.slot)
        w.replug()
        self.assertEqual(w.session(), 0)
        data, sw = w.get_receipt(rec["SIGN_COUNTER"])
        self.assertEqual(sw, q.SW_OK)

    def test_unknown_and_bad_requests(self):
        w = self.w
        self.assertEqual(w.get_receipt()[1], 0x6A88, "no signature yet")
        self.assertEqual(w.get_receipt(0)[1], 0x6A88)
        self.assertEqual(w.get_receipt(5)[1], 0x6A88, "never made")
        self.assertEqual(w.tok.sw(q.apdu("GET_RECEIPT", q.tlv(F["SIGN_COUNTER"], b"\x01"))),
                         0x6A80)

    def test_ring_keeps_last_sixteen(self):
        w = self.w
        recs = [w.sign(self.slot)[3] for _ in range(RING + 1)]
        self.assertEqual(w.get_receipt(recs[0]["SIGN_COUNTER"])[1], 0x6A88, "overwritten")
        for r in recs[1:]:
            data, sw = w.get_receipt(r["SIGN_COUNTER"])
            self.assertEqual(sw, q.SW_OK)
            self.assertEqual(q.open_signed(q.tlv_dict(data), w.device_pub,
                                           "SIGN_RECEIPT").raw, r.raw)

    def test_se_failure_receipt_saved(self):
        w = self.w
        n = w.nonce()
        LIB.sim_fail_dsc_sign(1)
        data, sw = w.tok.raw(w.sign_apdu(n, q.sha256(b"doc"), self.slot))
        LIB.sim_fail_dsc_sign(0)
        self.assertEqual(sw, 0x6F00)
        r = q.tlv_dict(data)
        rec = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
        self.assertEqual(rec["STATUS"], ST["SE_FAILED"])
        self.assertNotIn(T["DSC_SIG_RAW"], r)
        data, sw = w.get_receipt(rec["SIGN_COUNTER"])
        self.assertEqual(q.open_signed(q.tlv_dict(data), w.device_pub,
                                       "SIGN_RECEIPT")["STATUS"], ST["SE_FAILED"])

    def test_reset_forgets_receipts(self):
        w = self.w
        w.sign(self.slot)
        st = q.stmt_build("RESET", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1)
        w.tok.ok(q.apdu("RESET", q.signed(st, w.cmd)))
        w.phone = new_key()
        w.pair()
        self.assertEqual(w.get_receipt()[1], 0x6A88,
                         "the new Subscriber does not see the old one's receipts")

    def test_power_cut_at_every_write_of_sign(self):
        """Never a DSC signature without a saved receipt; every gap is explained."""
        base = V32World()
        base.setup_ready()
        before = LIB.sim_write_count()
        base.sign(0)
        n_writes = LIB.sim_write_count() - before
        self.assertGreaterEqual(n_writes, 4)
        for cut in range(n_writes + 1):
            w = V32World()
            slot, pub, _ = w.setup_ready()
            ctr0 = w.sign_ctr()
            n = w.nonce()
            h = q.sha256(b"doc %d" % cut)
            LIB.sim_set_power_budget(cut)
            data, sw = w.tok.raw(w.sign_apdu(n, h, slot))
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0, f"cut {cut}")
            w.tok.select()
            ctr = w.sign_ctr()
            if sw == q.SW_OK:
                self.assertEqual(cut, n_writes)
            if ctr == ctr0:
                self.assertEqual(cut, 0)
                continue
            self.assertEqual(ctr, ctr0 + 1)
            data2, sw2 = w.get_receipt(ctr)
            if sw2 == 0x6A88:
                # Counted but cut before the pending receipt landed: a visible gap.
                self.assertEqual(cut, 1, f"cut {cut}")
                continue
            r = q.tlv_dict(data2)
            rec = q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
            self.assertEqual(rec["H_TBS"], h)
            if sw == q.SW_OK:
                self.assertEqual(rec["STATUS"], ST["OK"])
                self.assertTrue(q.verify_dsc(pub, r[T["DSC_SIG_RAW"]], h))
            else:
                self.assertEqual(rec["STATUS"], ST["INTERRUPTED"], f"cut {cut}")
                self.assertNotIn(T["DSC_SIG_RAW"], r)
                self.assertEqual(rec["SIG_HASH"], bytes(32))
            # The token keeps signing afterwards.
            w.sign(slot)


# ═════════════════════════════════════════════════════════════════════
# 3. Records inside the secure elements

class TestStorageInSecureElements(unittest.TestCase):
    def test_nothing_in_mcu_flash(self):
        w = V32World()
        slot, pub, cert = w.setup_ready()
        w.sign(slot)
        self.assertEqual(LIB.sim_nvs_count(), 0)
        self.assertEqual(obj(OBJ_DEVICE_CERT), w.device_cert)
        self.assertEqual(obj(OBJ_SLOT_CERT, slot), cert)
        self.assertIsNotNone(obj(OBJ_SLOT_REC, slot))
        self.assertIsNotNone(obj(OBJ_RECEIPT, 1))
        r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
        self.assertEqual(r[T["CHUNK"]], cert)

    def test_torn_certificate_not_served(self):
        """A certificate that does not match its slot record's hash is not used."""
        w = V32World()
        slot, _, _ = w.setup_ready()
        LIB.sim_obj_flip(OBJ_SLOT_CERT, slot, 40)
        self.assertEqual(w.tok.sw(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"),
                                         p1=slot)), 0x6A88)

    def test_power_cut_during_certificate_write(self):
        """Old certificate or new one, never half of one."""
        probe = V32World()
        probe.factory(); probe.pair()
        s, p = probe.keygen()
        cert = make_cert(p, probe.ca)
        before = LIB.sim_write_count()
        probe.write_cert(s, cert)
        n_writes = LIB.sim_write_count() - before
        for cut in range(n_writes + 1):
            w = V32World()
            w.factory(); w.pair()
            slot, pub = w.keygen()
            cert = make_cert(pub, w.ca)
            LIB.sim_set_power_budget(cut)
            sw = w.write_cert(slot, cert)
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            data, sw2 = w.tok.raw(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
            if sw2 == q.SW_OK:
                self.assertEqual(q.tlv_dict(data)[T["CHUNK"]], cert)
                self.assertEqual(w.tok.lc, LC["READY"])
            else:
                self.assertEqual(sw2, 0x6A88, f"cut {cut}")
                self.assertNotEqual(sw, q.SW_OK)
                self.assertEqual(w.write_cert(slot, cert), q.SW_OK, "retry works")

    def _make_legacy(self, w, slot, pub, cert):
        """Turn a 0.6 token into what firmware 0.5 left: records in MCU flash."""
        spki = q.spki_of(pub)
        meta = b"S" + bytes([2, 0, 1]) + struct.pack(">I", w.slot_seq(slot)) + \
            struct.pack(">H", len(spki)) + spki
        LIB.sim_nvs_put(0x0100, w.device_cert, len(w.device_cert))
        LIB.sim_nvs_put(0x0110 + slot, meta, len(meta))
        LIB.sim_nvs_put(0x0120 + slot, cert, len(cert))
        LIB.sim_obj_del(OBJ_DEVICE_CERT, 0)
        for i in range(4):
            LIB.sim_obj_del(OBJ_SLOT_REC, i)
            LIB.sim_obj_del(OBJ_SLOT_CERT, i)
        for i in range(RING):
            LIB.sim_obj_del(OBJ_RECEIPT, i)

    def test_migration_from_firmware_05(self):
        w = V32World()
        slot, pub, cert = w.setup_ready()
        self._make_legacy(w, slot, pub, cert)
        self.assertEqual(w.tok.boot(), 0)
        w.tok.select()
        self.assertEqual(LIB.sim_nvs_count(), 0, "flash copies removed")
        self.assertEqual(obj(OBJ_DEVICE_CERT), w.device_cert)
        self.assertEqual(obj(OBJ_SLOT_CERT, slot), cert)
        self.assertNotIn(T["SLOT_ENTRY"], w.tok.info(), "hidden while logged out")
        w.login()
        self.assertEqual(w.info_slots()[slot]["status"], q.SLOT_STATUS["CERTIFIED"])
        h, _, sig, rec = w.sign(slot)
        self.assertTrue(q.verify_dsc(pub, sig, h))
        self.assertEqual(w.get_receipt(rec["SIGN_COUNTER"])[1], q.SW_OK, "ring created")

    def test_migration_survives_power_cuts(self):
        for cut in range(0, 40, 3):
            w = V32World()
            slot, pub, cert = w.setup_ready()
            self._make_legacy(w, slot, pub, cert)
            LIB.sim_set_power_budget(cut)
            w.tok.boot()
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0, f"cut {cut}")
            w.tok.select()
            self.assertEqual(LIB.sim_nvs_count(), 0)
            self.assertEqual(obj(OBJ_SLOT_CERT, slot), cert)
            w.login()
            w.sign(slot)

    def test_curve_created_after_wipe(self):
        w = V32World()
        w.factory()
        w.tok.ok(w.wipe_apdu(stmt=False if w.tok.lc == LC["MANUFACTURING"] else True))
        self.assertEqual(LIB.sim_curve_present(SE_DEV), 0)
        self.assertEqual(LIB.sim_curve_present(SE_DSC), 0)
        w.factory()
        self.assertEqual(LIB.sim_curve_present(SE_DEV), 1)
        self.assertEqual(LIB.sim_curve_present(SE_DSC), 1)


# ═════════════════════════════════════════════════════════════════════
# 4. DSC key attestation, separate from device attestation

class TestKeyAttestation(unittest.TestCase):
    def setUp(self):
        self.w = V32World()
        self.slot, self.pub, self.cert = self.w.setup_ready()

    def check_vendor(self, r, pub, origin_code, challenge):
        blob = r[T["KEY_VENDOR_ATT"]]
        nxp = ctypes.create_string_buffer(65)
        LIB.sim_dsc_att_pub(nxp)
        tbs, sig = blob[:-64], blob[-64:]
        self.assertTrue(q.verify(nxp.raw, tbs, sig), "signed by the SE052F's own key")
        self.assertEqual(tbs[:7], b"SIMKATT")
        self.assertEqual(tbs[7], origin_code)
        self.assertEqual(tbs[8:24], challenge[:16])
        raw = q.load_spki(pub)
        if isinstance(raw, rsa.RSAPublicKey):
            body = raw.public_numbers().n.to_bytes(256, "big")
        else:
            body = q.pub_bytes(raw)
        self.assertEqual(tbs[24:56], q.sha256(body))

    def test_certified_key(self):
        w = self.w
        ch = bytes(range(24))
        r, st = w.key_attestation(self.slot, ch)
        self.assertEqual(st["KEY_SLOT"], self.slot)
        self.assertEqual(st["DSC_PUB"], self.pub)
        self.assertEqual(st["CHALLENGE"], ch)
        self.assertEqual(st["STATUS"], q.SLOT_STATUS["CERTIFIED"])
        self.assertEqual(st["CERT_HASH"], q.sha256(self.cert))
        self.assertEqual(st["KEY_ORIGIN"], ORIGIN["GENERATED"])
        self.assertEqual(st["KEYGEN_SEQ"], w.slot_seq(self.slot))
        self.check_vendor(r, self.pub, 1, ch)
        # The SE052F's own id: a different chip from the SE050 behind ATTEST.
        self.assertEqual(len(r[T["DSC_UID"]]), 18)
        self.assertNotEqual(r[T["DSC_UID"]], w.chip_uid)

    def test_pending_key_and_errors(self):
        w = self.w
        slot, pub = w.keygen(alg="RSA2048")
        r, st = w.key_attestation(slot)
        self.assertEqual(st["STATUS"], q.SLOT_STATUS["PENDING"])
        self.assertEqual(st["CERT_HASH"], bytes(32))
        self.check_vendor(r, pub, 1, b"K" * 24)
        self.assertEqual(w.tok.sw(q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], b"K" * 24),
                                         p1=3)), 0x6986)
        self.assertEqual(w.tok.sw(q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], b"K" * 8),
                                         p1=self.slot)), 0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], b"K" * 24),
                                         p1=9)), 0x6A86)

    def test_device_attestation_unchanged(self):
        """ATTEST still speaks only for the device (SE050), not for any DSC key."""
        st = self.w.attest(b"Q" * 16)
        self.assertNotIn("DSC_PUB", st.fields)


# ═════════════════════════════════════════════════════════════════════
# 5/6. Factory reset of both secure elements

class TestFactoryWipe(unittest.TestCase):
    def test_wipe_ready_token_and_remake(self):
        w = V32World()
        slot, _, _ = w.setup_ready()
        w.sign(slot)
        old_id, old_bind = w.device_id, w.bind_apdu()
        r = w.tok.ok(w.wipe_apdu())
        self.assertEqual(r[F["STATE"]], bytes([LC["MANUFACTURING"]]))
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        for k in (OBJ_DEVICE_CERT, OBJ_RECEIPT, OBJ_SLOT_REC, OBJ_SLOT_CERT):
            self.assertTrue(all(obj(k, i) is None for i in range(RING)))
        self.assertTrue(all(LIB.sim_dsc_present(i) == 0 for i in range(4)))
        self.assertTrue(all(LIB.sim_counter_present(c) == 0 for c in range(4)))
        self.assertEqual(LIB.sim_wipe_secret_present(SE_DEV), 0)
        self.assertEqual(LIB.sim_wipe_secret_present(SE_DSC), 0)
        # Survives a reboot as a fresh token.
        self.assertEqual(w.tok.boot(), 0)
        w.tok.select()
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        # Re-made: new device key, so new id; nothing from the old life applies.
        w.factory()
        self.assertNotEqual(w.device_id, old_id)
        self.assertEqual(w.tok.sw(old_bind), 0x6A80)
        w.pair()
        slot, _, _ = w.issue_dsc()
        w.sign(slot)

    def test_secrets_and_statement_required(self):
        w = V32World()
        w.setup_ready()
        self.assertEqual(w.tok.sw(w.wipe_apdu(dev=b"\x00" * 16)), 0x6982)
        self.assertEqual(w.tok.sw(w.wipe_apdu(dsc=b"\x00" * 16)), 0x6982)
        self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False)), 0x6A80, "DTI statement needed")
        self.assertEqual(w.tok.sw(w.wipe_apdu(signer=w.phone)), 0x6982, "phone can't wipe")
        self.assertEqual(w.tok.sw(w.wipe_apdu(binding=w.binding_no() - 1)), 0x6984)
        self.assertEqual(w.tok.sw(w.wipe_apdu(device_id=b"\x11" * 16)), 0x6A80)
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_WIPE", q.tlv(T["WIPE_SECRET_DEV"], b"x" * 15))),
                         0x6A80)
        self.assertEqual(w.tok.lc, LC["READY"], "nothing erased")
        w.sign(0)

    def test_manufacturing_needs_only_secrets(self):
        w = V32World()
        w.factory()
        # UNASSIGNED: statement still needed.
        self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False)), 0x6A80)
        w.tok.ok(w.wipe_apdu())
        w.factory_init_only = True
        r = w.tok.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        w.device_id, w.device_pub = r[F["DEVICE_ID"]], r[F["DEVICE_PUB"]]
        w.device_cert = make_cert(w.device_pub, w.device_ca, "QDSD device")
        w.tok.ok(q.apdu("FACTORY_PERSONALISE", w.personalise_data()))
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        w.tok.ok(w.wipe_apdu(stmt=False))

    def test_no_secret_no_wipe(self):
        """A token personalised before v3.2 has no FACTORY_RESET object."""
        w = V32World()
        w.tok.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False)), 0x6985)

    def test_personalise_requires_secrets(self):
        w = V32World()
        r = w.tok.ok(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        cert = make_cert(r[F["DEVICE_PUB"]], w.device_ca)
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_PERSONALISE",
                                         q.tlv(T["DEVICE_CERT"], cert) +
                                         q.tlv(T["CMD_PUB"], q.pub_bytes(w.cmd)))), 0x6A80)

    def test_power_cut_at_every_write(self):
        probe = V32World()
        probe.setup_ready()
        before = LIB.sim_write_count()
        probe.tok.ok(probe.wipe_apdu())
        n_writes = LIB.sim_write_count() - before
        for cut in range(n_writes + 1):
            w = V32World()
            w.setup_ready()
            a = w.wipe_apdu()
            LIB.sim_set_power_budget(cut)
            sw = w.tok.sw(a)
            LIB.sim_reboot()
            rc = w.tok.boot()
            w.tok.select()
            if cut == 0:
                self.assertEqual((rc, w.tok.lc), (0, LC["READY"]), "untouched")
                continue
            if sw == q.SW_OK or (rc == 0 and w.tok.lc == LC["MANUFACTURING"]):
                self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
                continue
            # Cut part-way: service mode until DTI finishes the wipe.
            self.assertEqual(rc, 1, f"cut {cut}")
            self.assertEqual(w.tok.lc, LC["FAULT"])
            self.assertEqual(w.tok.info()[F["STATE"]], bytes([LC["FAULT"]]))
            self.assertEqual(w.tok.sw(q.apdu("ATTEST", q.tlv(F["CHALLENGE"], b"a" * 16))),
                             0x6F00)
            self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False, dev=b"\x01" * 16)), 0x6982)
            w.tok.ok(w.wipe_apdu(stmt=False))
            self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
            w.factory()


# ═════════════════════════════════════════════════════════════════════
# 7. Signatures checked inside the SE050

class TestVerifyInSecureElement(unittest.TestCase):
    def test_stored_keys_checked_by_the_element(self):
        w = V32World()
        w.factory()
        n0 = LIB.sim_se_verify_count()
        w.pair()                      # DTI command key
        n1 = LIB.sim_se_verify_count()
        self.assertEqual(n1, n0 + 1)
        slot, _, _ = w.issue_dsc()    # phone key
        w.login()
        w.sign(slot)
        self.assertEqual(LIB.sim_se_verify_count(), n1 + 3)

    def test_forged_assertion_refused(self):
        w = V32World()
        slot, _, _ = w.setup_ready()
        n = w.nonce()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"x"), slot, signer=new_key())),
                         0x6982)


# ═════════════════════════════════════════════════════════════════════
# 8. User certificates: upload, retrieve, delete

class TestDeleteKey(unittest.TestCase):
    def setUp(self):
        self.w = V32World()
        self.slot, self.pub, self.cert = self.w.setup_ready()

    def test_delete_certified_key(self):
        w = self.w
        seq = w.slot_seq(self.slot)
        r = w.tok.ok(w.delete_apdu(self.slot, seq))
        st = q.open_signed(r, w.device_pub, "KEY_DELETED")
        self.assertEqual((st["KEY_SLOT"], st["KEYGEN_SEQ"]), (self.slot, seq))
        self.assertEqual(LIB.sim_dsc_present(self.slot), 0)
        self.assertIsNone(obj(OBJ_SLOT_CERT, self.slot))
        self.assertEqual(w.info_slots()[self.slot]["status"], q.SLOT_STATUS["EMPTY"])
        self.assertEqual(w.tok.sw(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"),
                                         p1=self.slot)), 0x6A88)
        self.assertEqual(w.tok.lc, LC["BOUND"], "no certified key left")
        n = w.nonce()
        self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"x"), self.slot)), 0x6985)
        # Download a new one into the freed slot.
        slot, _, _ = w.issue_dsc()
        self.assertEqual(slot, self.slot)
        self.assertEqual(w.tok.lc, LC["READY"])

    def test_approval_cannot_hit_a_later_key(self):
        w = self.w
        seq = w.slot_seq(self.slot)
        old = w.delete_apdu(self.slot, seq)
        w.tok.ok(w.delete_apdu(self.slot, seq))
        slot, _, _ = w.issue_dsc()
        self.assertEqual(slot, self.slot)
        self.assertEqual(w.tok.sw(old), 0x6984, "approval named the earlier key")

    def test_refusals(self):
        w = self.w
        seq = w.slot_seq(self.slot)
        self.assertEqual(w.tok.sw(w.delete_apdu(self.slot, seq, signer=w.cmd)), 0x6982,
                         "cloud alone cannot delete a Subscriber's DSC")
        self.assertEqual(w.tok.sw(w.delete_apdu(self.slot, seq, slot_in_stmt=1)), 0x6A80)
        self.assertEqual(w.tok.sw(w.delete_apdu(2, 1)), 0x6986, "empty slot")
        self.assertEqual(w.tok.sw(w.delete_apdu(7, 1)), 0x6A86)
        self.assertEqual(LIB.sim_dsc_present(self.slot), 1)

    def test_keeps_other_slots(self):
        w = self.w
        slot2, pub2, _ = w.issue_dsc(alg="RSA2048")
        w.tok.ok(w.delete_apdu(self.slot, w.slot_seq(self.slot)))
        self.assertEqual(w.tok.lc, LC["READY"])
        h, _, sig, _ = w.sign(slot2)
        self.assertTrue(q.verify_dsc(pub2, sig, h))

    def test_power_cut_at_every_write(self):
        probe = V32World()
        s, _, _ = probe.setup_ready()
        before = LIB.sim_write_count()
        probe.tok.ok(probe.delete_apdu(s, probe.slot_seq(s)))
        n_writes = LIB.sim_write_count() - before
        for cut in range(n_writes + 1):
            w = V32World()
            slot, _, _ = w.setup_ready()
            a = w.delete_apdu(slot, w.slot_seq(slot))
            LIB.sim_set_power_budget(cut)
            sw = w.tok.sw(a)
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            w.login()
            status = w.info_slots()[slot]["status"]
            if status == q.SLOT_STATUS["EMPTY"]:
                self.assertEqual(LIB.sim_dsc_present(slot), 0, "no orphan key")
                self.assertIsNone(obj(OBJ_SLOT_CERT, slot))
                self.assertEqual(w.tok.lc, LC["BOUND"], f"cut {cut}")
            else:
                self.assertNotEqual(sw, q.SW_OK)
                self.assertEqual(w.tok.lc, LC["READY"])
                w.tok.ok(a)  # approval still valid: retry


class TestReviewFixes(unittest.TestCase):
    """Findings of the independent review of 0.6 (all fixed)."""

    def test_sign_approval_dies_with_its_key(self):
        """An approval names the key (keygen_seq): it never applies to a later key
        in the same slot, and changing keys elsewhere no longer cancels it."""
        w = V32World()
        slot, _, _ = w.setup_ready()
        old_seq = w.seqs[slot]
        n = w.nonce()
        held = w.sign_apdu(n, q.sha256(b"approved for the personal DSC"), slot)
        w.tok.ok(w.delete_apdu(slot, w.slot_seq(slot)))
        key, cert, _ = institutional("P256")
        s2, _ = w.import_pfx(key, cert, "P256")
        self.assertEqual(s2, slot)
        data, sw = w.tok.raw(held)
        self.assertEqual(sw, 0x6984)
        self.assertEqual(q.tlv_dict(data)[T["NONCE_STATUS"]],
                         bytes([q.NONCE_WHY["KEY_CHANGED"]]))
        # The nonce itself survived the delete and the import: a fresh approval
        # for the new key uses it.
        self.assertNotEqual(w.seqs[slot], old_seq)
        w.tok.ok(w.sign_apdu(n, q.sha256(b"approved for the new key"), slot))
        # Same through KEYGEN + certificate.
        n = w.nonce()
        held = w.sign_apdu(n, q.sha256(b"x"), slot)
        w.tok.ok(w.delete_apdu(slot, w.slot_seq(slot)))
        w.issue_dsc()
        self.assertEqual(w.tok.sw(held), 0x6984)
        # DSC download in another slot no longer cancels a waiting approval.
        n = w.nonce()
        held = w.sign_apdu(n, q.sha256(b"y"), slot)
        w.issue_dsc()
        w.tok.ok(held)
        # An approval for a deleted key in an emptied slot: slot state.
        other, _, _ = w.issue_dsc()
        n = w.nonce()
        held = w.sign_apdu(n, q.sha256(b"z"), slot)
        w.tok.ok(w.delete_apdu(slot, w.slot_seq(slot)))
        self.assertEqual(w.tok.lc, LC["READY"])
        self.assertEqual(w.tok.sw(held), 0x6986)
        w.tok.ok(w.sign_apdu(n, q.sha256(b"z"), other))

    def test_certificate_reissue_power_cut(self):
        """Old certificate or new one after a cut at every write, never none."""
        probe = V32World()
        s, p, _ = probe.setup_ready()
        new = make_cert(p, probe.ca, "Reissued certificate with a longer name")
        before = LIB.sim_write_count()
        probe.write_cert(s, new)
        n_writes = LIB.sim_write_count() - before
        self.assertGreaterEqual(n_writes, 3)
        for cut in range(n_writes + 1):
            w = V32World()
            slot, pub, old = w.setup_ready()
            new = make_cert(pub, w.ca, "Reissued certificate with a longer name")
            LIB.sim_set_power_budget(cut)
            sw = w.write_cert(slot, new)
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            data, sw2 = w.tok.raw(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
            self.assertEqual(sw2, q.SW_OK, f"cut {cut}")
            got = q.tlv_dict(data)[T["CHUNK"]]
            self.assertIn(got, (old, new))
            if sw == q.SW_OK:
                self.assertEqual(got, new)
            # Only the current bank is left after boot.
            other = [obj(OBJ_SLOT_CERT, slot), obj(OBJ_SLOT_CERT, slot + 4)]
            self.assertEqual(sum(o is not None for o in other), 1, f"cut {cut}")
            w.login()
            w.sign(slot)

    def test_fault_still_needs_dti_statement(self):
        """A FAULT that is not a lost record or a cut-off wipe: secrets alone don't erase."""
        w = V32World()
        w.setup_ready()
        LIB.sim_obj_del(OBJ_DEVICE_CERT, 0)
        self.assertEqual(w.tok.boot(), 1)
        w.tok.select()
        self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False)), 0x6A80)
        self.assertEqual(w.tok.lc, LC["FAULT"])
        st = q.stmt_build("WIPE", DEVICE_ID=w.device_id, BINDING_NO=1)
        body = (q.signed(st, w.cmd) + q.tlv(T["WIPE_SECRET_DEV"], w.WIPE_DEV) +
                q.tlv(T["WIPE_SECRET_DSC"], w.WIPE_DSC))
        w.tok.ok(q.apdu("FACTORY_WIPE", body))
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])

    def test_lost_state_record_is_not_a_fresh_token(self):
        w = V32World()
        w.setup_ready()
        LIB.sim_state_remove()
        self.assertEqual(w.tok.boot(), 1, "service mode, not MANUFACTURING")
        w.tok.select()
        self.assertEqual(w.tok.lc, LC["FAULT"])
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16))),
                         0x6F00, "factory commands stay closed")
        self.assertEqual(w.tok.sw(q.apdu("FACTORY_PERSONALISE", w.personalise_data(
            cmd=new_key()))), 0x6F00)
        self.assertEqual(w.tok.sw(w.wipe_apdu(stmt=False, dsc=b"\x09" * 16)), 0x6982)
        w.tok.ok(w.wipe_apdu(stmt=False))
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        w.factory()

    def test_corrupt_state_record_repairable(self):
        w = V32World()
        w.setup_ready()
        LIB.sim_corrupt_state()
        self.assertEqual(w.tok.boot(), 1)
        w.tok.select()
        w.tok.ok(w.wipe_apdu(stmt=False))
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])

    def test_fresh_line_token_after_cut_in_factory_init(self):
        """Device key made, record not yet written: still a fresh token, not FAULT."""
        w = V32World()
        LIB.sim_set_power_budget(1)   # curve present: device key written, record write cut
        w.tok.raw(q.apdu("FACTORY_INIT", q.tlv(F["CHALLENGE"], b"F" * 16)))
        LIB.sim_reboot()
        self.assertEqual(w.tok.boot(), 0)
        w.tok.select()
        self.assertEqual(w.tok.lc, LC["MANUFACTURING"])
        w.factory()


# ═════════════════════════════════════════════════════════════════════
# 9. Institutional certificates from .pfx

class TestImport(unittest.TestCase):
    def setUp(self):
        self.w = V32World()
        self.w.factory()
        self.w.pair()

    def check_imported(self, slot, key, cert, att):
        w = self.w
        spki = q.spki_of(key)
        self.assertEqual(att["DSC_PUB"], spki)
        self.assertEqual(att["KEY_ORIGIN"], ORIGIN["IMPORTED"])
        self.assertEqual(w.tok.lc, LC["READY"])
        info = w.info_slots()[slot]
        self.assertEqual((info["status"], info["has_cert"], info["origin"]),
                         (q.SLOT_STATUS["CERTIFIED"], 1, ORIGIN["IMPORTED"]))
        r = w.tok.ok(q.apdu("GET_CERT", q.tlv(T["OFFSET"], b"\x00\x00"), p1=slot))
        self.assertEqual(r[T["CHUNK"]], cert)
        h, _, sig, rec = w.sign(slot)
        self.assertTrue(q.verify_dsc(spki, sig, h))
        self.assertEqual(rec["KEY_ORIGIN"], ORIGIN["IMPORTED"])
        _, st = w.key_attestation(slot)
        self.assertEqual(st["KEY_ORIGIN"], ORIGIN["IMPORTED"])
        self.assertEqual(LIB.sim_dsc_origin(slot), 2, "element says: written from outside")
        # An imported key never signs a CSR: it already has its certificate.
        self.assertEqual(w.tok.sw(q.apdu("SIGN_CSR", q.tlv(T["CSR_DIGEST"], bytes(32)),
                                         p1=slot, p2=1)), 0x6986)

    def test_import_p256(self):
        key, cert, _ = institutional("P256")
        offer = self.w.import_begin(cert, "P256")
        self.assertEqual(offer["CERT_HASH"], q.sha256(cert))
        self.assertEqual(offer["KEY_ALG"], q.ALG["P256"])
        pkg = q.import_wrap(offer, self.w.device_id, key, cert)
        data, sw = self.w.import_send(pkg)
        self.assertEqual(sw, q.SW_OK)
        r = q.tlv_dict(data)
        att = q.open_signed(r, self.w.device_pub, "KEY_ATTEST")
        self.w.seqs[r[F["KEY_SLOT"]][0]] = att["KEYGEN_SEQ"]
        self.check_imported(r[F["KEY_SLOT"]][0], key, cert, att)

    def test_import_rsa(self):
        key, cert, _ = institutional("RSA2048")
        slot, att = self.w.import_pfx(key, cert, "RSA2048")
        self.check_imported(slot, key, cert, att)

    def test_import_next_to_own_dsc(self):
        w = self.w
        own, pub, _ = w.issue_dsc()
        key, cert, _ = institutional("P256")
        slot, _ = w.import_pfx(key, cert, "P256")
        self.assertNotEqual(slot, own)
        h, _, sig, rec = w.sign(own)
        self.assertEqual(rec["KEY_ORIGIN"], ORIGIN["GENERATED"])
        # The imported one can be deleted like any other.
        w.tok.ok(w.delete_apdu(slot, w.slot_seq(slot)))
        self.assertEqual(LIB.sim_dsc_present(slot), 0)

    def test_other_certificate_refused_before_anything_is_spent(self):
        w = self.w
        key, cert, ca = institutional("P256")
        other = make_cert(q.spki_of(key), ca, "Someone else")
        offer = w.import_begin(cert, "P256")
        ctr = w.keygen_ctr()
        good = q.tlv_dict(q.import_wrap(offer, w.device_id, key, cert))
        pkg = (q.tlv(T["IMPORT_CERT"], other) + q.tlv(T["AGENT_PUB"], good[T["AGENT_PUB"]]) +
               q.tlv(T["IMPORT_CT"], good[T["IMPORT_CT"]]))
        self.assertEqual(w.import_send(pkg)[1], 0x6A80)
        self.assertEqual(w.keygen_ctr(), ctr, "approval not spent")
        self.assertEqual(w.import_send(q.import_wrap(offer, w.device_id, key, cert))[1], 0x6985,
                         "one attempt per IMPORT_BEGIN")
        slot, _ = w.import_pfx(key, cert, "P256")   # a fresh begin with the same approval
        self.assertEqual(slot, 0)

    def test_key_not_matching_certificate(self):
        w = self.w
        key, cert, _ = institutional("P256")
        wrong = ec.generate_private_key(ec.SECP256R1())
        offer = w.import_begin(cert, "P256")
        # The agent's own sanity check is bypassed: wrap a different key.
        alg, pt = q.import_plaintext(wrong)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        agent = ec.generate_private_key(ec.SECP256R1())
        z = agent.exchange(ec.ECDH(), q.pub_from_bytes(offer["IMPORT_PUB"]))
        k = q.sha256(q.IMPORT_KDF_LABEL + z + offer["IMPORT_PUB"] + q.pub_bytes(agent))
        aad = w.device_id + struct.pack(">I", offer["KEYGEN_SEQ"]) + offer["CERT_HASH"] + bytes([alg])
        iv = b"\x07" * 12
        ct = AESGCM(k).encrypt(iv, pt, aad)
        pkg = (q.tlv(T["IMPORT_CERT"], cert) + q.tlv(T["AGENT_PUB"], q.pub_bytes(agent)) +
               q.tlv(T["IMPORT_CT"], iv + ct))
        self.assertEqual(w.import_send(pkg)[1], 0x6A80)
        self.assertTrue(all(LIB.sim_dsc_present(i) == 0 for i in range(4)), "key removed")
        self.assertEqual(w.tok.lc, LC["BOUND"])
        self.assertEqual(w.tok.sw(w.import_consent_apdu(cert, "P256",
                                                        seq=offer["KEYGEN_SEQ"])), 0x6984,
                         "approval spent")

    def test_tampered_or_misdirected_wrap(self):
        w = self.w
        key, cert, _ = institutional("P256")
        offer = w.import_begin(cert, "P256")
        pkg = bytearray(q.import_wrap(offer, w.device_id, key, cert))
        pkg[-20] ^= 1
        self.assertEqual(w.import_send(bytes(pkg))[1], 0x6A80, "GCM tag")
        # Wrapped to some other key than this token's offer (another token, or
        # an attacker in the middle): the token cannot decrypt it.
        offer = w.import_begin(cert, "P256")
        fake = q.stmt_parse(q.stmt_build(
            "IMPORT_OFFER", DEVICE_ID=w.device_id, KEYGEN_SEQ=offer["KEYGEN_SEQ"],
            CERT_HASH=offer["CERT_HASH"], IMPORT_PUB=q.pub_bytes(new_key()),
            KEY_ALG=offer["KEY_ALG"]))
        self.assertEqual(w.import_send(q.import_wrap(fake, w.device_id, key, cert))[1], 0x6A80)
        # Bound to this device id and approval number (AAD).
        offer = w.import_begin(cert, "P256")
        self.assertEqual(w.import_send(q.import_wrap(offer, b"\x22" * 16, key, cert))[1],
                         0x6A80)
        self.assertTrue(all(LIB.sim_dsc_present(i) == 0 for i in range(4)))
        slot, _ = w.import_pfx(key, cert, "P256")
        self.assertEqual(slot, 0)

    def test_wrong_algorithm_and_signers(self):
        w = self.w
        key, cert, _ = institutional("P256")
        self.assertEqual(w.tok.sw(w.import_consent_apdu(cert, "P256", signer=w.cmd)), 0x6982)
        self.assertEqual(w.tok.sw(w.import_consent_apdu(cert, "P256", seq=5)), 0x6984)
        offer = w.import_begin(cert, "RSA2048")  # approval says RSA, certificate is P-256
        pkg = (q.tlv(T["IMPORT_CERT"], cert) + q.tlv(T["AGENT_PUB"], q.pub_bytes(new_key())) +
               q.tlv(T["IMPORT_CT"], bytes(12 + 640 + 16)))
        self.assertEqual(w.import_send(pkg)[1], 0x6A80)
        self.assertEqual(offer["KEY_ALG"], q.ALG["RSA2048"])

    def test_unplug_and_order(self):
        w = self.w
        key, cert, _ = institutional("P256")
        self.assertEqual(w.tok.sw(q.apdu("IMPORT_DATA", q.tlv(T["CHUNK"], b"x"))), 0x6985)
        offer = w.import_begin(cert, "P256")
        pkg = q.import_wrap(offer, w.device_id, key, cert)
        w.replug()
        w.login()
        self.assertEqual(w.import_send(pkg)[1], 0x6985, "ephemeral key gone with the session")
        # Not before pairing.
        t = V32World(seed=4)
        t.factory()
        self.assertEqual(t.tok.sw(t.import_consent_apdu(cert, "P256", seq=1)), 0x6985)

    def test_power_cut_at_every_write(self):
        key, cert, _ = institutional("P256")
        probe = V32World()
        probe.factory(); probe.pair()
        offer = probe.import_begin(cert, "P256")
        pkg = q.import_wrap(offer, probe.device_id, key, cert)
        before = LIB.sim_write_count()
        self.assertEqual(probe.import_send(pkg)[1], q.SW_OK)
        n_writes = LIB.sim_write_count() - before
        for cut in range(n_writes + 1):
            w = V32World()
            w.factory(); w.pair()
            offer = w.import_begin(cert, "P256")
            pkg = q.import_wrap(offer, w.device_id, key, cert)
            LIB.sim_set_power_budget(cut)
            sw = w.import_send(pkg)[1]
            LIB.sim_reboot()
            self.assertEqual(w.tok.boot(), 0)
            w.tok.select()
            w.login()
            info = w.info_slots()
            if info[0]["status"] == q.SLOT_STATUS["CERTIFIED"]:
                self.assertEqual(w.tok.lc, LC["READY"])
                w.seqs[0] = info[0]["seq"]  # the cloud learns it from GET_INFO / receipts
                w.sign(0)
            else:
                self.assertNotEqual(sw, q.SW_OK)
                self.assertEqual(LIB.sim_dsc_present(0), 0, f"cut {cut}: no orphan key")
                self.assertEqual(w.tok.lc, LC["BOUND"])


if __name__ == "__main__":
    unittest.main()
