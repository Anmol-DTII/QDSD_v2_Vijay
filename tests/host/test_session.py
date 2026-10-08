"""Firmware 0.6.1-0.6.2 (protocol v3.3): session robustness and short-APDU hosts.

  1. A failed SELECT keeps the current selection.
  2. Re-SELECTing our AID keeps the login (and the idle timer).
  3. A CCID power cycle keeps the login and nonces; a USB reset does not.
  4. (keygen_seq in SIGN_ASSERTION: test_v32.TestReviewFixes)
  5. Session epoch in GET_INFO.
  6. Reason byte with 6984 for SIGN and LOGIN.
  7. ISO 7816 command chaining and GET RESPONSE.
"""
import struct
import unittest

import qdsd_proto as q
from qdsd_proto import CCID, F, T, LC
from test_ccid import CcidToken, Reader
from test_flows import HOUR, LIB, World, make_cert, new_key
from test_v32 import V32World

PIV_AID = bytes.fromhex("00A4040005A000000308")
WHY = q.NONCE_WHY


def epoch(w):
    return struct.unpack(">I", w.tok.info()[T["SESSION_EPOCH"]])[0]


def reason(data):
    return q.tlv_dict(data)[T["NONCE_STATUS"]][0]


class TestSelect(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.slot, _, _ = self.w.setup_ready()
        self.w.replug()
        self.w.login()

    def test_failed_select_keeps_selection(self):
        """Team test: select, log in, SELECT PIV, GET_INFO -> 9000, full, session 01."""
        w = self.w
        self.assertEqual(w.tok.sw(PIV_AID), 0x6A82)
        info = w.tok.info()
        self.assertEqual(info[F["SESSION"]], b"\x01")
        self.assertIn(T["SLOT_ENTRY"], info, "full detail")
        # Wrong P1/P2 and wrong CLA also leave the selection alone.
        self.assertEqual(w.tok.sw(bytes.fromhex("00A4000005A000000308")), 0x6A86)
        self.assertEqual(w.tok.sw(bytes.fromhex("80A4040005A000000308")), 0x6E00)
        self.assertEqual(w.tok.info()[F["SESSION"]], b"\x01")
        w.sign(self.slot)

    def test_reselect_keeps_login_and_nonces(self):
        """Team test: log in, SELECT our AID again, GET_INFO -> still logged in; nonces usable."""
        w = self.w
        n = w.nonce()
        w.tok.select()
        self.assertEqual(w.session(), 1)
        w.tok.ok(w.sign_apdu(n, q.sha256(b"after reselect"), self.slot))

    def test_reselect_does_not_refresh_idle_timer(self):
        w = self.w
        LIB.sim_advance_ms(8 * HOUR - 60_000)
        w.tok.select()                       # housekeeping, not use
        LIB.sim_advance_ms(120_000)
        self.assertEqual(w.session(), 0, "idle timeout still applies")

    def test_first_select_sets_starting_session(self):
        w = self.w
        w.replug()                           # USB reset: new connection
        self.assertEqual(w.session(), 0)


class TestCardPowerCycle(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.w.tok = CcidToken(self.w.tok)
        self.w.tok.select()
        self.slot, _, _ = self.w.setup_ready()
        LIB.token_engine_session_reset()     # plug in again
        self.w.tok.select()
        self.w.login()
        self.reader = self.w.tok.reader

    def power_cycle(self):
        mtype, _, status, _, _, _ = self.reader.send(CCID["POWER_OFF"])
        self.assertEqual(mtype, CCID["SLOT_STATUS"])
        self.reader.power_on()

    def test_power_cycle_keeps_login_and_nonces(self):
        """Team test: log in, two nonces, SCardReconnect(RESET), SELECT -> logged in, both usable."""
        w = self.w
        n1, n2 = w.nonce(), w.nonce()
        e = epoch(w)
        self.power_cycle()
        self.assertEqual(w.tok.sw(q.apdu("GET_INFO")), 0x6982, "SELECT needed again")
        w.tok.select()
        self.assertEqual(w.session(), 1)
        self.assertEqual(epoch(w), e, "same session")
        w.tok.ok(w.sign_apdu(n1, q.sha256(b"one"), self.slot))
        w.tok.ok(w.sign_apdu(n2, q.sha256(b"two"), self.slot))
        # A warm reset (power-on of a powered card) behaves the same.
        n3 = w.nonce()
        self.reader.power_on()
        w.tok.select()
        w.tok.ok(w.sign_apdu(n3, q.sha256(b"three"), self.slot))

    def test_usb_reset_still_clears_everything(self):
        w = self.w
        n = w.nonce()
        e = epoch(w)
        LIB.token_engine_session_reset()
        w.tok.select()
        self.assertEqual(w.session(), 0)
        self.assertNotEqual(epoch(w), e)
        data, sw = w.tok.raw(w.sign_apdu(n, q.sha256(b"x"), self.slot))
        self.assertEqual((sw, reason(data)), (0x6984, WHY["DISCARDED"]))

    def test_update_needs_login_after_card_reset(self):
        """The login survives a card reset, but the right to install firmware does not."""
        w = self.w
        begin = q.apdu("UPDATE_BEGIN", q.tlv(T["IMAGE_SIZE"], b"\0\0\1\0") +
                       q.tlv(T["IMAGE_SHA256"], bytes(32)))
        w.tok.ok(begin)
        self.power_cycle()
        w.tok.select()
        self.assertEqual(w.session(), 1)
        self.assertEqual(w.tok.sw(begin), 0x6983)
        w.login()
        w.tok.ok(begin)

    def test_power_cycle_aborts_uploads(self):
        w = self.w
        slot, pub = w.keygen()
        cert = make_cert(pub, w.ca)
        first = q.apdu("WRITE_CERT", q.tlv(T["TOTAL"], struct.pack(">H", len(cert))) +
                       q.tlv(T["CHUNK"], cert[:100]), p1=slot, p2=0)
        w.tok.ok(first)
        self.power_cycle()
        w.tok.select()
        self.assertEqual(w.tok.sw(q.apdu("WRITE_CERT", q.tlv(T["CHUNK"], cert[100:]),
                                         p1=slot, p2=1)), 0x6985)
        self.assertEqual(w.write_cert(slot, cert), q.SW_OK)


class TestEpoch(unittest.TestCase):
    def test_epoch_in_both_forms_and_changes_only_on_session_reset(self):
        w = World()
        w.factory()
        e0 = epoch(w)
        w.pair()
        w.replug()
        e1 = epoch(w)
        self.assertNotEqual(e0, e1)
        self.assertEqual(w.session(), 0)
        self.assertIn(T["SESSION_EPOCH"], w.tok.info(), "logged-out form")
        w.login()
        w.tok.select()
        w.tok.ok(q.apdu("LOGOUT"))
        self.assertEqual(epoch(w), e1, "login, re-SELECT, LOGOUT keep the epoch")
        self.assertEqual(w.tok.boot(), 0)   # token restart
        w.tok.select()
        e2 = epoch(w)
        self.assertNotEqual(e2, e1)
        # A factory wipe ends the session too.
        st = q.stmt_build("WIPE", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no())
        w.tok.ok(q.apdu("FACTORY_WIPE", q.signed(st, w.cmd) +
                        q.tlv(T["WIPE_SECRET_DEV"], w.WIPE_DEV) +
                        q.tlv(T["WIPE_SECRET_DSC"], w.WIPE_DSC)))
        self.assertNotEqual(epoch(w), e2)


class TestNonceReasons(unittest.TestCase):
    def setUp(self):
        self.w = V32World()
        self.slot, _, _ = self.w.setup_ready()

    def stale(self, nonce, slot=None, signer=None):
        data, sw = self.w.tok.raw(self.w.sign_apdu(nonce, q.sha256(b"r"), self.slot if slot is None
                                                   else slot, signer=signer))
        self.assertEqual(sw, 0x6984)
        return reason(data)

    def test_expired(self):
        n = self.w.nonce()
        LIB.sim_advance_ms(601_000)
        self.assertEqual(self.stale(n), WHY["EXPIRED"])

    def test_expired_then_evicted_is_still_expired(self):
        first = self.w.nonce()
        LIB.sim_advance_ms(601_000)
        for _ in range(4):
            self.w.nonce()
        self.assertEqual(self.stale(first), WHY["EXPIRED"])

    def test_replaced(self):
        first = self.w.nonce()
        for _ in range(4):
            self.w.nonce()
        self.assertEqual(self.stale(first), WHY["REPLACED"])

    def test_discarded_by_rebind(self):
        w = self.w
        n = w.nonce()
        newphone = new_key()
        st = q.stmt_build("REBIND", DEVICE_ID=w.device_id, BINDING_NO=w.binding_no() + 1,
                          NEW_KEY_HASH=q.sha256(q.pub_bytes(newphone)), METHOD=1)
        w.tok.ok(q.apdu("REBIND", q.tlv(F["ACTIVATION_PUB"], q.pub_bytes(newphone)) +
                        q.signed(st, w.phone, der=True)))
        w.phone = newphone
        self.assertEqual(self.stale(n), WHY["DISCARDED"])

    def test_unknown(self):
        self.assertEqual(self.stale(bytes(range(32))), WHY["UNKNOWN"])

    def test_used(self):
        w = self.w
        n = w.nonce()
        a = w.sign_apdu(n, q.sha256(b"once"), self.slot)
        w.tok.ok(a)
        data, sw = w.tok.raw(a)
        self.assertEqual((sw, reason(data)), (0x6984, WHY["USED"]),
                         "lost reply: the agent fetches the receipt with GET_RECEIPT")

    def test_too_many_failures(self):
        w = self.w
        n = w.nonce()
        for _ in range(3):
            self.assertEqual(w.tok.sw(w.sign_apdu(n, q.sha256(b"x"), self.slot,
                                                  signer=new_key())), 0x6982)
        self.assertEqual(self.stale(n), WHY["FAILS"])

    def test_login_reasons(self):
        w = self.w
        n = w.nonce()
        w.tok.ok(w.login_apdu(n))
        data, sw = w.tok.raw(w.login_apdu(n))
        self.assertEqual((sw, reason(data)), (0x6984, WHY["USED"]))
        data, sw = w.tok.raw(w.login_apdu(bytes(32)))
        self.assertEqual((sw, reason(data)), (0x6984, WHY["UNKNOWN"]))


class TestChaining(unittest.TestCase):
    """A host whose driver only does short APDUs: chaining out, 61xx/GET RESPONSE back."""

    def setUp(self):
        self.w = World()
        self.w.factory()
        self.w.pair()

    def send(self, a):
        out_data, sw = self.w.tok.raw(a)
        return out_data + bytes([sw >> 8, sw & 0xFF])

    def test_rsa_flow_with_short_apdus_only(self):
        w = self.w
        # KEYGEN RSA: command < 255, response (294-byte key + receipt) > 256.
        a = w.consent_apdu()
        st_sig = a[7:-2]                      # body of the extended APDU
        rsp, sw = q.transmit_short(self.send, "KEYGEN", st_sig, p1=q.ALG["RSA2048"])
        self.assertEqual(sw, q.SW_OK)
        r = q.tlv_dict(rsp)
        att = q.open_signed(r, w.device_pub, "KEY_ATTEST")
        slot, pub = r[F["KEY_SLOT"]][0], r[F["DSC_PUB"]]
        w.seqs[slot] = att["KEYGEN_SEQ"]
        cert = make_cert(pub, w.ca)
        # WRITE_CERT: one ~1 KB chunk, sent as 5 chained short APDUs.
        body = q.tlv(T["TOTAL"], struct.pack(">H", len(cert))) + q.tlv(T["CHUNK"], cert)
        _, sw = q.transmit_short(self.send, "WRITE_CERT", body, p1=slot)
        self.assertEqual(sw, q.SW_OK)
        # SIGN: command > 255 and response > 256 (256-byte signature + receipt).
        n = w.tok.ok(q.apdu("GET_SESSION_NONCE", short=True))[F["NONCE"]]
        h = q.sha256(b"doc")
        a = w.sign_apdu(n, h, slot)
        rsp, sw = q.transmit_short(self.send, "SIGN", a[7:-2])
        self.assertEqual(sw, q.SW_OK)
        r = q.tlv_dict(rsp)
        self.assertTrue(q.verify_dsc(pub, r[T["DSC_SIG_RAW"]], h))
        q.open_signed(r, w.device_pub, "SIGN_RECEIPT")
        # GET_CERT in short form: 1 KB answer in 61xx pieces.
        rsp, sw = q.transmit_short(self.send, "GET_CERT", q.tlv(T["OFFSET"], b"\0\0"), p1=slot)
        self.assertEqual(q.tlv_dict(rsp)[T["CHUNK"]], cert[:1024])

    def test_get_response_details(self):
        w = self.w
        slot, pub = w.keygen(alg="RSA2048")
        r = w.tok.raw(q.apdu("GET_INFO", short=True))
        self.assertEqual(r[1], q.SW_OK, "short answers stay short")
        a = q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], b"K" * 24), p1=slot, short=True)
        data, sw = w.tok.raw(a)
        self.assertEqual(len(data), 256)
        self.assertEqual(sw >> 8, 0x61)
        # Le smaller than what is left: several GET RESPONSEs.
        got, total = data, None
        while sw >> 8 == 0x61:
            d, sw = w.tok.raw(bytes([0x00, 0xC0, 0x00, 0x00, 0x40]))
            self.assertLessEqual(len(d), 0x40)
            got += d
        self.assertEqual(sw, q.SW_OK)
        q.open_signed(q.tlv_dict(got), w.device_pub, "KEY_STATUS")
        self.assertEqual(w.tok.sw(bytes([0x00, 0xC0, 0x00, 0x00, 0x00])), 0x6985, "nothing held")
        # Any other command drops a held answer.
        w.tok.raw(a)
        w.tok.info()
        self.assertEqual(w.tok.sw(bytes([0x00, 0xC0, 0x00, 0x00, 0x00])), 0x6985)
        # Extended form: whole answer at once.
        data, sw = w.tok.raw(q.apdu("GET_KEY_ATTESTATION", q.tlv(F["CHALLENGE"], b"K" * 24),
                                    p1=slot))
        self.assertEqual(sw, q.SW_OK)
        self.assertGreater(len(data), 256)

    def test_chaining_errors(self):
        w = self.w
        pieces = q.chained("WRITE_CERT", b"\x24\x02\x01\x00" + b"\x25\x81\xff" + b"x" * 300, p1=0)
        self.assertEqual(w.tok.sw(pieces[0]), q.SW_OK)
        self.assertEqual(w.tok.sw(q.apdu("GET_INFO", short=True)), 0x6883,
                         "another command in the middle of a chain")
        self.assertEqual(w.tok.sw(pieces[1]), 0x6986, "chain gone: an ordinary WRITE_CERT now")
        self.assertEqual(w.tok.sw(bytes.fromhex("10A4040005A000000308")), 0x6E00,
                         "SELECT cannot be chained")
        big = b"y" * 255
        for _ in range(9):  # 9 x 255 > 2112
            sw = w.tok.sw(bytes([0x90, q.INS["WRITE_CERT"], 0, 0, 255]) + big)
        self.assertEqual(sw, 0x6700, "chain longer than the largest APDU")
        w.tok.info()  # recovers

    def test_select_and_get_response_end_a_chain(self):
        w = self.w
        piece = bytes([0x90, q.INS["WRITE_CERT"], 0, 0, 3]) + b"abc"
        self.assertEqual(w.tok.sw(piece), q.SW_OK)
        w.tok.select()                       # an agent restarting: runs, chain dropped
        self.assertEqual(w.tok.sw(bytes([0x80, q.INS["GET_INFO"], 0, 0])), q.SW_OK)
        self.assertEqual(w.tok.sw(piece), q.SW_OK)
        self.assertEqual(w.tok.sw(bytes([0x00, 0xC0, 0x00, 0x00, 0x00])), 0x6985)
        self.assertEqual(w.tok.sw(bytes([0x80, q.INS["GET_INFO"], 0, 0])), q.SW_OK,
                         "GET RESPONSE dropped the chain")
        LIB.token_engine_session_reset()
        self.assertEqual(w.tok.sw(bytes.fromhex("10A4040005A000000308")), 0x6E00,
                         "chained SELECT, even before selection")

    def test_empty_chain(self):
        """Pieces without data still make one command (here GET_INFO)."""
        w = self.w
        self.assertEqual(w.tok.sw(bytes([0x90, q.INS["GET_INFO"], 0, 0])), q.SW_OK)
        data, sw = w.tok.raw(bytes([0x80, q.INS["GET_INFO"], 0, 0]))
        self.assertEqual(sw, q.SW_OK)
        self.assertIn(F["STATE"], q.tlv_dict(data))

    def test_chain_before_select(self):
        w = self.w
        LIB.token_engine_session_reset()
        self.assertEqual(w.tok.sw(bytes([0x90, q.INS["SIGN"], 0, 0, 1, 0])), 0x6982)

    def test_over_ccid(self):
        """The same short-APDU path through the CCID reader."""
        w = World()
        w.tok = CcidToken(w.tok)
        w.tok.select()
        w.factory()
        w.pair()
        slot, pub, _ = w.issue_dsc(alg="RSA2048")
        n = w.nonce()
        h = q.sha256(b"ccid short")
        a = w.sign_apdu(n, h, slot)

        def send(x):
            data, sw = w.tok.raw(x)
            return data + bytes([sw >> 8, sw & 0xFF])
        rsp, sw = q.transmit_short(send, "SIGN", a[7:-2])
        self.assertEqual(sw, q.SW_OK)
        self.assertTrue(q.verify_dsc(pub, q.tlv_dict(rsp)[T["DSC_SIG_RAW"]], h))


if __name__ == "__main__":
    unittest.main()
