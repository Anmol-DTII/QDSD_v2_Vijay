"""QDSD token protocol v3.2: reference encoder/decoder (PROTOCOL.md).

Written independently of the firmware's C encoder, from the spec, so the host
tests catch disagreements between the two. Intended as the starting point for
the Ascert.en Middleware (APDUs, receipts) and DTI Cloud / Subscriber App
(statements they sign).

Requires: cryptography >= 41.

Protocol v3.1 (Ascert.en Flows v3.4): login session, POLICY, approval method in
every phone-signed statement; v3.1 adds RSA-2048 DSC keys (public keys travel
as DER SubjectPublicKeyInfo), digest-mode CSR signing, several outstanding
nonces, and firmware update over the token interface.

Protocol v3.2: USB CCID transport, records kept inside the secure elements,
signing receipts kept on the token (GET_RECEIPT), DELETE_KEY, separate DSC key
attestation (GET_KEY_ATTESTATION), factory reset of both secure elements
(FACTORY_WIPE), institutional certificate import from .pfx (IMPORT_BEGIN /
IMPORT_DATA), key origin in every key statement and receipt.

Protocol v3.3 (firmware 0.6.1-0.6.2, GET_INFO minor 3): SIGN_ASSERTION and SIGN_RECEIPT
carry keygen_seq (the approval names the key, not only the slot); GET_INFO
returns a session epoch (39); 6984 on SIGN/LOGIN carries a reason (3A); ISO
7816 command chaining and GET RESPONSE for hosts limited to short APDUs;
GET_RECEIPT by request id (tag 08).
apdu() now builds extended-form APDUs (whole response at once); short=True
gives the short form, and transmit_short() runs chaining + GET RESPONSE.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

AID = bytes.fromhex("A0000000445449494C03")
MAGIC = b"QDS3"

# Field tags (§2.3)
F = dict(
    DEVICE_ID=0x01, BINDING_NO=0x02, STATE=0x03, CHALLENGE=0x04, NONCE=0x05,
    H_TBS=0x06, H_CTX=0x07, REQUEST_ID=0x08, TIME=0x09, ACTIVATION_PUB=0x0A,
    NEW_KEY_HASH=0x0B, KEYGEN_SEQ=0x0C, SIGN_COUNTER=0x0D, KEY_SLOT=0x0E,
    DSC_PUB=0x0F, SIG_HASH=0x10, FW_VERSION=0x11, VALID_UNTIL=0x12,
    SETTING_REF=0x13, STATUS=0x14, KEYGEN_COUNTER=0x15, DEVICE_PUB=0x16,
    CMD_KEY_HASH=0x17, ACT_KEY_HASH=0x18, DEVICE_CERT_HASH=0x19,
    POLICY_NO=0x1A, POLICY_FLAGS=0x1F, METHOD=0x26, SESSION=0x27,
    CERT_HASH=0x2C, KEY_ORIGIN=0x2D, IMPORT_PUB=0x2E, KEY_ALG=0x2F,
)
T = dict(
    CHIP_UID=0x1B, VENDOR_ATT=0x1C, DEVICE_CERT=0x1D, CMD_PUB=0x1E,
    SLOT_ENTRY=0x20, PROTO_VER=0x21, SLOT_COUNT=0x22, OFFSET=0x23, TOTAL=0x24,
    CHUNK=0x25, STMT=0x70, STMT_SIG=0x71, DSC_SIG_RAW=0x72, DSC_SIG_DER=0x73,
    CRI=0x74, CSR_DIGEST=0x75, IMAGE_SIZE=0x28, IMAGE_SHA256=0x29,
    IMAGE_OFFSET=0x2A, PROTO_MINOR=0x2B, WIPE_SECRET_DEV=0x31,
    WIPE_SECRET_DSC=0x32, AGENT_PUB=0x34, IMPORT_CT=0x35, IMPORT_CERT=0x36,
    DSC_UID=0x37, KEY_VENDOR_ATT=0x38, SESSION_EPOCH=0x39, NONCE_STATUS=0x3A,
)

# Purposes (§2.4) and their field lists in wire order
P = dict(
    BIND=0x01, KEYGEN_CONSENT=0x02, KEYGEN_ENVELOPE=0x03, SIGN_ASSERTION=0x04,
    REBIND=0x05, RESET=0x06, POLICY=0x07, LOGIN_ASSERTION=0x08,
    DELETE_KEY=0x09, IMPORT_CONSENT=0x0A, WIPE=0x0B,
    ATTEST=0x81, FACTORY_RECEIPT=0x82,
    BIND_RECEIPT=0x83, KEY_ATTEST=0x84, SIGN_RECEIPT=0x85, REBIND_RECEIPT=0x86,
    RESET_RECEIPT=0x87, POLICY_RECEIPT=0x88, LOGIN_RECEIPT=0x89,
    IMPORT_OFFER=0x8A, KEY_STATUS=0x8B, KEY_DELETED=0x8C,
)
SCHEMA: Dict[int, List[str]] = {
    P["BIND"]: ["DEVICE_ID", "BINDING_NO", "ACTIVATION_PUB", "POLICY_FLAGS"],
    P["KEYGEN_CONSENT"]: ["DEVICE_ID", "KEYGEN_SEQ", "VALID_UNTIL", "METHOD"],
    P["KEYGEN_ENVELOPE"]: ["DEVICE_ID", "KEYGEN_SEQ", "SETTING_REF"],
    P["SIGN_ASSERTION"]: ["DEVICE_ID", "NONCE", "H_TBS", "H_CTX", "REQUEST_ID",
                          "TIME", "KEYGEN_SEQ", "KEY_SLOT", "METHOD"],
    P["REBIND"]: ["DEVICE_ID", "BINDING_NO", "NEW_KEY_HASH", "METHOD"],
    P["RESET"]: ["DEVICE_ID", "BINDING_NO"],
    P["POLICY"]: ["DEVICE_ID", "TIME", "POLICY_NO", "POLICY_FLAGS", "METHOD"],
    P["LOGIN_ASSERTION"]: ["DEVICE_ID", "NONCE", "TIME", "METHOD"],
    P["ATTEST"]: ["DEVICE_ID", "BINDING_NO", "STATE", "CHALLENGE", "SIGN_COUNTER",
                  "FW_VERSION", "KEYGEN_COUNTER", "CMD_KEY_HASH", "ACT_KEY_HASH",
                  "POLICY_NO", "POLICY_FLAGS"],
    P["FACTORY_RECEIPT"]: ["DEVICE_ID", "BINDING_NO", "STATE", "SIGN_COUNTER",
                           "KEYGEN_COUNTER", "CMD_KEY_HASH", "DEVICE_CERT_HASH"],
    P["BIND_RECEIPT"]: ["DEVICE_ID", "BINDING_NO", "STATE", "ACT_KEY_HASH",
                        "POLICY_NO", "POLICY_FLAGS"],
    P["KEY_ATTEST"]: ["DEVICE_ID", "KEYGEN_SEQ", "KEY_SLOT", "DSC_PUB", "KEY_ORIGIN"],
    P["SIGN_RECEIPT"]: ["DEVICE_ID", "NONCE", "H_TBS", "H_CTX", "REQUEST_ID",
                        "KEYGEN_SEQ", "SIGN_COUNTER", "KEY_SLOT", "SIG_HASH", "STATUS",
                        "KEY_ORIGIN"],
    # v3.2
    P["DELETE_KEY"]: ["DEVICE_ID", "TIME", "KEYGEN_SEQ", "KEY_SLOT", "METHOD"],
    P["IMPORT_CONSENT"]: ["DEVICE_ID", "KEYGEN_SEQ", "VALID_UNTIL", "METHOD",
                          "CERT_HASH", "KEY_ALG"],
    P["WIPE"]: ["DEVICE_ID", "BINDING_NO"],
    P["IMPORT_OFFER"]: ["DEVICE_ID", "KEYGEN_SEQ", "CERT_HASH", "IMPORT_PUB", "KEY_ALG"],
    P["KEY_STATUS"]: ["DEVICE_ID", "CHALLENGE", "KEYGEN_SEQ", "KEY_SLOT", "DSC_PUB",
                      "STATUS", "CERT_HASH", "KEY_ORIGIN"],
    P["KEY_DELETED"]: ["DEVICE_ID", "KEYGEN_SEQ", "KEY_SLOT"],
    P["REBIND_RECEIPT"]: ["DEVICE_ID", "BINDING_NO", "ACT_KEY_HASH"],
    P["RESET_RECEIPT"]: ["DEVICE_ID", "BINDING_NO", "STATE"],
    P["POLICY_RECEIPT"]: ["DEVICE_ID", "POLICY_NO", "POLICY_FLAGS"],
    P["LOGIN_RECEIPT"]: ["DEVICE_ID", "NONCE", "POLICY_NO", "SESSION"],
}
U32_FIELDS = {"BINDING_NO", "KEYGEN_SEQ", "SIGN_COUNTER", "KEYGEN_COUNTER", "POLICY_NO"}
U64_FIELDS = {"TIME", "VALID_UNTIL"}
U8_FIELDS = {"STATE", "KEY_SLOT", "STATUS", "POLICY_FLAGS", "METHOD", "SESSION",
             "KEY_ORIGIN", "KEY_ALG"}

# Approval methods (§2.4), policy flags (§2.5), SKIPPED context marker (§2.6)
METHOD = dict(BIOMETRIC=1, PATTERN=2, DEVICE_PIN=3, ASCERTEN_PIN=4, NONE=5)
POLICY_LOGIN_REQUIRED = 0x01
SESSION = dict(LOGGED_OUT=0, LOGGED_IN=1)
ORIGIN = dict(GENERATED=0, IMPORTED=1)                     # §2.8
RCPT_STATUS = dict(OK=0, SE_FAILED=1, INTERRUPTED=2)       # SIGN_RECEIPT STATUS
SLOT_STATUS = dict(EMPTY=0, PENDING=1, CERTIFIED=2)
# Reason in 3A with 6984 for SIGN / LOGIN (§4.8)
NONCE_WHY = dict(EXPIRED=1, REPLACED=2, DISCARDED=3, UNKNOWN=4, USED=5, FAILS=6,
                 KEY_CHANGED=7)

INS = dict(
    SELECT=0xA4, GET_INFO=0xC1, GET_CERT=0xC3, WRITE_CERT=0xC5,
    GET_DEVICE_CERT=0xD0, ATTEST=0xD1, BIND=0xD2, GET_SESSION_NONCE=0xD3,
    SIGN=0xD4, KEYGEN=0xD5, SIGN_CSR=0xD6, REBIND=0xD7, RESET=0xD8,
    LOGIN=0xD9, LOGOUT=0xDA, POLICY=0xDB,
    DELETE_KEY=0xDC, GET_RECEIPT=0xDD, GET_KEY_ATTESTATION=0xDE,
    IMPORT_BEGIN=0xDF, IMPORT_DATA=0xCB, GET_RESPONSE=0xC0,
    FACTORY_INIT=0xE0, FACTORY_PERSONALISE=0xE1, FACTORY_CLOSE=0xE2,
    FACTORY_WIPE=0xE3,
    UPDATE_BEGIN=0xE8, UPDATE_WRITE=0xE9, UPDATE_FINISH=0xEA,
)
ALG = dict(P256=0x00, RSA2048=0x01)        # KEYGEN P1
CSR_MODE = dict(FULL=0x00, DIGEST=0x01)   # SIGN_CSR P2
LC = dict(MANUFACTURING=0, UNASSIGNED=1, BOUND=2, READY=3, FAULT=0xFF)

SW_OK = 0x9000


# ── TLV ──────────────────────────────────────────────────────────────

def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        hdr = bytes([tag, n])
    elif n <= 0xFF:
        hdr = bytes([tag, 0x81, n])
    elif n <= 0xFFFF:
        hdr = bytes([tag, 0x82]) + struct.pack(">H", n)
    else:
        raise ValueError("TLV too long")
    return hdr + value


def tlv_parse(buf: bytes) -> List[Tuple[int, bytes]]:
    out, i = [], 0
    while i < len(buf):
        if i + 2 > len(buf):
            raise ValueError("truncated TLV")
        tag, l0 = buf[i], buf[i + 1]
        i += 2
        if l0 < 0x80:
            n = l0
        elif l0 == 0x81:
            n = buf[i]; i += 1
        elif l0 == 0x82:
            n = struct.unpack(">H", buf[i:i + 2])[0]; i += 2
        else:
            raise ValueError("bad TLV length")
        if i + n > len(buf):
            raise ValueError("truncated TLV value")
        out.append((tag, buf[i:i + n]))
        i += n
    return out


def tlv_dict(buf: bytes) -> Dict[int, bytes]:
    d: Dict[int, bytes] = {}
    for tag, val in tlv_parse(buf):
        if tag in d and tag != T["SLOT_ENTRY"]:
            raise ValueError(f"duplicate tag {tag:#x}")
        d[tag] = val
    return d


# ── keys & signatures ────────────────────────────────────────────────

def pub_bytes(key) -> bytes:
    pk = key.public_key() if hasattr(key, "public_key") else key
    return pk.public_bytes(serialization.Encoding.X962,
                           serialization.PublicFormat.UncompressedPoint)


def pub_from_bytes(b: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b)


def sign_der(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg, ec.ECDSA(hashes.SHA256()))


def sign_raw(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    r, s = decode_dss_signature(sign_der(priv, msg))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der(raw: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                int.from_bytes(raw[32:], "big"))


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) == 64:
        sig = raw_to_der(sig)
    try:
        pub_from_bytes(pub).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


H_CTX_SKIPPED = hashlib.sha256(b"QDSD-CTX-SKIPPED").digest()


# ── statements ───────────────────────────────────────────────────────

def _enc_field(name: str, v) -> bytes:
    if name in U32_FIELDS:
        return struct.pack(">I", v)
    if name in U64_FIELDS:
        return struct.pack(">Q", v)
    if name in U8_FIELDS:
        return bytes([v])
    return bytes(v)


def stmt_build(purpose: str, **fields) -> bytes:
    p = P[purpose]
    names = SCHEMA[p]
    if set(fields) != set(names):
        raise ValueError(f"{purpose}: need {names}, got {sorted(fields)}")
    body = b"".join(tlv(F[n], _enc_field(n, fields[n])) for n in names)
    return MAGIC + bytes([p]) + body


@dataclass
class Stmt:
    purpose: int
    raw: bytes
    fields: Dict[str, object]

    def __getitem__(self, k):
        return self.fields[k]


def stmt_parse(raw: bytes) -> Stmt:
    if raw[:4] != MAGIC:
        raise ValueError("bad magic")
    p = raw[4]
    names = SCHEMA[p]
    items = tlv_parse(raw[5:])
    if [t for t, _ in items] != [F[n] for n in names]:
        raise ValueError("non-canonical statement")
    fields: Dict[str, object] = {}
    for (t, v), n in zip(items, names):
        if n in U32_FIELDS:
            fields[n] = struct.unpack(">I", v)[0]
        elif n in U64_FIELDS:
            fields[n] = struct.unpack(">Q", v)[0]
        elif n in U8_FIELDS:
            fields[n] = v[0]
        else:
            fields[n] = v
    return Stmt(p, raw, fields)


def signed(stmt: bytes, priv, der: bool = False) -> bytes:
    """70/71 wire form, signed by priv (cloud command key or phone key)."""
    sig = sign_der(priv, stmt) if der else sign_raw(priv, stmt)
    return tlv(T["STMT"], stmt) + tlv(T["STMT_SIG"], sig)


def open_signed(rsp: Dict[int, bytes], device_pub: bytes, purpose: str) -> Stmt:
    """Verify a token-signed statement in a response and parse it."""
    raw, sig = rsp[T["STMT"]], rsp[T["STMT_SIG"]]
    if not verify(device_pub, raw, sig):
        raise ValueError("device signature invalid")
    st = stmt_parse(raw)
    if st.purpose != P[purpose]:
        raise ValueError("unexpected purpose")
    return st


# ── APDUs ────────────────────────────────────────────────────────────

def apdu(ins: str, data: bytes = b"", p1: int = 0, p2: int = 0, cla: int = 0x80,
         short: bool = False) -> bytes:
    """Extended form by default (Lc 3 bytes, Le 00 00: whole response at once).

    short=True gives the short form (Lc 1 byte, no Le), as a host limited to
    short APDUs sends it; a response over 256 bytes then comes back with 61xx
    and needs GET RESPONSE (see transmit_short).
    """
    hdr = bytes([cla, INS[ins], p1, p2])
    if short:
        if len(data) > 255:
            raise ValueError("short APDU data > 255: use chained()")
        return hdr + (bytes([len(data)]) + data if data else b"")
    if not data:
        return hdr + b"\x00\x00\x00"
    return hdr + b"\x00" + struct.pack(">H", len(data)) + data + b"\x00\x00"


def chained(ins: str, data: bytes, p1: int = 0, p2: int = 0, piece: int = 255) -> List[bytes]:
    """ISO 7816-4 command chaining: CLA 0x90 for every piece but the last (0x80)."""
    parts = [data[i:i + piece] for i in range(0, len(data), piece)] or [b""]
    out = []
    for n, part in enumerate(parts):
        cla = 0x80 if n == len(parts) - 1 else 0x90
        out.append(bytes([cla, INS[ins], p1, p2]) + (bytes([len(part)]) + part if part else b""))
    return out


def transmit_short(send, ins: str, data: bytes = b"", p1: int = 0, p2: int = 0,
                   piece: int = 255) -> Tuple[bytes, int]:
    """Run one command using short APDUs only: chaining out, GET RESPONSE back.

    send(apdu) -> raw response (data || SW1 SW2).
    """
    rsp = b""
    pieces = chained(ins, data, p1, p2, piece)
    for n, a in enumerate(pieces):
        r = send(a)
        sw = (r[-2] << 8) | r[-1]
        if n < len(pieces) - 1 and sw != SW_OK:
            return r[:-2], sw  # a chained piece was refused
    body = r[:-2]
    rsp += body
    while (sw >> 8) == 0x61:
        le = sw & 0xFF
        r = send(bytes([0x00, INS["GET_RESPONSE"], 0x00, 0x00, le]))
        body, sw = r[:-2], (r[-2] << 8) | r[-1]
        rsp += body
    return rsp, sw


def select() -> bytes:
    return bytes([0x00, 0xA4, 0x04, 0x00, len(AID)]) + AID


def chunked(ins: str, payload: bytes, chunk: int = 1024, p1: int = 0) -> List[bytes]:
    """Split payload into WRITE_CERT / IMPORT_DATA APDUs: first carries TOTAL (P2=00)."""
    out = []
    for i in range(0, len(payload), chunk):
        part = payload[i:i + chunk]
        if i == 0:
            out.append(apdu(ins, tlv(T["TOTAL"], struct.pack(">H", len(payload))) +
                            tlv(T["CHUNK"], part), p1=p1, p2=0))
        else:
            out.append(apdu(ins, tlv(T["CHUNK"], part), p1=p1, p2=1))
    return out


# ── USB CCID framing (v3.2 transport) ────────────────────────────────

CCID = dict(XFR_BLOCK=0x6F, POWER_ON=0x62, POWER_OFF=0x63, GET_SLOT_STATUS=0x65,
            GET_PARAMETERS=0x6C, SET_PARAMETERS=0x61, RESET_PARAMETERS=0x6D,
            ESCAPE=0x6B, ABORT=0x72, DATA_BLOCK=0x80, SLOT_STATUS=0x81,
            PARAMETERS=0x82)


def ccid_msg(mtype: int, data: bytes = b"", seq: int = 0, slot: int = 0,
             param: bytes = b"\x00\x00\x00") -> bytes:
    """PC_to_RDR message: type, dwLength LE, bSlot, bSeq, 3 message-specific bytes."""
    return bytes([mtype]) + struct.pack("<I", len(data)) + bytes([slot, seq]) + param + data


def ccid_parse(msg: bytes) -> Tuple[int, int, int, int, int, bytes]:
    """RDR_to_PC: (type, seq, bStatus, bError, bParam, data)."""
    n = struct.unpack("<I", msg[1:5])[0]
    if len(msg) != 10 + n:
        raise ValueError("CCID length mismatch")
    return msg[0], msg[6], msg[7], msg[8], msg[9], msg[10:]


def split_rsp(rsp: bytes) -> Tuple[bytes, int]:
    return rsp[:-2], (rsp[-2] << 8) | rsp[-1]


# ── minimal DER for CSR assembly ─────────────────────────────────────

def der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n <= 0xFF:
        ln = bytes([0x81, n])
    else:
        ln = bytes([0x82]) + struct.pack(">H", n)
    return bytes([tag]) + ln + body


def spki_of(key) -> bytes:
    """DER SubjectPublicKeyInfo for a key object, a 65-byte P-256 point, or SPKI bytes."""
    if isinstance(key, (bytes, bytearray)):
        key = bytes(key)
        if key[:1] == b"\x30":
            return key
        key = pub_from_bytes(key)
    if hasattr(key, "public_key"):
        key = key.public_key()
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def load_spki(spki: bytes):
    return serialization.load_der_public_key(spki_of(spki))


def is_rsa(spki: bytes) -> bool:
    return isinstance(load_spki(spki), rsa.RSAPublicKey)


def verify_dsc(spki: bytes, sig: bytes, digest: bytes) -> bool:
    """Check a DSC signature over a SHA-256 digest (raw r||s or RSA PKCS#1 v1.5)."""
    pk = load_spki(spki)
    try:
        if isinstance(pk, rsa.RSAPublicKey):
            pk.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        else:
            if len(sig) == 64:
                sig = raw_to_der(sig)
            pk.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False


def build_cri(subject_der: bytes, pub) -> bytes:
    """PKCS#10 CertificationRequestInfo (no attributes) for a P-256 or RSA key."""
    return der(0x30, b"\x02\x01\x00" + subject_der + spki_of(pub) + b"\xa0\x00")


def build_csr(cri: bytes, sig: bytes, rsa_key: bool = False) -> bytes:
    """Assemble a PKCS#10 request: sig is DER ECDSA, or the raw RSA signature."""
    if rsa_key:
        alg = der(0x30, der(0x06, bytes.fromhex("2A864886F70D01010B")) + b"\x05\x00")
    else:
        alg = der(0x30, der(0x06, bytes.fromhex("2A8648CE3D040302")))  # ecdsa-with-SHA256
    return der(0x30, cri + alg + der(0x03, b"\x00" + sig))


def mcuboot_header(major: int, minor: int, rev: int, build: int = 0) -> bytes:
    """Minimal MCUboot image header (32 bytes) for update tests."""
    return (struct.pack("<IIHHII", 0x96F3B83D, 0, 32, 0, 0, 0) +
            struct.pack("<BBHI", major, minor, rev, build) + b"\x00" * 4)


# ── v3.2: institutional certificate import (.pfx) ────────────────────

IMPORT_KDF_LABEL = b"QDSD-IMPORT-V1"
IMPORT_CHECK_LABEL = b"QDSD-IMPORT-CHECK"


def import_plaintext(key) -> Tuple[int, bytes]:
    """(alg, private key bytes) as the token expects them inside the wrap.

    P-256: d (32 bytes). RSA-2048 (e = 65537): p || q || dp || dq || qinv,
    each 128 bytes big-endian.
    """
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return ALG["P256"], key.private_numbers().private_value.to_bytes(32, "big")
    n = key.private_numbers()
    if key.key_size != 2048 or n.public_numbers.e != 65537:
        raise ValueError("only RSA-2048 with e = 65537")
    parts = [n.p, n.q, n.dmp1, n.dmq1, n.iqmp]
    return ALG["RSA2048"], b"".join(x.to_bytes(128, "big") for x in parts)


def import_wrap(offer: "Stmt", device_id: bytes, key, cert_der: bytes,
                agent_key: Optional[ec.EllipticCurvePrivateKey] = None,
                iv: Optional[bytes] = None) -> bytes:
    """Build the IMPORT_DATA package for the token's signed IMPORT_OFFER.

    What the Ascert.en agent does after opening the .pfx with the user's
    password. The caller must already have verified the offer's device
    signature. The package is TLV 36 (certificate), 34 (agent ephemeral
    key), 35 (iv || AES-256-GCM ciphertext || tag).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os

    alg, pt = import_plaintext(key)
    if alg != offer["KEY_ALG"] or sha256(cert_der) != offer["CERT_HASH"]:
        raise ValueError("offer does not match this certificate")
    agent_key = agent_key or ec.generate_private_key(ec.SECP256R1())
    token_pub = offer["IMPORT_PUB"]
    z = agent_key.exchange(ec.ECDH(), pub_from_bytes(token_pub))
    k = sha256(IMPORT_KDF_LABEL + z + token_pub + pub_bytes(agent_key))
    aad = device_id + struct.pack(">I", offer["KEYGEN_SEQ"]) + offer["CERT_HASH"] + bytes([alg])
    iv = iv or os.urandom(12)
    ct = AESGCM(k).encrypt(iv, pt, aad)  # ciphertext || tag
    return (tlv(T["IMPORT_CERT"], cert_der) + tlv(T["AGENT_PUB"], pub_bytes(agent_key)) +
            tlv(T["IMPORT_CT"], iv + ct))
