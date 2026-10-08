# Secure-element object map (firmware 0.6, protocol v3.2)

Every secure object QDSD creates sits in one of two ranges, one per element.
The ranges are Kconfig options, so a deployment can move them (for example to
stay clear of another application on the same chip). The defaults are the ids
firmware 0.3–0.5 used, so tokens in the field keep working.

Source of truth: `include/qdsd/qdsd_objids.h`.

| Kconfig | Default | Element |
|---|---|---|
| `CONFIG_QDSD_OID_SE050_BASE` | `0x51DE0000` | SE050 (device trust) |
| `CONFIG_QDSD_OID_SE052F_BASE` | `0x5D5C0000` | SE052F (DSC keys) |

Changing a base on a token that already has objects orphans them: only do it
for new production, together with the factory tool.

## SE050 — device trust

| Offset | Default id | Type | Size | Content | Created | Removed |
|---|---|---|---|---|---|---|
| `+0x0001` | `0x51DE0001` | EC key pair, NIST P-256 | – | Device key | FACTORY_INIT | FACTORY_WIPE |
| `+0x0002` | `0x51DE0002` | EC public key, NIST P-256 | 65 | DTI command key | FACTORY_PERSONALISE | FACTORY_WIPE |
| `+0x0003` | `0x51DE0003` | EC public key, NIST P-256 | 65 | Subscriber activation key | BIND, REBIND | RESET, FACTORY_WIPE |
| `+0x0010` | `0x51DE0010` | Binary | 96 | Lifecycle record + journal (CRC) | first write | FACTORY_WIPE |
| `+0x0021` | `0x51DE0021` | Counter | 4 | Binding number | FACTORY_CLOSE | FACTORY_WIPE |
| `+0x0022` | `0x51DE0022` | Counter | 4 | Keygen / import number | FACTORY_CLOSE | FACTORY_WIPE |
| `+0x0023` | `0x51DE0023` | Counter | 4 | Sign counter | FACTORY_CLOSE | FACTORY_WIPE |
| `+0x0024` | `0x51DE0024` | Counter | 4 | Policy number | FACTORY_CLOSE (or first boot of 0.4+ on a 0.3 token) | FACTORY_WIPE |
| `+0x0030` | `0x51DE0030` | Binary | ≤ 2048 | Device certificate (DER) | FACTORY_PERSONALISE (or migration from 0.3–0.5) | FACTORY_WIPE |
| `+0x0100 + n` | `0x51DE0100..010F` | Binary | 528 | Signing receipt ring entry `n` (n = sign_counter mod 16) | FACTORY_CLOSE (or first boot on a 0.3–0.5 token) | contents cleared by RESET; objects by FACTORY_WIPE |

Receipt entry layout: `'R'`, kind (`0` empty, `1` pending, `2` final),
statement length u16, DSC signature length u16, 2 reserved, statement (≤ 200),
device signature r‖s (64), DSC signature (≤ 256). Bytes 0–207 are one atomic
write.

## SE052F — DSC keys

| Offset | Default id | Type | Size | Content | Created | Removed |
|---|---|---|---|---|---|---|
| `+0x0000 + slot` | `0x5D5C0000..03` | EC key pair (P-256) or RSA key pair (2048, CRT, e = 65537) | – | DSC key of the slot | KEYGEN, IMPORT_DATA | KEYGEN reuse, DELETE_KEY, RESET, FACTORY_WIPE |
| `+0x0100 + slot` | `0x5D5C0100..03` | Binary | 48 | Slot record | KEYGEN, IMPORT, migration | DELETE_KEY empties it; RESET, FACTORY_WIPE delete it |
| `+0x0200 + slot` | `0x5D5C0200..03` | Binary | ≤ 2048 | DSC certificate (DER), bank A | WRITE_CERT, IMPORT_DATA, migration | DELETE_KEY, RESET, FACTORY_WIPE; a replaced certificate's bank |
| `+0x0200 + N + slot` | `0x5D5C0204..07` | Binary | ≤ 2048 | DSC certificate (DER), bank B (N = slot count) | WRITE_CERT replacing a certificate | as bank A |

Slot record layout: `'S'`, version `02`, status (`0` empty, `1` pending, `2`
certified), alg (`0` P-256, `1` RSA-2048), origin (`0` generated, `1`
imported), csr_mode (`0` none, `1` full, `2` digest), keygen_seq u32,
certificate length u16, certificate SHA-256 (32), current certificate bank
(byte 44: `0` A, `1` B), 3 reserved. One atomic write. A new certificate goes
into the other bank and the record switches to it, so a power cut always
leaves one complete certificate.

## UserIDs and NXP-reserved objects

| Id | Element | Type | Content | Notes |
|---|---|---|---|---|
| `0x7FFF0205` | both | UserID (16 bytes) | FACTORY_RESET secret | NXP-reserved FACTORY_RESET authentication object. Created at FACTORY_PERSONALISE with a per-device secret only DTI holds. A session authenticated with it is the only way to run DeleteAll (FACTORY_WIPE). Deleted by DeleteAll itself. |
| `0x7FFF0206` | both | Binary (read only) | 18-byte unique id | SE050 id goes into device_id; SE052F id is returned by GET_KEY_ATTESTATION (`37`) |
| `0xF0000012` | both | EC key (NXP) | NXP attestation key | Signs `ReadObject_W_Attst` (device key at FACTORY_INIT, DSC keys at GET_KEY_ATTESTATION). Trust-provisioned: survives DeleteAll |
| Platform SCP03 keys | both | ISD keys | I²C link protection | Not applet objects; survive DeleteAll |

## Object policies

All QDSD objects are still created with the default (NULL) policy, as in
Phase 2 and firmware 0.3–0.5. Restricting them (sign + read-public only for
keys, no delete except from the FACTORY_RESET session for device-trust
objects, increment-only counters) is a hardening step listed in
`docs/BRINGUP.md` §3. It needs lab verification first: a wrong policy can make
an object impossible to use or delete, and Phase 2 showed the encoding
(`[len 08][auth id u32][access rules u32]`, AN12413 §3.7) works on this PCBA
only for the SE052F UserID case so far.

## Resource use (default build)

| Element | Objects | Data |
|---|---|---|
| SE050 | 1 key pair, 2 public keys, 4 counters, 18 binary objects, 1 UserID | about 11 KB (8.4 KB receipts, ≤ 2 KB device certificate) |
| SE052F | up to 4 key pairs, 8–12 binary objects, 1 UserID | ≤ 8.4 KB (certificates; a second bank exists only while a certificate is being replaced) |

Endurance: each SIGN writes one receipt entry three times; with 16 entries,
each entry is written about once per 5 signatures.
