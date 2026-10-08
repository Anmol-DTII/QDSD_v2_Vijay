# QDSD Token Protocol v3.3 (Ascert.en Flows v3.4)

This is the contract between the Ascert.en Middleware (PC) and the QDSD token
firmware. DTI Cloud and the Subscriber App produce some of the signed
statements described here, so they must follow the same encoding.

Status: draft 3.3, 8 Oct 2026, **implemented by firmware 0.7.0**. Supersedes
3.2 (firmware 0.6.0, lab only) and 3.1 (firmware 0.5.0). GET_INFO `2B`
reports the minor version, so the agent and cloud can tell a 3.2 token (which
signs SIGN_ASSERTION without keygen_seq) from a 3.3 one. Same AID and statement magic as 3.0/3.1: a v3.1
middleware keeps working for every command it knows, except that the token is
now a USB CCID reader (§1), so the transport layer must change. Builds on
protocol v2 (`claude/qdsd-token-protocol-v2.md`). Everything marked
**[decide]** still needs a decision from the DTII product or security team;
§9 says what firmware 0.6 does in each case until then.

**What changed in v3.2** (review of firmware 0.5 by the DTII team):

| # | Change | Why |
|---|---|---|
| 16 | USB CCID smart-card reader class (`0x0B`) replaces the WinUSB vendor interface; APDUs travel in `PC_to_RDR_XfrBlock` | Every desktop OS binds its own driver; PC/SC everywhere (§1) |
| 17 | Every SIGN receipt (and the DSC signature) is saved in the SE050 before the reply; GET_RECEIPT fetches it again, also while logged out; a signature cut off by power loss gets a receipt with status `02` at next boot | Lost replies and power cuts no longer lose receipts (§4.15, §4.19) |
| 18 | Device certificate, DSC certificates and slot records move from MCU flash into the secure elements; tokens made by 0.3–0.5 are migrated at first boot | Records live in, and are deleted from, the element that holds the keys (§7) |
| 19 | DELETE_KEY: phone-approved removal of one DSC key, its certificate and record | Upload / retrieve / delete of user certificates; revocation stays at the CA (§4.20) |
| 20 | GET_KEY_ATTESTATION: per-key status signed by the device key **plus** the SE052F's own NXP attestation of the key | DSC attestation separate from device attestation (ATTEST) (§4.21) |
| 21 | FACTORY_WIPE: factory reset of both secure elements, gated inside each element by a FACTORY_RESET UserID secret only DTI holds | Refurbish or repair a token (§4.23) |
| 22 | IMPORT_BEGIN / IMPORT_DATA: institutional certificate and key from a .pfx, key encrypted to the token, phone-approved, permanently marked *imported* | Institutional certificates (§4.22) |
| 23 | `2D` key_origin in KEY_ATTEST, SIGN_RECEIPT and slot entries; `14` status adds `02` interrupted | An imported key can never pass as one generated in the token |
| 24 | Phone and cloud signatures are checked inside the SE050 (`ECDSAVerify` with the stored key) | Mobile key registration, authentication and signing authorisation all checked in the secure element (§7) |
| 25 | device_id now also covers the device public key | A wiped and re-made token gets a new identity; nothing signed for its previous life applies (§4.3) |
| 26 | Published object-id map, ranges set by Kconfig (`docs/OBJECT_IDS.md`) | Custom object ids |
| 27 | GET_INFO `2B` protocol minor = **2**; slot entry `20` gains a 9th byte (key origin) | Middleware feature detection; parsers must read entries by length |

**What changed in v3.3** (firmware 0.6.1–0.7.0; middleware review of 0.6.0):

| # | Change | Why |
|---|---|---|
| 28 | A failed SELECT (other AID, wrong P1/P2 or CLA) keeps the current selection | Windows and other token software SELECT their own AIDs on every card (§4.1) |
| 29 | Re-SELECTing our AID keeps the login, the pairing session and the idle timer; only the first SELECT of a USB connection sets the starting session | The agent can re-SELECT safely after any interference (§3.2) |
| 30 | A CCID card power cycle (`IccPowerOn`/`IccPowerOff`) needs SELECT again and aborts uploads, but keeps the login and the outstanding nonces; only a USB reset or unplug ends the session | `SCardReconnect` with reset, Windows recovery and pcsc-lite idle power-down no longer log the user out or cancel approvals (§1, §3.2) |
| 31 | `0C` keygen_seq in SIGN_ASSERTION and SIGN_RECEIPT; KEYGEN, IMPORT_DATA and DELETE_KEY no longer discard nonces | An approval names the key, not just the slot; a DSC download no longer cancels signatures waiting on the phone; the SER records exactly which key signed (§4.15) |
| 32 | `39` session epoch (random u32) in GET_INFO, both forms | The agent knows for certain whether the session was reset since it last looked (§4.2) |
| 33 | `3A` nonce status with every `6984` from SIGN and LOGIN | The app can say "approval timed out" or "cancelled, try again" (§4.8) |
| 34 | ISO 7816 command chaining (CLA bit `10`) and `61xx` / GET RESPONSE for short-form commands | Fallback for any host whose CCID driver cannot do extended APDUs (§1.2) |
| 35 | GET_INFO `2B` protocol minor = **3** | What the phone signs changed (keygen_seq) and tags `39`/`3A` were added; lab tokens on 0.6.0 report `2` |
| 36 | GET_RECEIPT by `08` request_id | After a lost SIGN reply (nonce status `05`) the agent knows the request id, not the counter (§4.19) |
| 37 | A bring-up build without MCUboot (`CONFIG_QDSD_FW_UPDATE=n`, firmware 0.6.3) answers `6D00` to UPDATE_BEGIN / WRITE / FINISH; nothing else changes | Board bring-up before MCUboot works; the agent treats `6D00` as "this token cannot be updated in the field" (§4.18). Product tokens always support update |
| 38 | FACTORY_DRIVE (`80 E6`, factory only, firmware 0.7.0) writes the install drive: a read-only USB disk with the Ascert.en installer, next to the CCID reader | New users install the middleware from the token itself. No change for middleware; GET_INFO minor stays 3 (§4.3, `docs/INSTALL_DRIVE.md`) |

**What changed in v3.1** (review of firmware 0.4 by the middleware team):

| # | Change | Why |
|---|---|---|
| 10 | Up to 4 outstanding nonces; a new one replaces the oldest only when all are in use | Several signing apps (and a login) can wait for phone approval at once without cancelling each other (§1.1, §4.8) |
| 11 | SIGN_CSR digest mode (P2 = `01`), allowed once per key | Windows CNG `NCryptSignHash` and PKCS#11 `CKM_ECDSA` hand the provider only a hash (§4.12) |
| 12 | RSA-2048 DSC keys (KEYGEN P1 = `01`), RSASSA-PKCS1-v1_5 with SHA-256 | Most CA tools and portal signers expect RSA; CCA requires devices to support both SHA256-with-RSA and ECDSA-SHA256 (§4.11) |
| 13 | DSC public keys travel as DER SubjectPublicKeyInfo (`0F`), for both key types | One encoding the middleware can hand to CAPI/CNG/PKCS#11 unchanged |
| 14 | ENTER_UPDATE removed; UPDATE_BEGIN / UPDATE_WRITE / UPDATE_FINISH stream the signed image over the normal interface | No second USB device class, no SMP client, and the bootloader never needs the USB switch (§4.18) |
| 15 | GET_INFO adds `2B` protocol minor (= 1); slot entries carry the key algorithm | Middleware feature detection |

**What changed from v2** (to bring the token in line with Flows v3.2–v3.4):

| # | Change | Why (Flows) |
|---|---|---|
| 1 | New session state, LOGGED_OUT / LOGGED_IN, kept in RAM | Flow 2b, login to the QDSD |
| 2 | New commands LOGIN, LOGOUT and POLICY | Flow 2b; QDSD settings |
| 3 | New statements LOGIN_ASSERTION and POLICY (phone-signed), with receipts | Flow 2b; QDSD settings |
| 4 | New field `method` in every phone-signed statement | v3.2: the approval method is inside every assertion and recorded in the SER |
| 5 | New persistent policy flags and policy counter; BIND sets the default policy | v3.2: settings are signed by the activation key and numbered |
| 6 | GET_INFO returns only identity and state while LOGGED_OUT | v3.3: the login covers device-info reads only |
| 7 | SIGN, KEYGEN, SIGN_CSR, WRITE_CERT and GET_CERT work in either session state | v3.3: signing and DSC download don't need the login |
| 8 | GET_SESSION_NONCE is also allowed in BOUND (for LOGIN before a DSC exists) | Flow 2b |
| 9 | Protocol version 3; AID application version byte `03` | Phone-signed statement formats changed, so v2 middleware must fail cleanly |

Flows v3.4 itself (SIM verification by outgoing SMS, User Profile, optional
email verification) is between the phone and DTI Cloud only and needs no token
change.

---

## 1. Transport

| Item | Value |
|---|---|
| USB | VID `0x1915`, PID `0x520F` (development ids; production needs DTII's own), product "TrustBox", full speed |
| Class | **CCID 1.10** (smart-card reader, interface class `0x0B`): bulk OUT `0x01`, bulk IN `0x81`, interrupt IN `0x82`, 64-byte packets |
| Drivers | The OS's own: Windows `usbccid.sys` + WinSCard, macOS CryptoTokenKit / PC/SC, Linux pcsc-lite `libccid`. No QDSD driver |
| Reader | One slot, card always present (the QDSD applet). Exchange level: **extended APDU** (`dwFeatures` `0x000400BE`), so one `XfrBlock` carries one whole APDU. `dwMaxCCIDMessageLength` 2122 |
| ATR | `3B 8C 80 01 "QDSDAscertEN" TCK` (T=1, historical bytes = card name) |
| APDU | ISO 7816-4, up to **2112** bytes. Extended form (`Lc` = `00 hi lo`, `Le` = `hi lo`): the whole response (up to 2048 + 2 bytes) in one exchange. Short form: responses over 256 bytes come back with `61xx` and GET RESPONSE; long commands can be sent with chaining (§1.2) |
| Long operations | The token sends a CCID time extension every second while a command runs (RSA-2048 key generation takes several seconds) |
| Card power | `IccPowerOn` / `IccPowerOff` (`SCardReconnect`/`SCardDisconnect` with reset, Windows recovering a crashed process, pcsc-lite idle power-down): SELECT is needed again and uploads in progress (WRITE_CERT, IMPORT_DATA, UPDATE_*) are aborted; **the login, the pairing session and outstanding nonces are kept** |
| USB reset / unplug | Full reset: deselected, session ended, every nonce discarded, uploads aborted, new session epoch |

One command is processed at a time. The host must wait for the response
before sending the next command. `docs/USB_CCID.md` has the descriptor
details and the Windows Plug-and-Play note.

### 1.1 Host architecture (informative)

With CCID the token is a PC/SC card, so any process can reach it through the
OS smart-card service, and PC/SC transactions (`SCardBeginTransaction`)
serialise access between processes. The token still has one session (SELECT,
login, nonces) shared by everyone who talks to it, and every flow needs the
DTI Cloud connection, so the recommended design is unchanged: one **Ascert.en
agent per user** owns the token and the cloud connection, and the PKCS#11 /
CNG / macOS CryptoTokenKit providers are thin clients of the agent. The agent
sends one command at a time.

The agent should keep one PC/SC connection to the token open for as long as it
is plugged in, preferably `SCARD_SHARE_EXCLUSIVE`. That stops pcsc-lite
powering the card down when idle and keeps other programs from SELECTing other
AIDs, asking for nonces (which can push the agent's out of the pool) or
sending LOGOUT. The token stays robust when that is not possible: a failed
SELECT and a card reset no longer disturb the session (§3.2), and GET_INFO's
session epoch (`39`) tells the agent whether the session was reset.

### 1.2 Short-APDU hosts (chaining and GET RESPONSE)

The token reports extended-APDU exchange, and every OS's CCID driver is
expected to carry extended APDUs (bring-up check, `docs/BRINGUP.md` §5). If one
does not, the agent can use short APDUs only:

- **Command chaining** (ISO 7816-4 §5.1.1.1): split the command data into
  pieces of up to 255 bytes; send every piece but the last with CLA `90`, the
  last with CLA `80`, all with the same INS, P1, P2. Each piece but the last
  is answered `9000`; the last runs the whole command. A different command in
  the middle of a chain gets `6883` and the chain is dropped; a chain longer
  than 2112 bytes gets `6700`; SELECT cannot be chained (`6E00`). A card reset
  or USB reset drops a chain.
- **GET RESPONSE:** a command sent in short form (or by chaining) whose
  response is longer than 256 bytes gets the first 256 bytes and `61xx` (xx =
  bytes left, `00` = 256 or more). `00 C0 00 00 Le` returns the next part (up
  to Le; `00` = 256), again with `61xx` until the last part, which carries the
  command's real status word. Any other command drops the held response;
  GET RESPONSE with nothing held gets `6985`. GET RESPONSE, a SELECT (which
  then runs normally) or any different command also ends a chain.
- Extended-form commands always get the whole response at once.

`tools/qdsd_proto.py` has `chained()` and `transmit_short()`.

Chain and held-response state is shared by everyone talking to the card, so
the agent sends a chain inside one PC/SC transaction (`SCardBeginTransaction`)
or holds the card exclusively (§1.1). Interleaving cannot authorise anything,
because every sensitive field is checked against a signed statement, but it
can make a command fail.
Commands are short (well under 2 s, RSA key generation aside), so this is a
queue, not a bottleneck. Phone approvals are the slow part, and the token keeps
up to 4 nonces outstanding (§4.8), so several requests can wait for the phone
at once.

The USB data switch (TS3USB221) opens once the boot self-test passes. It stays
closed if the crypto self-test fails or a secure element does not answer, so a
faulty token never enumerates. A token whose records are inconsistent, or whose
factory reset was cut off, enumerates in service mode (§3.1) so DTI can finish
the reset.

## 2. Encoding

### 2.1 TLV

All command and response bodies are TLV sequences:

- Tag: 1 byte.
- Length: `0x00..0x7F` in one byte, `0x81 nn` for 128–255, `0x82 hh ll` for 256–65535.
- Integers are big-endian and fixed size (`u8`, `u32`, `u64`).
- Public keys are uncompressed P-256 points: 65 bytes, `04 || X || Y`.

### 2.2 Signed statements

Everything that the cloud, the phone or the token signs is a **statement**:

```
STMT = "QDS3" (4 bytes, ASCII) || purpose (1 byte) || fields
fields = TLV fields in strictly ascending tag order, each exactly once
```

- **Magic:** `"QDS3"` (was `"QDS2"`). A v2 statement can never verify as a v3
  one, so nothing signed under v2 can be replayed after the upgrade.
- **Signature:** ECDSA P-256 over SHA-256(STMT).
- **Signature encoding:** the token accepts raw `r||s` (64 bytes) or ASN.1 DER
  (as Android Keystore and the iOS Secure Enclave produce). The token always
  outputs raw `r||s`.
- **Canonical form:** the token rejects a statement that has unknown tags,
  missing tags, duplicate tags, out-of-order tags or wrong field lengths.
  Each signed byte string therefore has exactly one meaning.
- **Wire format:** a signed statement travels as two TLVs:
  `70 <STMT>` then `71 <signature>`.

### 2.3 Field tags

| Tag | Name | Size | Meaning |
|---|---|---|---|
| `01` | device_id | 16 | Token identity, fixed at factory |
| `02` | binding_no | u32 | Binding counter (monotonic, in SE050) |
| `03` | state | u8 | Lifecycle state (§3) |
| `04` | challenge | 16–32 | Freshness from the cloud or factory tool |
| `05` | nonce | 32 | N_SE from GET_SESSION_NONCE |
| `06` | h_tbs | 32 | SHA-256 to be signed by the DSC key |
| `07` | h_ctx | 32 | SHA-256 of the signing context shown to the Subscriber, or the SKIPPED marker (§2.6) |
| `08` | request_id | 16 | Cloud signing request id |
| `09` | time | u64 | Unix time in ms (informational; the token has no clock) |
| `0A` | activation_pubkey | 65 | Phone activation public key |
| `0B` | new_key_hash | 32 | SHA-256 of the new activation public key (REBIND) |
| `0C` | keygen_seq | u32 | Must equal keygen counter + 1 |
| `0D` | sign_counter | u32 | Signature counter (monotonic, in SE050) |
| `0E` | key_slot | u8 | DSC key slot, `0..N-1` |
| `0F` | dsc_pubkey | 91 or 294 | DSC public key as DER SubjectPublicKeyInfo: 91 bytes for P-256, 294 for RSA-2048 (e = 65537) |
| `10` | sig_hash | 32 | SHA-256 of the raw DSC signature (64-byte r‖s, or 256-byte RSA) |
| `11` | fw_version | 4 | major, minor, patch, build |
| `12` | valid_until | u64 | Pre-approval expiry, Unix ms (checked by the cloud, not the token) |
| `13` | setting_ref | 32 | SHA-256 of the Subscriber's signed "without asking" setting |
| `14` | status | u8 | SIGN_RECEIPT: `00` OK, `01` DSC signing failed, `02` **interrupted** (power lost after the signature was counted; no signature was released). KEY_STATUS: the slot status (`01` pending, `02` certified) |
| `15` | keygen_counter | u32 | Keygen counter (monotonic, in SE050) |
| `16` | device_pubkey | 65 | Device public key (SE050) |
| `17` | cmd_key_hash | 32 | SHA-256 of the DTI command public key held by the token |
| `18` | activation_key_hash | 32 | SHA-256 of the current activation key (32 zero bytes if none) |
| `19` | device_cert_hash | 32 | SHA-256 of the Device Certificate DER |
| `1A` | policy_no | u32 | **New.** Policy counter (monotonic, in SE050); a POLICY must carry current + 1 |
| `1F` | policy_flags | u8 | **New.** Token-enforced settings (§2.5) |
| `26` | method | u8 | **New.** Approval method used on the phone (§2.4) |
| `27` | session | u8 | **New.** `00` LOGGED_OUT, `01` LOGGED_IN |
| `2C` | cert_hash | 32 | **v3.2.** SHA-256 of a DER certificate (32 zero bytes if none) |
| `2D` | key_origin | u8 | **v3.2.** `00` generated inside the token, `01` imported (§2.8) |
| `2E` | import_pubkey | 65 | **v3.2.** The token's one-time key for a .pfx import |
| `2F` | key_alg | u8 | **v3.2.** Key algorithm, as KEYGEN P1 (`00` P-256, `01` RSA-2048) |

Response-only tags (not used inside statements):

| Tag | Name |
|---|---|
| `1B` | SE050 chip UID (18 bytes) |
| `1C` | vendor attestation: `01` command APDU, `02` attested response (SE050 `ReadObject_W_Attst`) |
| `1D` | Device Certificate DER |
| `1E` | DTI command public key (65 bytes) |
| `20` | slot entry: `slot u8, status u8, alg u8, keygen_seq u32, has_cert u8, key_origin u8` (status `00` empty, `01` key without certificate, `02` certified; alg as KEYGEN P1). **v3.2:** 9 bytes; v3.1 had 8, so read entries by their length |
| `21` | protocol version (u8 = **3**) |
| `22` | number of DSC slots (u8) |
| `23` | offset (u16) for chunked reads |
| `24` | total length (u16) for chunked reads/writes |
| `25` | chunk data |
| `28` | image size (u32), UPDATE_BEGIN |
| `29` | image SHA-256 (32), UPDATE_BEGIN |
| `2A` | image offset (u32), UPDATE_WRITE |
| `2B` | protocol minor version (u8 = **3**; `2` = firmware 0.6.0, `1` = 0.5) |
| `31` | FACTORY_RESET secret for the SE050 (16 bytes) |
| `32` | FACTORY_RESET secret for the SE052F (16 bytes) |
| `34` | agent's ephemeral P-256 public key (65), IMPORT_DATA |
| `35` | wrapped private key: IV (12) ‖ AES-256-GCM ciphertext ‖ tag (16), IMPORT_DATA |
| `36` | certificate DER being imported, IMPORT_DATA |
| `37` | SE052F chip UID (18 bytes) |
| `38` | SE052F vendor attestation of a DSC key: `01` command APDU, `02` attested response |
| `39` | session epoch (u32, random), GET_INFO (v3.3) |
| `3A` | nonce status (u8) with `6984` from SIGN and LOGIN (v3.3, §4.8) |
| `70` | statement |
| `71` | statement signature |
| `72` | DSC signature, raw: `r||s` (64) for P-256, the 256-byte signature for RSA |
| `73` | DSC signature, DER ECDSA-Sig-Value (P-256 only) |
| `74` | CertificationRequestInfo DER |
| `75` | SHA-256 digest for SIGN_CSR digest mode |

`26` method and `27` session have higher tag numbers than the response-only
tags `20`–`25`. They are still statement fields and still sort by tag, so in
every statement that carries them they come last.

### 2.4 Approval method values (`26`)

| Value | Method (Flows "QDSD settings and approval methods") | Checked by |
|---|---|---|
| `01` | Device biometric (default) | Phone OS + StrongBox / Secure Enclave |
| `02` | Device pattern | Phone OS + secure hardware |
| `03` | Device PIN | Phone OS + secure hardware |
| `04` | Own Ascert.en PIN | Subscriber App |
| `05` | No authentication | Nobody |

The token does not and cannot check how the phone was unlocked. It only
requires the field to be present and in range (`01`–`05`), so it is covered by
the activation-key signature and copied into the cloud's SER. Whether the token
should refuse some methods for SIGN is an open item (§8).

### 2.5 Policy flags (`1F`)

| Bit | Name | Default | Meaning |
|---|---|---|---|
| 0 | LOGIN_REQUIRED | 1 | The session starts LOGGED_OUT on every plug-in and needs LOGIN (Flow 2b). If 0, the session starts LOGGED_IN. |
| 1–7 | reserved | 0 | Must be 0. A POLICY with a reserved bit set is rejected (`6A80`). |

Only "Require approval to log in" is enforced by the token. The other five
Subscriber settings are enforced by DTI Cloud (DSC pre-approval, notifications)
or by the middleware and phone (skip document details), so they have no flag
here.

### 2.6 SKIPPED context marker

When the Subscriber has turned on "Skip document details when signing", the
middleware sets `h_ctx` = SHA-256(`"QDSD-CTX-SKIPPED"`). The token treats it
like any other h_ctx; the cloud recognises the value and records "context
skipped by Subscriber setting" in the SER.

### 2.7 Statement purposes

**Signed by DTI Cloud (DTI command key):**

| Purpose | Name | Fields |
|---|---|---|
| `01` | BIND | device_id, binding_no (= current + 1), activation_pubkey, policy_flags |
| `03` | KEYGEN_ENVELOPE | device_id, keygen_seq (= current + 1), setting_ref |
| `06` | RESET | device_id, binding_no (= current + 1) |
| `0B` | WIPE | device_id, binding_no (= **current**) |

BIND now carries the initial policy flags (normally `01`, LOGIN_REQUIRED). The
cloud sets them from the defaults; every later change comes from the
Subscriber's activation key through POLICY.

**Signed by the Subscriber App (activation key):**

| Purpose | Name | Fields |
|---|---|---|
| `02` | KEYGEN_CONSENT | device_id, keygen_seq (= current + 1), valid_until, method |
| `04` | SIGN_ASSERTION | device_id, nonce, h_tbs, h_ctx, request_id, time, **keygen_seq** (of the key in the slot), key_slot, method |
| `05` | REBIND | device_id, binding_no (= current + 1), new_key_hash, method |
| `07` | POLICY | device_id, time, policy_no (= current + 1), policy_flags, method |
| `08` | LOGIN_ASSERTION | device_id, nonce, time, method |
| `09` | DELETE_KEY | device_id, time, keygen_seq (of the key in the slot), key_slot, method |
| `0A` | IMPORT_CONSENT | device_id, keygen_seq (= current + 1), valid_until, method, cert_hash, key_alg |

**Signed by the token (device key, SE050):**

| Purpose | Name | Fields |
|---|---|---|
| `81` | ATTEST | device_id, binding_no, state, challenge, sign_counter, fw_version, keygen_counter, cmd_key_hash, activation_key_hash, policy_no, policy_flags |
| `82` | FACTORY_RECEIPT | device_id, binding_no, state, sign_counter, keygen_counter, cmd_key_hash, device_cert_hash |
| `83` | BIND_RECEIPT | device_id, binding_no, state, activation_key_hash, policy_no, policy_flags |
| `84` | KEY_ATTEST | device_id, keygen_seq, key_slot, dsc_pubkey, key_origin |
| `85` | SIGN_RECEIPT | device_id, nonce, h_tbs, h_ctx, request_id, **keygen_seq**, sign_counter, key_slot, sig_hash, status, key_origin |
| `86` | REBIND_RECEIPT | device_id, binding_no, activation_key_hash |
| `87` | RESET_RECEIPT | device_id, binding_no, state |
| `88` | POLICY_RECEIPT | device_id, policy_no, policy_flags |
| `89` | LOGIN_RECEIPT | device_id, nonce, policy_no, session |
| `8A` | IMPORT_OFFER | device_id, keygen_seq, cert_hash, import_pubkey, key_alg |
| `8B` | KEY_STATUS | device_id, challenge, keygen_seq, key_slot, dsc_pubkey, status, cert_hash, key_origin |
| `8C` | KEY_DELETED | device_id, keygen_seq, key_slot |

Each table lists fields in their wire order, which is ascending tag order.

> **Differences from Flows v3.4, for review**
> 1. SIGN_ASSERTION also carries `key_slot`, so a phone approval for one DSC
>    cannot be used with another DSC on the same token. (Unchanged from v2.)
> 2. BIND carries `binding_no = current + 1`, not a fixed `1` as the Flow 2
>    diagram shows. The binding counter is monotonic and survives RESET, so
>    re-pairing after a RESET binds with the next number and an old BIND
>    envelope can't be replayed. (Unchanged from v2.)
> 3. The sign, keygen, binding and policy counters are never reset, not even
>    by RESET.
> 4. The Flow 2b diagram calls the status read GET_STATUS; here it is GET_INFO.
> 5. The flows say a policy change "reaches the token at the next plug-in".
>    The token applies it whenever POLICY arrives; the middleware sends queued
>    POLICY updates first thing after SELECT (§4.0).
> 6. **v3.2, new steps for the flows document:**
>    - *Remove DSC* (Flow 3 variant): the Subscriber chooses a DSC in the app
>      and approves; the cloud relays a DELETE_KEY statement through the
>      middleware; the token returns KEY_DELETED, which the cloud stores. The
>      cloud asks the CA to revoke the certificate separately.
>    - *Institutional certificate import*: the QDSD User selects a .pfx in
>      the middleware and types its password; the middleware sends the
>      certificate's hash and type to the cloud; the Subscriber approves on
>      the phone (IMPORT_CONSENT); the middleware runs IMPORT_BEGIN /
>      IMPORT_DATA (§4.22). Who must approve for an institution (the
>      Subscriber only, or also an institution admin) is open **[decide]**.
>    - *Factory reset* (DTI service): FACTORY_WIPE (§4.23).

### 2.8 Key origin (`2D`, v3.2)

| Value | Origin | Set by |
|---|---|---|
| `00` | Generated inside the SE052F; the private key never existed anywhere else | KEYGEN |
| `01` | Imported from outside (institutional .pfx) | IMPORT_DATA |

The origin is fixed when the key enters the slot and can only be removed with
the key (DELETE_KEY, RESET, FACTORY_WIPE). It appears in KEY_ATTEST,
SIGN_RECEIPT, KEY_STATUS and the GET_INFO slot entry, so the cloud records it
in every SER. Independently, the SE052F's own attestation (§4.21) reports
whether the element generated the key or had it written from outside.

## 3. Lifecycle and session

### 3.1 Lifecycle (persistent)

| Value | State | Meaning |
|---|---|---|
| `00` | MANUFACTURING | Fresh from the line; factory commands allowed |
| `01` | UNASSIGNED | Personalised and closed; waiting for BIND |
| `02` | BOUND | Activation key installed; no certified DSC yet |
| `03` | READY | At least one DSC key has a certificate |
| `FF` | FAULT | Runtime only. Crypto self-test failed or a secure element does not answer: USB stays off. Lifecycle record or objects inconsistent, or a factory reset was cut off: **service mode**, USB on, only GET_INFO and FACTORY_WIPE answered |

```
MANUFACTURING --FACTORY_CLOSE--> UNASSIGNED --BIND--> BOUND --WRITE_CERT / IMPORT--> READY
BOUND/READY --REBIND/POLICY--> same state      BOUND/READY --RESET--> UNASSIGNED
READY --DELETE_KEY (last certified key)--> BOUND
any (incl. FAULT service) --FACTORY_WIPE--> MANUFACTURING
```

### 3.2 Session (volatile, new in v3)

Exists only in BOUND and READY. Held in RAM, never written to flash.

```
first SELECT of a USB connection ──► LOGGED_OUT  (if LOGIN_REQUIRED = 1)
first SELECT of a USB connection ──► LOGGED_IN   (if LOGIN_REQUIRED = 0)
LOGGED_OUT --LOGIN--> LOGGED_IN
LOGGED_IN --LOGOUT / idle timeout / POLICY setting LOGIN_REQUIRED--> LOGGED_OUT
any --unplug / USB reset--> gone (set again at the next first SELECT)
re-SELECT, failed SELECT, card power cycle --> unchanged
```

- **v3.3:** a SELECT of another AID, a SELECT with wrong parameters, a
  re-SELECT of our AID and a CCID card power cycle leave the login, the
  pairing session, the idle timer and the outstanding nonces as they are. A
  card power cycle does deselect (SELECT is needed again) and aborts uploads.
  The login guards GET_INFO detail (§3.3) and firmware update; a nonce grants
  nothing without a phone assertion. So that a program reaching the card
  after a card reset does not inherit the right to install firmware, UPDATE_*
  needs a LOGIN (or the pairing) made **since the last card power cycle**
  (§4.18). Only LOGOUT, the idle timeout, POLICY turning approval on, and a
  USB reset or unplug end a login.

- **BIND** leaves the session LOGGED_IN until the token is unplugged, so the
  QDSD User can continue straight after pairing (Flows: "the session opened
  by pairing lasts until the token is unplugged"). A re-SELECT on the same
  plug-in keeps it; the idle timeout does not apply to it.
- **Idle timeout:** after `CONFIG_QDSD_SESSION_IDLE_S` seconds with no
  accepted command, the session returns to LOGGED_OUT. Default 28 800 s
  (8 h) **[decide]**; the flows give it as [N] hours. The token measures this
  with its own uptime timer, not wall-clock time.
- The session affects only the reads listed in §3.3. SIGN and KEYGEN are
  authorised by their own statements in either session state (Flows v3.3).

### 3.3 Command / state matrix

| Command | MFG | UNASSIGNED | BOUND | READY | Needs LOGGED_IN? |
|---|:-:|:-:|:-:|:-:|:-:|
| SELECT | ✓ | ✓ | ✓ | ✓ | – |
| GET_INFO | ✓ | ✓ | ✓ | ✓ | Full detail only (§4.2) |
| FACTORY_INIT / PERSONALISE / CLOSE / DRIVE | ✓ | | | | – |
| ATTEST, GET_DEVICE_CERT | | ✓ | ✓ | ✓ | No |
| BIND | | ✓ | | | – |
| POLICY, REBIND, RESET | | | ✓ | ✓ | No |
| GET_SESSION_NONCE, LOGIN, LOGOUT | | | ✓ | ✓ | No |
| KEYGEN, SIGN_CSR, WRITE_CERT, GET_CERT | | | ✓ | ✓ | No |
| DELETE_KEY, GET_KEY_ATTESTATION, GET_RECEIPT | | | ✓ | ✓ | No |
| IMPORT_BEGIN, IMPORT_DATA | | | ✓ | ✓ | No |
| SIGN | | | | ✓ | No |
| UPDATE_BEGIN / WRITE / FINISH | | ✓ | ✓ | ✓ | **Yes** if LOGIN_REQUIRED **[decide]** |
| FACTORY_WIPE | ✓ | ✓ | ✓ | ✓ | No (also in FAULT service mode) |

A command in the wrong lifecycle state returns `6985`. A command that needs
LOGGED_IN while the session is LOGGED_OUT returns `6983` (new).

**Why so little is gated.** Signing apps must read the certificate (GET_CERT)
to build a signature, and certificates are public, so GET_CERT can't be
gated. Queued REBIND, RESET and POLICY must run before anyone can log in. What
the login protects on the token is the device detail in GET_INFO (counters,
binding and policy numbers, slot table). Hiding View certs while logged out is
a middleware screen rule, not a token guarantee.

## 4. Commands

All proprietary commands use CLA `80`. **SELECT must succeed first;** until then
every other command returns `6982`. Unplugging the token or a USB bus reset
deselects the application and discards the nonces and the session. A CCID
card power cycle only deselects (v3.3, §3.2).

### 4.0 Middleware plug-in sequence (informative)

1. SELECT.
2. GET_INFO.
3. Ask DTI Cloud for pending actions; send any RESET, REBIND and POLICY, in
   the order the cloud gives them.
4. GET_INFO again. If `27` session = LOGGED_OUT, show "Log in to QDSD"
   (Flow 2b).
5. Signing and DSC download requests go ahead whatever the session.

### 4.1 SELECT — `00 A4 04 00`
- Data: AID `A0 00 00 00 44 54 49 49 4C 03` ("DTIIL", app version **3**).
- Middleware that sends `…4C 01` or `…4C 02` gets `6A82`, so older middleware
  fails cleanly instead of sending v2 statements.
- The first SELECT of a USB connection sets the session from LOGIN_REQUIRED
  (§3.2). A later SELECT of our AID changes nothing but the selection.
- **v3.3:** a SELECT that fails (another AID `6A82`, wrong P1/P2 `6A86`,
  wrong CLA `6E00`) leaves the current selection as it is, as ISO 7816-4 and
  Java Card do.

### 4.2 GET_INFO — `80 C1 00 00`
- **LOGGED_IN, or lifecycle MANUFACTURING / UNASSIGNED:** `21` protocol
  version, `2B` protocol minor, `01` device_id (once personalised), `03` state, `27` session (BOUND
  and READY only), `02` binding_no, `0D` sign_counter, `15` keygen_counter,
  `1A` policy_no, `1F` policy_flags, `11` fw_version, `22` slot count, then one
  `20` entry per slot (BOUND and READY only).
- **LOGGED_OUT (BOUND or READY):** only `21`, `2B`, `01`, `03`, `27`, `1F`,
  `11` and `39`.
- **v3.3:** both forms include `39` session epoch, a random u32 chosen at
  boot, at every USB reset or unplug, and by FACTORY_WIPE. It stays the same through LOGIN,
  LOGOUT, SELECT and card power cycles. If it changed since the agent last
  looked, the session was reset: the agent's nonces are gone and the user is
  logged out. (Nonces can also go for other reasons, §4.8, so SIGN must still
  handle `6984`.) This is enough to show the login screen and to know whether the token
  can sign, without exposing the device detail.

This information is not signed; use ATTEST when the cloud needs proof.

### 4.3 Factory commands (MANUFACTURING only)

Unchanged from v2.

**FACTORY_INIT — `80 E0 00 00`**
- Data: `04` challenge (16–32 bytes, from the Factory Tool).
- The token creates the NIST P-256 curve in both elements if missing (a
  wiped element has none), creates the device key inside the SE050 if it
  doesn't already exist (it never leaves the chip), then derives
  `device_id = SHA-256("QDSD-DEVID" || SE050 UID || device_pubkey)[0..15]`.
  **v3.2:** the device public key is included, so a token that is wiped and
  re-made has a new id and nothing signed for its earlier life (BIND, RESET,
  WIPE envelopes, approvals) can apply to it. Tokens made by 0.3–0.5 keep the
  id they were given.
- Response: `01` device_id, `16` device_pubkey, `1B` chip UID,
  `1C` vendor attestation.
- `1C` vendor attestation is the SE050's `ReadObject_W_Attst` of the device
  key. It is signed by NXP's factory attestation key (`0xF0000012`) and uses
  the **first 16 bytes** of the challenge as SE05x freshness. Inside `1C` are
  two TLVs: `01` the exact command APDU and `02` the attested response, because
  NXP's attestation signature covers both. DTI Cloud checks it against NXP's
  attestation certificate chain.

**FACTORY_PERSONALISE — `80 E1 00 00`**
- Data: `1D` Device Certificate DER (up to 2048 bytes), `1E` DTI command
  public key, **`31` and `32`: the FACTORY_RESET secrets** for the SE050 and
  the SE052F (16 bytes each, per device; DTI derives them from a master key
  in its HSM, for example HMAC(master, device_id ‖ element)).
- The token checks that the certificate's public key equals the device key,
  stores the certificate in the SE050, and creates each element's
  FACTORY_RESET UserID object (§4.23) holding its secret.
- It can be repeated until CLOSE.

**FACTORY_CLOSE — `80 E2 00 00`**
- Requires the device certificate and the command key to be present.
- Creates the **four** SE050 counters (binding, keygen, sign, policy; all 0)
  and the signing-receipt ring, sets policy_flags = `00` (no activation key
  yet), sets state UNASSIGNED, and returns a FACTORY_RECEIPT (`70`/`71`).
- Factory commands are then permanently refused (`6985`).

**FACTORY_DRIVE — `80 E6 <phase> 00`** (firmware 0.7.0, boards with the
install drive; `docs/INSTALL_DRIVE.md`)
- Writes the install-drive image (the read-only USB disk with the Ascert.en
  installer) into the external QSPI flash. MANUFACTURING only (`6985`
  afterwards); `6D00` on a board or build without the drive. P2 must be 0.
- `P1 = 00` BEGIN — data: `28` image size (u32, multiple of 512, at most
  the flash size), `29` SHA-256 of the image. The drive shows "no medium"
  until FINISH.
- `P1 = 01` WRITE — data: `2A` offset (u32, must equal the bytes written so
  far), `25` chunk (1–2048 bytes, not past the announced size). `6A80` if
  out of order or too long.
- `P1 = 02` FINISH — no data. The token reads the whole image back and checks
  the SHA-256, then writes the first 512 bytes (the FAT boot sector, held in
  RAM until now) and shows the drive. `6985` if the image is incomplete,
  `6A80` if the hash differs (the drive then shows no medium until a good
  upload).
- A card reset aborts an upload. The hash is a transfer check, not a
  signature; nothing after FACTORY_CLOSE can write the drive.

### 4.4 GET_DEVICE_CERT — `80 D0 00 00`
- Data: `23` offset (u16).
- Response: `24` total length, `25` chunk (up to 1024 bytes).

### 4.5 ATTEST — `80 D1 00 00` (Flow 2 step 3)
- Data: `04` challenge (16–32 bytes).
- Response: `70` ATTEST statement, `71` device-key signature.
- The cloud verifies it against the Device Certificate and checks that
  state = UNASSIGNED before pairing.
- Allowed while LOGGED_OUT: the statement is for the cloud, and the flows
  keep attestation readable for pairing and support.

### 4.6 BIND — `80 D2 00 00` (Flow 2 step 6)
- Data: `70`/`71` BIND statement signed by the DTI command key.
- Checks:
  - state = UNASSIGNED
  - device_id matches
  - binding_no = current + 1
  - policy_flags has no reserved bits set
  - the signature verifies against the command key
- Effect: the activation key and policy_flags are stored in the SE050, the
  binding counter is incremented, the state becomes BOUND and the session
  LOGGED_IN until unplugged. The policy counter is **not** changed (BIND's
  flags are the starting point, not a Subscriber change). Power-loss safe (§5).
- Response: `70`/`71` BIND_RECEIPT.

### 4.7 POLICY — `80 DB 00 00` (new; QDSD settings)
- Data: `70`/`71` POLICY statement signed by the **current activation key**.
- Checks:
  1. state = BOUND or READY
  2. device_id matches
  3. policy_no = policy counter + 1
  4. reserved bits of policy_flags are 0
  5. method is `01`–`05`
  6. the signature verifies against the activation key
- Effect: policy_flags are stored and the policy counter incremented, in one
  journalled step (§5). If LOGIN_REQUIRED changes from 0 to 1, the session
  becomes LOGGED_OUT at once. If it changes from 1 to 0, the session becomes
  LOGGED_IN. If it does not change, the session is unchanged.
- Response: `70`/`71` POLICY_RECEIPT. The middleware forwards it to DTI Cloud,
  which marks the queued update as applied.
- Because the activation key signs it and the counter must step by one,
  neither the cloud nor the computer can change a setting or replay an old
  one (Flows: settings "cannot be forged by the cloud or replayed").

### 4.8 GET_SESSION_NONCE — `80 D3 00 00` (Flow 2b step 2, Flow 4 step 2)
- Allowed in BOUND and READY (v2: READY only), so LOGIN works before the first
  DSC is issued.
- Response: `05` nonce (32 random bytes).
- **v3.1:** the token keeps up to `CONFIG_QDSD_NONCE_SLOTS` (default 4) nonces
  outstanding. A new nonce takes a free place; only when all are in use does it
  replace the oldest. So a second signing request or a login does not cancel
  an approval the Subscriber is already looking at.
- Each nonce is single-use, held in RAM only, and lost on token restart and
  on USB reset or unplug. All are discarded by REBIND and RESET (the approving
  key changes) and FACTORY_WIPE. LOGOUT, POLICY, SELECT, card power cycles,
  KEYGEN, IMPORT_DATA and DELETE_KEY keep them (v3.3: SIGN approvals name the
  key through keygen_seq, §4.15, so a key change no longer needs to cancel
  them).
- **v3.3, nonce status.** Every `6984` from SIGN or LOGIN about the nonce
  carries `3A` with the reason, so the app can explain it:

  | `3A` | Meaning | What the agent does |
  |---|---|---|
  | `01` | Expired (`CONFIG_QDSD_NONCE_TTL_S`), also if it was later pushed out of the pool | "Approval timed out": ask again |
  | `02` | Replaced: all nonces were in use and a newer GET_SESSION_NONCE took its place | "Cancelled, try again" |
  | `03` | Discarded: REBIND, RESET, factory reset, or USB reset/unplug | "Cancelled, try again" |
  | `04` | Unknown: never issued by this token since it started | Restart the request |
  | `05` | Already used by a successful SIGN or LOGIN | For SIGN, the earlier reply was lost: fetch it with GET_RECEIPT by request_id (§4.19) |
  | `06` | Discarded after three failed signature checks | Investigate (wrong phone key?) |
  | `07` | SIGN only: the approval names an earlier key in that slot (keygen_seq) | Ask for a new approval; the nonce is still usable |

  The token remembers the last 8 dropped nonces (8 bytes each, with the
  reason) to tell these apart; older ones answer `04`.
- Each expires `CONFIG_QDSD_NONCE_TTL_S` (default 600 s) after it was issued
  **[decide]**.
- A nonce serves either LOGIN or SIGN, whichever consumes it first. LOGIN and
  SIGN name the nonce inside the phone's signed assertion, so requests can be
  interleaved freely.
- Three failed signature checks against one nonce discard that nonce only.

### 4.9 LOGIN — `80 D9 00 00` (new; Flow 2b step 3)
- Data: `70`/`71` LOGIN_ASSERTION signed by the activation key.
- Checks:
  1. state = BOUND or READY
  2. a nonce is outstanding and not expired
  3. the statement parses; device_id and nonce equal the token's values
  4. method is `01`–`05`
  5. the signature verifies against the activation key
- Failed checks don't consume the nonce, but three failed signature checks
  discard it (as for SIGN). A missing nonce answers `6984` with `3A` (§4.8).
- Effect: the nonce is consumed and the session becomes LOGGED_IN. Nothing is
  written to flash.
- Response: `70`/`71` LOGIN_RECEIPT (session = `01`). DTI Cloud stores it with
  the login record; it is what lets the cloud show "logged in on [computer]".
- If LOGIN_REQUIRED = 0 the command is still accepted, with the same checks
  (and simply confirms LOGGED_IN), so the middleware doesn't have to
  special-case it.

### 4.10 LOGOUT — `80 DA 00 00` (new)
- No data. Allowed in BOUND and READY.
- Effect: session = LOGGED_OUT and the pairing session (if any) ends.
  Outstanding nonces are kept (v3.1): they may belong to other pending signing
  requests, and a nonce grants nothing without a phone assertion. If LOGIN_REQUIRED = 0, the session stays
  LOGGED_IN until the token is next plugged in **[decide]**.
- Response: `27` session. No receipt: logging out needs no proof.
- Used by the middleware's "Log out of QDSD" button.

### 4.11 KEYGEN — `80 D5 <alg> 00` (Flow 3 step 4)
- **P1 = key algorithm (v3.1):** `00` ECDSA P-256, `01` RSA-2048 (public
  exponent 65537). Other values: `6A86`. The algorithm is a plain parameter:
  the Subscriber's consent covers creating a key, not its type. The middleware
  picks it from the CA tool's request (PKCS#11 mechanism, CNG algorithm).
- Data: `70`/`71` authorisation, which is either:
  - KEYGEN_CONSENT (purpose `02`) signed by the activation key, or
  - KEYGEN_ENVELOPE (purpose `03`) signed by the DTI command key.
- Checks: device_id, and keygen_seq = keygen counter + 1; for KEYGEN_CONSENT,
  also method `01`–`05`.
- **Session:** allowed while LOGGED_OUT (Flows v3.3).
- Effect: the keygen counter is incremented **before** the key is generated,
  so a consent can't be replayed even if power fails mid-command. The DSC key
  pair is then generated inside the SE052F, in a free slot.
- Slot choice: the first EMPTY slot; otherwise the PENDING slot with the
  lowest keygen_seq (an abandoned download); otherwise `6A84`.
- Response: `0E` slot, `0F` dsc_pubkey (DER SubjectPublicKeyInfo), `70`/`71`
  KEY_ATTEST signed by the device key (key_origin `00`).
- RSA-2048 key generation inside the SE052F takes several seconds; the
  middleware should allow at least 30 s for this response.
- The token cannot check `valid_until` because it has no clock; DTI Cloud
  enforces it.

### 4.12 SIGN_CSR — `80 D6 <slot> <mode>` (Flow 3 step 4, proof of possession)
Allowed only while the slot holds a key without a certificate. Allowed while
LOGGED_OUT.

**Mode `00`: full request.**
- Data: `74` CertificationRequestInfo DER (the CSR body the CA wants signed).
- The token parses it and refuses (`6A80`) unless its SubjectPublicKeyInfo is
  exactly the slot's key. That way this mode can only ever produce a CSR
  signature, never a document signature.
- Repeatable, so a CA tool can retry.
- Used by the middleware whenever it has the data: PKCS#11
  `CKM_ECDSA_SHA256` / `CKM_SHA256_RSA_PKCS`, and requests the agent builds
  itself.

**Mode `01`: digest only (new in v3.1).**
- Data: `75` SHA-256 digest (32 bytes).
- For CA tools that hand the provider only a hash: Windows CNG
  `NCryptSignHash` (used by CertEnroll / most Windows enrolment tools) and
  PKCS#11 `CKM_ECDSA` / `CKM_RSA_PKCS` with a pre-hashed DigestInfo.
- **Allowed once per key, and only as the key's first signature.** After a
  digest-mode signature, both modes return `6986`; after a full-request
  signature, digest mode returns `6986`. The token records this before signing,
  so a power cut can't allow a second one.
- Why this is safe: the token can't see what it signs here, but the key has no
  certificate yet and can sign only once. If that signature is the real
  request, the CA certifies the key. If a compromised PC spends it on anything
  else, no valid request can ever be made for that key, the CA never certifies
  it, and the stray signature never chains to a DSC.
- Cost: if the CA rejects the request and the download is retried, it needs a
  new KEYGEN (and a new pre-approval or envelope).

**Response (both modes):** `72` raw signature over the SHA-256 (r‖s for P-256,
RSASSA-PKCS1-v1_5 for RSA), plus `73` DER ECDSA signature for P-256 keys.

Keys generated by firmware 0.3/0.4 are treated as having already signed a full
request, so digest mode is refused for them.

### 4.13 WRITE_CERT — `80 C5 <slot> <phase>` (Flow 3 step 5)
- Phase `00` (first chunk): data is `24` total length followed by `25` chunk.
- Phase `01` (more): data is `25` chunk.
- Allowed while LOGGED_OUT.
- When the last byte arrives, the token parses the X.509 certificate and
  accepts it only if its subject public key equals the slot's key (same
  algorithm; P-256 point, or RSA-2048 modulus with e = 65537).
  Otherwise it returns `6A80` and the slot is unchanged.
- On success the slot becomes CERTIFIED and the state BOUND → READY.
- A later certificate for the same key (for example a reissue) replaces the
  stored one.
- The certificate is stored in the SE052F next to its key. It is written
  first and the slot record (which holds its hash) last, so a power cut leaves
  the old certificate or the new one, never a mix (§5).
- Removal: DELETE_KEY (§4.20) or RESET.

### 4.14 GET_CERT — `80 C3 <slot> 00`
- Data: `23` offset.
- Response: `24` total, `25` chunk. `6A88` if the slot has no certificate.
- Allowed while LOGGED_OUT, because signing apps need the certificate to build
  a signature.

### 4.15 SIGN — `80 D4 00 00` (Flow 4 step 4)
- Data: `06` h_tbs, `07` h_ctx, `08` request_id, `0E` key_slot, then `70`/`71`
  SIGN_ASSERTION signed by the activation key. **v3.3:** the assertion also
  carries `0C` keygen_seq, the keygen number of the DSC the Subscriber
  approved (the cloud has it from KEY_ATTEST or GET_INFO's slot entry).
- **Session:** allowed while LOGGED_OUT (Flows v3.3). The per-signature
  assertion is the Subscriber's authorisation.
- Checks, in order:
  1. state = READY
  2. a nonce is outstanding and not expired
  3. the statement parses
  4. its device_id, nonce, h_tbs, h_ctx, request_id and key_slot equal the
     token's values and the plain fields of this command
  5. method is `01`–`05`
  6. the slot is CERTIFIED
  7. **v3.3:** keygen_seq equals the keygen number of the key now in the
     slot, else `6984` with `3A` = `07` (the approval was for a key since
     deleted or replaced; the nonce stays usable)
  8. the signature verifies against the activation key
- Failed checks don't consume the nonce, but three failed signature checks
  discard it. A missing nonce answers `6984` with `3A` (§4.8).
- On success (**v3.2**, nothing is released before its receipt is saved):
  1. the nonce is consumed
  2. the sign counter is incremented
  3. a *pending* SIGN_RECEIPT (status `02`, sig_hash zero) is saved in the
     SE050 receipt ring
  4. the SE052F signs h_tbs with the slot key
  5. the SE050 device key signs the final SIGN_RECEIPT, and the receipt and
     the DSC signature are saved in the ring
  6. only then are they returned
- If power fails after step 3, the next boot signs the pending receipt as it
  is (status `02` interrupted, no signature) and saves it; GET_RECEIPT
  returns it. A DSC signature made in step 4 was never released. If power
  fails after step 5, GET_RECEIPT returns the receipt and the signature.
- The DSC key signs h_tbs: ECDSA P-256, or RSASSA-PKCS1-v1_5 with the SHA-256
  DigestInfo for RSA-2048 (the slot's algorithm, from KEYGEN).
- Response (`9000`): `72` DSC signature (64-byte r‖s, or 256-byte RSA),
  `70`/`71` SIGN_RECEIPT (status `00`).
- If the SE052F fails after the counter was incremented, the response is SW
  `6F00` with `70`/`71` SIGN_RECEIPT (status `01`, sig_hash all zero), also
  saved. The cloud can then explain the counter gap.
- Every receipt carries key_origin (`00` generated, `01` imported) and, v3.3,
  keygen_seq, so the SER records exactly which key made the signature.
- SIGN does not change the session and does not count as login.

### 4.16 REBIND — `80 D7 00 00` (Flow 5, planned phone change)
- Data: `0A` new activation public key, then `70`/`71` REBIND statement signed
  by the **current** activation key.
- Checks: binding_no = current + 1, new_key_hash = SHA-256(new key), method
  `01`–`05`.
- Effect: the activation key is swapped and the binding counter incremented,
  power-loss safe. DSC keys, certificates, policy_flags and the policy counter
  are kept.
- Also used when the Subscriber switches between hardware-checked and
  app-checked approval methods, which creates new activation keys (Flows,
  "Approval method").
- Response: `70`/`71` REBIND_RECEIPT.

### 4.17 RESET — `80 D8 00 00` (Flow 5, lost phone)
- Data: `70`/`71` RESET statement signed by the DTI command key.
- Checks: binding_no = current + 1.
- Effect: deletes every DSC key in the SE052F, every certificate and slot
  record, every saved signing receipt (they belong to the old Subscriber) and
  the activation key; sets policy_flags = `00`; increments the binding
  counter; sets state UNASSIGNED. The policy counter is kept. Power-loss safe:
  an interrupted reset finishes at the next boot.
- Response: `70`/`71` RESET_RECEIPT.

### 4.18 Firmware update — UPDATE_BEGIN / UPDATE_WRITE / UPDATE_FINISH (v3.1)

The signed firmware image is streamed over the normal token interface into
MCUboot's secondary slot while the application runs. MCUboot verifies the DTII
signature and refuses downgrades at the next boot before installing
(overwrite-only), so the token never needs a bootloader USB mode, a serial
driver or an SMP client, and the TS3USB221 switch stays under the
application's control. ENTER_UPDATE (`F0`) of v3.0 is removed (`6D00`).

Allowed in UNASSIGNED, BOUND and READY. With LOGIN_REQUIRED = 1, BEGIN and
FINISH return `6983` unless the session is LOGGED_IN through a LOGIN (or the
pairing) made since the last card power cycle (v3.3) **[decide]**.

A lab token built without firmware update (`CONFIG_QDSD_FW_UPDATE=n`, for
board bring-up before MCUboot) answers `6D00` to all three commands, before
any other check. Product firmware is always built with update.

**UPDATE_BEGIN — `80 E8 00 00`**
- Data: `28` image size (u32), `29` SHA-256 of the whole image file.
- The size must be at least 32 and fit the secondary slot (`6A80`).
- Erases the secondary slot and starts a new transfer (any previous one is
  abandoned).

**UPDATE_WRITE — `80 E9 00 00`**
- Data: `2A` offset (u32), `25` chunk (1–1024 bytes).
- Chunks must arrive in order (offset = bytes written so far), else `6A80`.
- The first chunk must hold the 32-byte MCUboot header. The token refuses
  (`6A80`) and abandons the transfer if the magic is wrong or the image version
  is older than the running firmware. Equal versions are allowed (reinstall).
- No transfer in progress: `6985`.

**UPDATE_FINISH — `80 EA 00 00`**
- No data. All bytes must have been written (`6985` otherwise).
- The token checks the SHA-256 of the slot against `29` (`6A80` and nothing
  installed if it differs), marks the image for installation, answers `9000`,
  and reboots about 300 ms later. MCUboot then checks the signature and
  version; if either fails, the old firmware keeps running.
- USB reset or unplug during a transfer abandons it; start again with BEGIN.

### 4.19 GET_RECEIPT — `80 DD 00 00` (v3.2)
- Data, one of:
  - `0D` sign_counter (u32): that signature;
  - `08` request_id (16 bytes, v3.3): the newest saved receipt for that cloud
    signing request, wherever it is in the ring (other signatures may have
    happened since). This is the lookup to use after a lost SIGN reply
    (nonce status `05`);
  - no data: the latest signature.
  Both `0D` and `08` together: `6A80`.
- Allowed in BOUND and READY, **also while LOGGED_OUT**: a receipt reveals
  nothing the cloud does not already hold, and the middleware needs it after a
  lost reply. (Documented exception to the login rule.)
- Response: `72` DSC signature (status `00` only), `70`/`71` SIGN_RECEIPT,
  exactly as SIGN returned or would have returned it.
- The SE050 keeps the last `CONFIG_QDSD_RECEIPT_RING` receipts (default 16).
  `6A88` if that counter value or request id was never used, was overwritten
  by newer ones, or the receipt was lost to a power cut before it was saved (the cloud
  sees the gap through ATTEST's sign_counter).
- RESET and FACTORY_WIPE delete all saved receipts.

### 4.20 DELETE_KEY — `80 DC <slot> 00` (v3.2)
- Data: `70`/`71` DELETE_KEY statement signed by the **activation key**.
- Checks:
  1. state = BOUND or READY; slot < N (`6A86`)
  2. device_id matches; key_slot in the statement = P1; method `01`–`05`
  3. the slot holds a key (`6986`)
  4. keygen_seq = the keygen number of the key now in the slot (`6984`), so
     an approval can never delete a later key put in the same slot
  5. the signature verifies against the activation key (the cloud alone
     cannot delete a Subscriber's DSC)
- Effect: the slot record is emptied first (the key is unusable at once),
  then the key and the certificate are deleted from the SE052F. If this was
  the last certified key the state goes READY → BOUND. Works the same for
  generated and imported keys. A power cut part-way leaves the slot empty and
  any leftover key or certificate is deleted at the next boot.
- Response: `70`/`71` KEY_DELETED.
- **Revocation** is done at the CA (the cloud asks the CA to revoke); the
  token's part is removing its copy. Retrieval is GET_CERT; upload is
  WRITE_CERT.

### 4.21 GET_KEY_ATTESTATION — `80 DE <slot> 00` (v3.2)
Separate from device attestation: ATTEST speaks for the token (SE050 device
key, counters, binding), GET_KEY_ATTESTATION for one DSC key in the SE052F.
- Data: `04` challenge (16–32 bytes).
- Allowed in BOUND and READY, in either session state; the slot must hold a
  key (`6986`).
- Response:
  - `70`/`71` KEY_STATUS signed by the device key: challenge, keygen_seq,
    slot, dsc_pubkey, status (`01` pending / `02` certified), cert_hash
    (zeros if none), key_origin;
  - `37` the SE052F's own chip UID;
  - `38` the SE052F's NXP attestation of the key object (`ReadObject_W_Attst`
    with the SE052F's NXP attestation key, freshness = first 16 bytes of the
    challenge): `01` command APDU, `02` attested response. It proves the key
    is inside that SE052F and states the key's origin as the chip sees it
    (generated inside or written from outside). The cloud verifies it
    against NXP's SE052F attestation certificate chain. Omitted if the
    element cannot attest that key type (bring-up item for RSA keys).

### 4.22 Institutional certificate import — IMPORT_BEGIN / IMPORT_DATA (v3.2)
For institutional certificates the CA delivers as a .pfx (PKCS#12). The
Ascert.en agent opens the .pfx with the password the user types; the token
never sees the password or the file. The private key travels to the token
encrypted to a one-time key of that token, and the Subscriber approves the
import on the phone.

**IMPORT_BEGIN — `80 DF 00 00`**
- Data: `70`/`71` IMPORT_CONSENT signed by the activation key: keygen_seq =
  keygen counter + 1, cert_hash = SHA-256 of the certificate being imported,
  key_alg, method, valid_until (checked by the cloud).
- Checks: BOUND or READY, device_id, keygen_seq (`6984`), alg and method
  (`6A80`), signature (`6982`), a free or pending slot (`6A84`).
- Effect: the token makes a fresh ephemeral P-256 key pair (RAM only).
- Response: `70`/`71` IMPORT_OFFER signed by the device key: keygen_seq,
  cert_hash, import_pubkey, key_alg. The agent verifies it against the
  device certificate, so it knows it encrypts to this very token.

**IMPORT_DATA — `80 CB 00 <phase>`**
- Phase `00` (first chunk): `24` total length, `25` chunk; phase `01`: `25`
  chunk. Total up to 3072 bytes. The package is:
  `36` certificate DER, `34` agent ephemeral public key, `35` IV ‖ ciphertext ‖ tag.
- Key wrap (the agent):
  - `Z` = X coordinate of ECDH(agent ephemeral, import_pubkey)
  - `K` = SHA-256(`"QDSD-IMPORT-V1"` ‖ Z ‖ import_pubkey ‖ agent_pubkey)
  - AAD = device_id ‖ keygen_seq (u32) ‖ cert_hash ‖ key_alg
  - plaintext: P-256 `d` (32 bytes); RSA-2048 (e = 65537)
    `p ‖ q ‖ dp ‖ dq ‖ qinv` (128 bytes each)
  - AES-256-GCM, 12-byte IV, 16-byte tag
- Checks, in order: the certificate's hash equals the approved cert_hash and
  its key has the approved algorithm (`6A80`, nothing spent); the wrap
  decrypts (`6A80`, nothing spent); the keygen counter is still the approved
  one (`6984`).
- Effect: keygen counter + 1 (the approval is spent); the key is written into
  the slot in the SE052F; the token signs a probe with it and checks the
  signature against the certificate's public key, and deletes the key if it
  does not match (`6A80`); the certificate is stored and the slot becomes
  CERTIFIED with key_origin `01`; BOUND → READY. The plaintext key is wiped
  from RAM as soon as it is written.
- One attempt per IMPORT_BEGIN: the ephemeral key is destroyed after the last
  chunk whatever the outcome, and on USB reset or unplug. A failed attempt
  that spent nothing can be repeated with a new IMPORT_BEGIN under the same
  approval.
- Response: `0E` slot, `0F` dsc_pubkey, `70`/`71` KEY_ATTEST (key_origin `01`).
- An imported slot never signs a CSR (it already has its certificate) and is
  removed with DELETE_KEY like any other.

### 4.23 FACTORY_WIPE — `80 E3 00 00` (v3.2)
Returns the token to MANUFACTURING with both secure elements empty, for
refurbishing or repair.
- Data: `31` and `32` the FACTORY_RESET secrets (from FACTORY_PERSONALISE),
  plus, unless the token is in MANUFACTURING or FAULT, `70`/`71` WIPE
  statement signed by the **DTI command key** with binding_no = current.
- The gate is in the elements: each holds a FACTORY_RESET UserID object
  (NXP-reserved id `0x7FFF0205`). DeleteAll is only accepted inside a session
  authenticated with that object, so wrong secrets fail inside the element
  (`6982`) and nothing is erased. The WIPE statement means a leaked factory
  secret alone cannot erase a Subscriber's token.
- Both secrets are checked before anything is touched. Then the token
  journals the wipe, erases the SE052F, then the SE050 (DeleteAll: every QDSD
  key, record, counter and the FACTORY_RESET objects themselves; NXP
  trust-provisioned objects and the Platform SCP03 keys stay).
- Counters restart at 0 on the re-made token, but FACTORY_INIT gives it a new
  device key and so a new device_id (§4.3): nothing signed for the old
  identity can be replayed.
- A wipe cut off by power loss leaves the token in FAULT service mode, where
  FACTORY_WIPE with the secrets alone finishes it. The secrets alone also
  suffice when the lifecycle record is corrupt, or missing on a personalised
  token (no statement could be checked). Any other FAULT (for example a
  secure-element error at boot) still needs the WIPE statement. A personalised
  token whose lifecycle record is missing is never treated as a fresh one:
  it boots into service mode, and factory commands stay closed.
- Response: `03` state (`00`).
- `6985` if the token has no FACTORY_RESET object (made before v3.2: those
  can only be reset with NXP tooling).

## 5. Power-loss safety

BIND, REBIND, RESET and POLICY each change more than one record. The token
writes an intent journal to the SE050 state object first, then applies the
steps, then clears the journal. If power fails part-way, the next boot replays
the journal before USB comes up. Every step can safely be repeated:

- writing a key or the policy flags overwrites them;
- a delete that finds nothing is ignored;
- a counter is incremented only while it is below the journal target.

KEYGEN, IMPORT and SIGN need no journal. Their counter is incremented first,
so a power cut wastes a sequence number but can never allow a replay.

**v3.2, records in the secure elements.** A write of up to 208 bytes is one
SE05x `WriteBinary` APDU, which the element applies all or nothing. Every
record that must change atomically fits that: the slot record (48 bytes), the
receipt header (208) and the state record (96). Longer writes (certificates,
receipt signatures) are split, so the token orders them:

- **Certificate:** each slot has two certificate objects (banks). A new
  certificate is written into the bank the slot record does not point at;
  the record (with the certificate's hash and bank) is then switched in one
  atomic write, and the old bank deleted. A cut leaves the old certificate or
  the new one; the unused bank is cleaned up at the next boot. A certificate
  that does not match its record's hash is never served.
- **Receipt:** signatures first, header last. Until the header says *final*,
  the entry reads as *pending* with its pending statement intact.
- **KEYGEN / IMPORT / DELETE_KEY:** the slot record is emptied before a key
  is created or deleted; a key or certificate left in an empty slot is
  deleted at the next boot.
- **Lifecycle:** READY means "at least one certified slot". If a power cut
  separates a slot change from the READY/BOUND update, the next boot sets the
  state from the slot records.
- **FACTORY_WIPE:** journalled; the SE052F (keys) is erased before the SE050
  (journal), so a cut-off wipe always boots into service mode and can be
  finished.
- **Migration from 0.3–0.5:** each record is copied into its element before
  the flash copy is deleted; the whole step repeats after a power cut.

LOGIN and LOGOUT change RAM only, so a power cut simply leaves the token
logged out (or logged in, if LOGIN_REQUIRED = 0) at the next plug-in.

## 6. Status words

| SW | Meaning |
|---|---|
| `9000` | OK |
| `6700` | Wrong length |
| `6982` | Not selected, a signature did not verify, or a FACTORY_RESET secret is wrong |
| `6983` | **New.** Session is LOGGED_OUT and this command needs LOGGED_IN |
| `61xx` | v3.3: more response data; send GET RESPONSE (§1.2) |
| `6883` | v3.3: a chain was expected to continue with the same command (§1.2) |
| `6984` | Stale: nonce missing/used/expired (SIGN and LOGIN add `3A` with the reason, §4.8), approval for an earlier key (`3A` = `07`), or seq/binding_no/policy_no not current + 1 |
| `6985` | Command not allowed in the current lifecycle state; no import in progress; no FACTORY_RESET object; GET RESPONSE with nothing held |
| `6986` | Slot in the wrong state for this command |
| `6A80` | Malformed data, wrong device_id, field mismatch, reserved policy bit, method out of range, certificate/key mismatch, import wrap that does not decrypt |
| `6A82` | Unknown AID (including v1 and v2 AIDs) |
| `6A84` | No free key slot |
| `6A86` | Bad P1/P2 |
| `6A88` | Referenced data not found (no certificate, no saved receipt for that counter) |
| `6D00` | INS not supported |
| `6E00` | CLA not supported (including a chained SELECT) |
| `6F00` | Secure element failure; anything but GET_INFO / FACTORY_WIPE in FAULT service mode |

## 7. Where keys and records live

Since v3.2 every key and every persistent record is inside a secure element.
MCU flash only holds the firmware itself and the MCUboot slots; records left in
flash by firmware 0.3–0.5 are moved into the elements at first boot and the
flash copies deleted. The full object-id map, with the Kconfig options that
move the ranges, is in `docs/OBJECT_IDS.md`.

| Item | Where (default id) | Notes |
|---|---|---|
| Device key (P-256 private) | SE050 `0x51DE0001` | Generated at FACTORY_INIT; signs attestations and receipts |
| DTI command public key | SE050 `0x51DE0002` | Written at PERSONALISE; **WIPE, BIND, KEYGEN_ENVELOPE, RESET checked inside the SE050** |
| Activation public key | SE050 `0x51DE0003` | Written by BIND/REBIND, deleted by RESET; **every phone statement checked inside the SE050** (`ECDSAVerify`) |
| State + policy flags + journal | SE050 binary `0x51DE0010` | 96 bytes, CRC-protected |
| Binding / keygen / sign / policy counters | SE050 counters `0x51DE0021..24` | 4 bytes each, increment-only |
| Device certificate | SE050 binary `0x51DE0030` | Written at PERSONALISE |
| Signing receipts | SE050 binary `0x51DE0100 + n` | 16 × 528 bytes: header, statement, device signature, DSC signature |
| FACTORY_RESET secret | SE050 and SE052F UserID `0x7FFF0205` | NXP-reserved id; enables DeleteAll |
| DSC keys (P-256 or RSA-2048) | SE052F `0x5D5C0000 + slot` | Generated in the chip, or imported (origin recorded) |
| Slot records | SE052F binary `0x5D5C0100 + slot` | 48 bytes: status, alg, origin, csr_mode, keygen_seq, cert length and hash |
| DSC certificates | SE052F binary `0x5D5C0200 + slot` and `0x5D5C0204 + slot` (two banks) | Must match the slot key and the record's hash; the record names the current bank |
| Session state, nonces, idle timer, import ephemeral key | MCU RAM | Never persisted |
| Staged firmware image | MCUboot secondary slot (internal flash) | Written by UPDATE_*; installed by MCUboot after signature check |

Phone and cloud signatures are verified by the SE050 against the stored key
object. The MCU verifies with PSA Crypto (mbedTLS / Oberon) only where no stored key exists yet: the
boot self-test, and the probe that proves an imported key matches its
certificate. `CONFIG_QDSD_VERIFY_IN_SE=n` moves the check back to the MCU,
for bring-up only.

## 8. Open items **[decide]**

Carried from v2:
- Nonce lifetime (default 600 s).
- Number of DSC slots (default 4). ~~No way to free a certified slot~~ —
  resolved in v3.2 by DELETE_KEY.
- ~~DSC algorithm~~ — resolved in v3.1: RSA-2048 and P-256 both supported.
  RSA-PSS is not offered; add it if a CA or portal requires it.
- Whether ATTEST should also return the SE050 vendor attestation in the field,
  not only at the factory.

New in v3:
- Login idle timeout `CONFIG_QDSD_SESSION_IDLE_S` (draft 8 h; Flows: [N] hours).
- Whether LOGOUT should force LOGGED_OUT even when LOGIN_REQUIRED = 0, until
  the next plug-in.
- Whether firmware update needs LOGGED_IN (v3.1: UPDATE_BEGIN/FINISH).
- ~~keygen_seq in SIGN_ASSERTION~~ — adopted in v3.3 (§4.15).
- Whether the token should refuse some approval methods for some commands,
  for example `05` (no authentication) for SIGN, depending on the CCA's view
  of the Ascert.en PIN and no-check methods (Flows open item).
- Whether GET_INFO while LOGGED_OUT should hide even more (for example
  fw_version), or be refused outright with `6983`.
- Migration of tokens personalised under v2 (missing policy counter and
  flags), and whether v2 middleware support is needed at all in the field.

New in v3.2:
- Who approves an institutional import and every signature with an imported
  key: the Subscriber's phone only (as implemented), or also an institution
  administrator (cloud policy, no token change).
- Which institutional certificate types are imported (organisation DSCs,
  document signers); whether some should instead be generated in the token.
- Number of saved receipts (default 16) and whether GET_RECEIPT should need
  LOGGED_IN after all.
- FACTORY_RESET secret management: per-device derivation in DTI's HSM (as
  proposed), who may run FACTORY_WIPE in the field, and whether the WIPE
  statement should also need a fresh token challenge.
- Production USB VID/PID (the development ids belong to Nordic).
- Whether to ship a Windows "null minidriver" INF for the token's ATR so
  Windows Plug and Play does not report "no driver found" for the card
  (`docs/USB_CCID.md`).

## 9. Implementation notes (firmware 0.7.0)

How firmware 0.6 behaves on each open point until DTII decides. Each is a
one-line change in `src/token/` or a Kconfig option.

| Open point | Firmware 0.6 does |
|---|---|
| Nonce lifetime | 600 s per nonce (`CONFIG_QDSD_NONCE_TTL_S`; lab build 120 s) |
| Outstanding nonces | 4 (`CONFIG_QDSD_NONCE_SLOTS`) |
| Idle timeout | 8 h (`CONFIG_QDSD_SESSION_IDLE_S`; lab build 300 s). Does not apply to the pairing session or when LOGIN_REQUIRED = 0 |
| LOGOUT with LOGIN_REQUIRED = 0 | Stays LOGGED_IN (returns `27` = `01`) |
| Firmware update | Needs LOGGED_IN when LOGIN_REQUIRED = 1; allowed in UNASSIGNED |
| Methods per command | All five methods accepted for every command |
| GET_INFO while LOGGED_OUT | Returns `21 2B 01 03 27 1F 11 39` as in §4.2 |
| v2 migration | Done at boot as in §7; v2 middleware is refused at SELECT |
| Import approval | Subscriber's phone (activation key), one approval per import, spends a keygen number |
| Receipt ring | 16 (`CONFIG_QDSD_RECEIPT_RING`); GET_RECEIPT allowed while logged out |
| FACTORY_WIPE | Secrets + DTI WIPE statement (binding_no = current); secrets alone in MANUFACTURING, for a cut-off wipe, or with a corrupt or lost lifecycle record |
| Dropped nonces remembered | 8, for the `3A` reason |
| Firmware update | Also needs a LOGIN or pairing since the last card power cycle (v3.3) |

Upgrading from 0.6.0 (lab builds only, never released; they report protocol
minor `2`): SIGN receipts saved by 0.6.0 lack keygen_seq; 0.6.1 and later do
not read them (GET_RECEIPT answers
`6A88`, a pending one is dropped at boot). Clear lab tokens with FACTORY_WIPE
before flashing 0.6.2, or accept that their receipt rings start empty.
| Signature checks | Inside the SE050 (`CONFIG_QDSD_VERIFY_IN_SE=y`) |

Clarifications the spec left implicit, as implemented:
- `27` session appears in GET_INFO only in BOUND and READY (no session exists
  in MANUFACTURING or UNASSIGNED).
- POLICY that leaves LOGIN_REQUIRED unchanged leaves the session unchanged.
- The pairing session survives a re-SELECT on the same plug-in; LOGOUT, USB
  reset, unplug, or POLICY turning approval on end it.
- After RESET, a new BIND starts again from the flags in its envelope; the
  policy counter continues from where it was, so a POLICY signed before the
  RESET can't be replayed.
