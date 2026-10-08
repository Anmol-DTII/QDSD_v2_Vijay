# QDSD Token Firmware 0.6.3: Ascert.en Flows v3.4 (protocol v3.3)

Firmware for the QDSD token (nRF52840 + NXP SE050 + NXP SE052F) in the
Ascert.en scheme. 0.6 takes in the DTII team's review of 0.5 in one batch:

- **USB CCID** (smart-card reader class) instead of WinUSB, so Windows, macOS
  and Linux use their own drivers.
- **Records inside the secure elements**: device certificate, DSC
  certificates, slot records and signing receipts. MCU flash holds nothing but
  firmware.
- **Signing receipts kept on the token**: nothing is released before its
  receipt is saved; GET_RECEIPT gets a lost one back.
- **DELETE_KEY**: phone-approved removal of a DSC (revocation stays at the CA).
- **GET_KEY_ATTESTATION**: the SE052F's own attestation of a DSC key,
  separate from the SE050 device attestation.
- **FACTORY_WIPE**: factory reset of both secure elements, gated inside each
  element by a FACTORY_RESET UserID secret only DTI holds.
- **Institutional .pfx import**: key encrypted to the token, phone-approved,
  permanently marked *imported* in every receipt.
- **Phone and cloud signatures checked inside the SE050** (`ECDSAVerify`).
- **Object-id map** with configurable ranges.

0.6.1–0.6.3 (protocol v3.3, from the middleware reviews of 0.6.0 and 0.6.1):

- A failed SELECT keeps the selection; re-SELECTing keeps the login and the
  idle timer.
- A CCID card power cycle keeps the login and outstanding nonces; only a USB
  reset or unplug ends the session.
- SIGN approvals and receipts name the key (`keygen_seq`), so downloading,
  importing or deleting a DSC no longer cancels approvals waiting on the
  phone.
- GET_INFO returns a random session epoch; `6984` on SIGN and LOGIN says why
  the nonce is not usable.
- ISO 7816 command chaining and GET RESPONSE for hosts limited to short APDUs.
- GET_INFO reports protocol minor 3 (0.6.0 lab tokens report 2), and
  GET_RECEIPT can look a receipt up by the cloud's request id.
- 0.6.3: build fixes only. A missing MCUboot or secondary slot now stops the
  build with a message saying what to do, instead of devicetree errors from
  `port_fw.c`; an optional bring-up build without MCUboot
  (`prj_noupdate.conf`, update commands answer `6D00`).

What stays from 0.3–0.5: the phone talks only to DTI Cloud; every approval
reaches the token as a statement signed by the phone's hardware key or the DTI
command key; no PIN, no Bluetooth; login session (Flow 2b); RSA-2048 and
P-256 DSC keys generated in the token; firmware update over the token
interface into MCUboot.

## Layout

One application, parallel `include/` and `src/` by subsystem, build files at
the root. A folder name means the same thing everywhere: the code in
`src/token/` includes `token/…` headers from `include/token/`, its bugs are
"token" bugs, and its rules are in the "Commands" part of `docs/PROTOCOL.md`.

```
CMakeLists.txt  Kconfig  prj.conf  prj_lab.conf  prj_noupdate.conf  VERSION  sysbuild.conf  app.overlay
sysbuild/mcuboot.conf    keys/README.md (development image-signing key)

include/                         src/
  qdsd/      config, object ids    main.c          boot order, USB gate
  token/     engine API, context   token/          command processor, one file per flow
  protocol/  TLV, statements, DER  protocol/       encoders and strict parsers
  state_machine/ lifecycle record  state_machine/  lifecycle record + journal
  security/  self-test             security/       boot crypto self-test
  port/      port.h (HW interface) port/           port.h on SE050, SE052F, MCU
  se05x/     SE session + objects  se05x/          Plug & Trust nano, SCP03 keys
  usb/       CCID, descriptors     usb/            CCID messages + Zephyr glue
  storage/   NVS                   storage/        MCU flash (legacy records only)
  hal/       GPIO, I2C, power      hal/            board HAL (from Phase 2)

docs/   PROTOCOL.md  BRINGUP.md  OBJECT_IDS.md  USB_CCID.md
tools/  qdsd_proto.py   reference encoder for middleware / cloud / app teams
tests/  host/ (end-to-end tests on a software model)   zephyr_ci/ (cross-compile check)
```

`src/token/`:

| File | Commands / job |
|---|---|
| `token_engine.c` | APDU parsing and dispatch, SELECT, GET_INFO, session and nonces, init |
| `token_factory.c` | FACTORY_INIT, FACTORY_PERSONALISE, FACTORY_CLOSE, FACTORY_WIPE (Flow 1) |
| `token_pairing.c` | ATTEST, BIND, REBIND, RESET, POLICY, LOGIN, LOGOUT (Flows 2, 2b, 5) |
| `token_dsc.c` | KEYGEN, SIGN_CSR, WRITE_CERT, DELETE_KEY, GET_KEY_ATTESTATION (Flow 3) |
| `token_import.c` | IMPORT_BEGIN, IMPORT_DATA (institutional .pfx) |
| `token_sign.c` | GET_SESSION_NONCE, SIGN (Flow 4) |
| `token_receipt.c` | Receipt ring in the SE050, GET_RECEIPT, receipt recovery at boot |
| `token_store.c` | Slot records and certificates in the SE052F, migration from 0.3–0.5, boot checks |
| `token_journal.c` | Power-loss-safe BIND / REBIND / RESET / POLICY |
| `token_update.c` | UPDATE_BEGIN / WRITE / FINISH |

## Flow coverage

| Flow | Token commands |
|---|---|
| 1 Factory | FACTORY_INIT, FACTORY_PERSONALISE (device cert, DTI command key, FACTORY_RESET secrets), FACTORY_CLOSE |
| 2 Pairing | ATTEST, GET_DEVICE_CERT, BIND |
| 2b Login | GET_SESSION_NONCE, LOGIN, LOGOUT, idle timeout |
| Settings | POLICY |
| 3 DSC download | KEYGEN (RSA-2048 or P-256), SIGN_CSR, WRITE_CERT; GET_CERT; **DELETE_KEY**; **GET_KEY_ATTESTATION** |
| Institutional | **IMPORT_BEGIN / IMPORT_DATA** |
| 4 Signing | GET_SESSION_NONCE, SIGN; **GET_RECEIPT** |
| 5 Phone change / lost phone | REBIND, RESET |
| Service | UPDATE_BEGIN / WRITE / FINISH; **FACTORY_WIPE** |

## Build

Product (NCS 3.0), from the repository root:

```
west build -b qdsd/nrf52840 . --sysbuild -- \
  -DBOARD_ROOT=<QDSD board repo> -DQDSD_KEYS_DIR=<secure dir with scp03_prod_keys.h>
```

Lab bench (NXP default SCP03 keys, RTT logs, debug port open):

```
west build -b qdsd/nrf52840 . --sysbuild -- \
  -DBOARD_ROOT=<QDSD board repo> -DEXTRA_CONF_FILE=prj_lab.conf
```

Generate a development image-signing key first: see `keys/README.md`.

`--sysbuild` is required: it builds MCUboot and lays out the flash
(Partition Manager), and firmware update (`src/port/port_fw.c`) needs both.
Without it the build stops in `port_fw.c` with a message that says so. Do not
comment out `port_fw.c` or the `port_fw_*` calls: the update commands are part
of the protocol, and the calls are in `src/token/token_update.c`.

Early board bring-up only, without MCUboot (the token then cannot be updated
in the field: UPDATE_* answer `6D00`, reflash through SWD):

```
west build -b qdsd/nrf52840 . -- \
  -DBOARD_ROOT=<QDSD board repo> -DEXTRA_CONF_FILE="prj_lab.conf;prj_noupdate.conf"
```

## Test

Host tests need mbedTLS 3.6 built with `-fPIC` and `pip install cryptography`:

```
cd tests/host && make MBEDTLS=/path/to/mbedtls-3.6.2 test
```

160 tests build the real `src/token`, `src/protocol`, `src/state_machine`,
`src/security`, `src/port/port_crypto.c` and `src/usb/ccid.c` against a
software model of the two secure elements (`tests/host/port_host.c`) and run
under AddressSanitizer and UBSan:

- `test_flows.py` (81): every flow end to end with real X.509, login and
  policy, RSA, digest-mode CSR, nonce pool, firmware update, replay and
  tampering of every authorisation, a power cut at every write of BIND,
  REBIND, RESET and POLICY, 3,000 random APDUs, a build without update.
- `test_v32.py` (46): receipts (lost reply, logged out, ring, SE failure, a
  power cut at every write of SIGN), records in the SEs (torn certificate,
  power cut during a first certificate write and during a reissue, migration
  from 0.5 with power cuts), DELETE_KEY, key attestation, FACTORY_WIPE
  (refusals, re-made token gets a new identity, power cut at every write,
  repair of a lost or corrupt lifecycle record), verification inside the
  SE050, .pfx import (P-256 and RSA, wrong certificate, wrong key, tampered or
  misdirected wrap, power cut at every write), approvals that must not
  outlive the key in their slot, receipt lookup by request id.
- `test_ccid.py` (9): class descriptor, ATR, reader messages and errors, all
  flows carried over CCID with 2 KB APDUs.
- `test_session.py` (24): failed and repeated SELECT, card power cycle vs
  USB reset (the review's own test scenarios), session epoch, every nonce
  status reason, command chaining and GET RESPONSE (a full RSA flow with
  short APDUs only, also over CCID).

Each new protection was also checked by planting a bug and confirming a test
fails (24 of 24 for 0.6, 19 of 19 for 0.6.1, 4 of 4 for 0.6.2). Independent reviews found one
medium and five low issues in 0.6 and one medium and five low in 0.6.1; all
are fixed and covered by tests (`TestReviewFixes` in `test_v32.py`,
`test_session.py`), except a documented format change for lab-only 0.6.0
receipts (PROTOCOL.md §9).

Compile check against upstream Zephyr (no NCS needed), with and without
firmware update:

```
ZP=<workspace with zephyr v4.1.0 + modules> tests/zephyr_ci/build.sh
ZP=<...> NOUPDATE=1 BUILD=build/ci-noupdate tests/zephyr_ci/build.sh
```

## Decisions in this firmware

- **Key split:** SE050 holds device trust (device key, command and activation
  keys, lifecycle record, counters, device certificate, receipts). SE052F
  holds DSC keys, their records and certificates.
- **Signature checks:** inside the SE050 for stored keys; mbedTLS on the MCU
  only for the self-test and for proving an imported key matches its
  certificate.
- **USB:** CCID, one interface; the TS3USB221 gate opens after the boot
  self-test. Service mode (records inconsistent, or wipe cut off) still
  enumerates so DTI can repair the token.
- **Host side:** one Ascert.en agent per user owns the token (PC/SC) and the
  cloud connection; PKCS#11 / CNG / CryptoTokenKit providers are its clients.
- **Imported keys:** allowed for institutional certificates; the plaintext key
  exists in token RAM only between decryption and the write into the SE052F.
  Origin is recorded permanently and reported in every receipt.

See `docs/PROTOCOL.md` §8 for open decisions and §9 for what this firmware
does meanwhile, and `docs/BRINGUP.md` for what must be checked on hardware.
