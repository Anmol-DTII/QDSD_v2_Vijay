# Hardware bring-up checklist (firmware 0.6)

The token logic is tested on host (159 end-to-end tests, including a power cut
at every persistent write of SIGN, DELETE_KEY, import, FACTORY_WIPE, BIND,
REBIND, RESET, POLICY and certificate writes), and the whole firmware
cross-compiles for the nRF52840 against upstream Zephyr 4.1 with warnings as
errors. What follows could not be verified without the QDSD PCBA and NCS 3.0.
Work through it in order on a lab board (`prj_lab.conf`). Items new in 0.6 are
marked **(0.6)**.

## 1. Build under NCS 3.0
- [ ] `west build -b qdsd/nrf52840 . --sysbuild -- -DBOARD_ROOT=<QDSD board repo> -DEXTRA_CONF_FILE=prj_lab.conf`
      (the application is now the repository root: `CMakeLists.txt`, `Kconfig`,
      `prj*.conf` sit next to `include/` and `src/`).
- [ ] NCS-only symbols are accepted: `CONFIG_NORDIC_SECURITY_BACKEND`,
      `CONFIG_MBEDTLS_SHA256_C`, `CONFIG_MBEDTLS_RSA_C`, `CONFIG_MBEDTLS_PKCS1_V15`,
      `CONFIG_MBEDTLS_GCM_C`, `CONFIG_NRF_APPROTECT_LOCK`. Adjust names if
      Kconfig warns. **(0.6: RSA verify and GCM are new on the MCU.)**
- [ ] The QDSD board definition provides everything `tests/zephyr_ci/nrf52840dk_ci.overlay`
      stands in for: aliases `usb-oe`, `usb-s`, `status-led-{green,orange,blue}`,
      `se2-en`, `se05x-i2c`; nodes `i2c0`, `i2c1`; partition label
      `qdsd_nvs_partition`; MCUboot `slot0_partition`, `slot1_partition`, `boot_partition`.

## 2. Secure-element operations new to this hardware
Session open, ReadObject, WriteBinary, CheckObjectExists, WriteECKey (key-pair
generation) and UserID sessions (ProcessSessionCmd) are carried over from
Phase 2, where they worked. These are new:

| # | Operation | Where | What to check |
|---|---|---|---|
| a | `ECDSASign` without a UserID session | SE050 device key, SE052F DSC | Signature verifies against the read-out public key |
| b | WriteCounter create/increment, `P1_COUNTER = 0x08` | `se05x_link.c` | Create at 0, increment by 1, ReadObject gives 4 bytes BE |
| c | WriteECKey public part only | command, activation keys | Object created; ReadObject returns it |
| d | `DeleteSecureObject` | KEYGEN reuse, DELETE_KEY, RESET | Object gone; CheckObjectExists = false |
| e | `ReadObject_W_Attst` on an EC key object | FACTORY_INIT (SE050) | Verifies against NXP attestation cert |
| f | Session switching SE050 ↔ SE052F | every SIGN | No T=1 errors over 1,000 signatures; time per SIGN |
| g | `CONFIG_PLUGANDTRUST_APDU_BUFFER_SIZE=512` | RSA, attested read | 256-byte results arrive intact through T=1 chaining and SCP03 |
| h | RSA-2048 key generation, ReadRSA, RSASign (algo `0x28`, digest input) | SE052F | As in 0.5 checklist i–k |
| i | SE052F FIPS mode allows RSA-2048 keygen and PKCS#1 v1.5 signing | KEYGEN, SIGN | No `6985`/`6986` |
| j | **(0.6) ECDSAVerify with a stored public key** | every BIND, KEYGEN, LOGIN, SIGN, POLICY, REBIND, RESET, DELETE_KEY, IMPORT, WIPE | Valid signature → `kSE05x_Result_SUCCESS`; flipped bit → FAILURE (token answers `6982`). If the applet refuses verify with a public-only object, set `CONFIG_QDSD_VERIFY_IN_SE=n` and report |
| k | **(0.6) Binary objects up to 2 KB: create with TAG_3 length, write at offsets in 208-byte APDUs, ReadSize, read at offsets** | device cert, DSC certs, slot records, receipts | Round trip of a 2,048-byte certificate; a 208-byte write under SCP03 fits one short APDU (no `6700`) |
| l | **(0.6) Atomicity of one WriteBinary** | slot record, receipt header, state | Cut VBUS during 1,000 slot-record rewrites: every read-back is old or new, never mixed |
| m | **(0.6) NIST P-256 curve after DeleteAll** | FACTORY_INIT after FACTORY_WIPE | CreateECCurve + 5 × SetECCurveParam succeed. On a chip that already has the curve, CreateECCurve must return `6A89` (the code treats only that as "present", then re-applies the parameters and ignores refusals); if the applet returns another status, change `QDSD_SE05X_SW_EXISTS`. Cut power between CreateECCurve and the parameters: the next FACTORY_INIT must still work |
| n | **(0.6) WriteUserID at `0x7FFF0205` (FACTORY_RESET)** | FACTORY_PERSONALISE | Object created on both chips; maxAttempts 0 accepted |
| o | **(0.6) FACTORY_RESET session + DeleteAll** | FACTORY_WIPE | Wrong secret → VerifySessionUserID fails, nothing erased. Right secret → DeleteAll in the session (P2 `0x2A`); afterwards QDSD objects gone, NXP objects (`0x7FFF0206`, `0xF0000012`) present, Platform SCP03 session opens again |
| p | **(0.6) Private-key import: WriteECKey key pair with d and Q** | IMPORT_DATA (P-256) | Key signs; SE052F attestation shows origin *external*. Check whether the SE052F FIPS configuration refuses plaintext key import under Platform SCP03; if so, switch to the applet's wrapped import (ImportExternalObject) — the protocol does not change |
| q | **(0.6) WriteRSAKey CRT in 7 APDUs (p with size, q, dp, dq, qInv, e, n)** | IMPORT_DATA (RSA) | Key signs and verifies with the certificate's modulus; 256-byte modulus APDU sent extended-length through SCP03 |
| r | **(0.6) `ReadObject_W_Attst` on the SE052F** | GET_KEY_ATTESTATION | Attestation key id `0xF0000012` exists on the SE052F; P-256 key object attests; RSA key object: attests or the token omits `38` (logged). Record origin byte values for generated vs imported keys |
| s | **(0.6) SE052F unique id `0x7FFF0206`** | GET_KEY_ATTESTATION `37` | 18 bytes, different from the SE050's |

## 3. Object policies (security hardening)
Objects are still created with the default (NULL) policy. Before production,
and only after §2 passes:
- [ ] Device key: sign + read public + attest; delete only from the
      FACTORY_RESET session.
- [ ] DSC keys: sign + read public + attest + delete.
- [ ] Command / activation keys: verify + read; write/delete from the default session.
- [ ] Counters: increment only; delete only from the FACTORY_RESET session.
- [ ] State, device certificate: write from the default session; delete only
      from the FACTORY_RESET session.
- [ ] Re-run the host-test scenarios on hardware with the policies on (a policy
      that forbids something the token needs shows up as `6986` from the SE).

## 4. Production key management
- [ ] Rotate both chips from NXP default Platform SCP03 keys to DTII keys at
      the factory; `scp03_prod_keys.h` outside the repo (`-DQDSD_KEYS_DIR=`).
- [ ] **(0.6)** FACTORY_RESET secrets: derive per device in DTI's HSM (for
      example HMAC(master, device_id ‖ "SE050") and ‖ "SE052F"); the factory
      tool never stores them.
- [ ] `CONFIG_NRF_APPROTECT_LOCK=y` confirmed locked on a production unit.
- [ ] MCUboot built with the DTII release public key; development key never shipped.

## 5. USB CCID **(0.6)**
- [ ] The token enumerates only after self-test; a board with an SE removed
      stays dark (orange LED, no USB).
- [ ] Windows 10 and 11: `usbccid.sys` binds without any driver package;
      `certutil -scinfo` (or `pcsc_scan` on Linux, `pcsctest` / `security list-smartcards`
      on macOS) lists the reader and the ATR `3B 8C 80 01 … 36`.
- [ ] Note the card's hardware id in Device Manager and build the null-driver
      INF (`docs/USB_CCID.md`).
- [ ] Linux pcsc-lite `libccid`: the reader is recognised from its class
      descriptor (no Info.plist entry needed for class-compliant readers);
      check the libccid version on the target distributions.
- [ ] macOS: built-in CCID driver; `SCardTransmit` works from a test app.
- [ ] 2 KB extended APDUs (WRITE_CERT, FACTORY_PERSONALISE, IMPORT_DATA) and
      2 KB responses in one XfrBlock on all three OSes.
- [ ] Time extension: RSA-2048 KEYGEN (several seconds) completes on all three
      OSes without the driver timing out.
- [ ] **(0.6.1)** Log in, get two nonces, `SCardReconnect(SCARD_RESET_CARD)`,
      SELECT: still logged in (GET_INFO `27` = `01`, same `39` epoch) and
      both nonces usable for SIGN. Same after pcsc-lite's idle power-down on
      Linux. Unplug, or a USB reset (for example sleep/resume): logged out,
      new epoch, nonces answer `6984` with `3A` = `03`.
- [ ] **(0.6.1)** With the token logged in, insert a second card-using program
      (or let Windows Plug and Play probe the card): its SELECTs of other AIDs
      get `6A82` and the token stays selected and logged in.
- [ ] **(0.6.1)** If an OS's CCID driver refuses extended APDUs: switch the
      agent to short APDUs (chaining + GET RESPONSE, PROTOCOL.md §1.2) and
      run the full flow, including RSA-2048 SIGN.
- [ ] Production VID/PID assigned to DTII before release.

## 6. Update path
- [ ] UPDATE_BEGIN/WRITE/FINISH with a signed 0.6.x image → reboot, MCUboot
      installs, new version in GET_INFO `11`.
- [ ] Wrong-key image refused by MCUboot; older version refused by the token
      at the first chunk.
- [ ] Power cut while MCUboot copies the image: the next boot finishes the copy.
- [ ] `VERSION` equals `QDSD_FW_*` in `include/qdsd/qdsd_config.h`.

## 7. Upgrade from firmware 0.3 / 0.4 / 0.5 **(0.6)**
- [ ] On a lab token personalised and paired by 0.5 (with a certified P-256
      and an RSA DSC), flash 0.6. First boot: device certificate, slot records
      and certificates move into the SEs, the receipt ring is created, NVS
      records are deleted, token comes up LOGGED_OUT, both DSCs sign.
- [ ] Cut power at random points during that first boot (20 runs): the token
      always ends up migrated and working.
- [ ] Such a token has no FACTORY_RESET objects: FACTORY_WIPE answers `6985`
      (document the NXP-tool procedure for refurbishing old tokens).
- [ ] Middleware must speak CCID and accept 9-byte slot entries (protocol 3.2).

## 8. Timing and robustness
- [ ] Cut power at random points during SIGN (relay on VBUS, 500 runs): after
      every boot, GET_RECEIPT for the counter returns the receipt (status 00 or
      02), or `6A88` only if the cut came right after the counter increment.
- [ ] Cut power during DELETE_KEY, IMPORT_DATA, FACTORY_WIPE (200 runs each):
      the token is in the old state or the new one, or (wipe only) in service
      mode where FACTORY_WIPE finishes it.
- [ ] One SIGN takes < 2 s end-to-end (now with three extra SE050 writes for
      the receipt); measure P-256 and RSA-2048.
- [ ] Two signing apps plus a login waiting for the phone at once: all three
      complete (nonce pool).
