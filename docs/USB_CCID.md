# USB transport: CCID smart-card reader (firmware 0.6)

From firmware 0.6 the token enumerates as a **USB CCID reader** (USB class
`0x0B`) with the QDSD applet as a permanently inserted card. Every desktop OS
already has a CCID driver, so the token works with no QDSD driver:

| OS | Driver | API the Ascert.en agent uses |
|---|---|---|
| Windows 10 / 11 | `usbccid.sys` (inbox), Smart Card service | WinSCard (`SCardConnect`, `SCardTransmit`) |
| macOS 11+ | built-in CCID driver (CryptoTokenKit) | PC/SC framework (`SCardTransmit`) |
| Linux | pcsc-lite + `libccid` | PC/SC (`SCardTransmit`) |

Firmware 0.3–0.5 used a vendor interface (class `0xFF`) with WinUSB, which
needed MS OS descriptors on Windows, libusb elsewhere, and gave one process
exclusive access. That interface is gone.

## Descriptors

| Field | Value |
|---|---|
| VID / PID | `0x1915` / `0x520F` (development ids, unchanged from Phase 2) |
| Interface | class `0x0B`, subclass `0`, protocol `0`, 3 endpoints |
| Endpoints | bulk OUT `0x01`, bulk IN `0x81` (64 bytes), interrupt IN `0x82` (8 bytes, 16 ms) |
| `bcdCCID` | 1.10 |
| Slots | 1 (`bMaxSlotIndex` 0), `bMaxCCIDBusySlots` 1 |
| Protocols | T=1 |
| `dwFeatures` | `0x000400BE`: automatic parameters, activation, voltage, clock, baud rate and PPS; **extended APDU level exchange** |
| `dwMaxCCIDMessageLength` | 2122 (10-byte header + the largest APDU, 2112) |
| `bClassGetResponse` / `bClassEnvelope` | `0xFF` (echo) |
| PIN pad, LCD | none |

ATR: `3B 8C 80 01 51 44 53 44 41 73 63 65 72 74 45 4E 36`
(T=1; historical bytes "QDSDAscertEN"; TCK).

The descriptor is built by `src/usb/ccid.c` (`ccid_class_descriptor()`) and
checked by `tests/host/test_ccid.py`.

## Messages

| PC_to_RDR | Answer | Behaviour |
|---|---|---|
| `IccPowerOn` (62) | DataBlock with the ATR | Card reset: SELECT needed again, uploads aborted; login and nonces kept (0.6.1) |
| `IccPowerOff` (63) | SlotStatus, card inactive | Same card reset |
| `GetSlotStatus` (65) | SlotStatus | Card always present; active after power-on |
| `XfrBlock` (6F) | DataBlock with the response APDU | One whole APDU per message (`wLevelParameter` must be 0) |
| `Get/Reset/SetParameters` (6C/6D/61) | Parameters, T=1 | Fixed values (APDU level) |
| `Abort` (72) | SlotStatus OK | Commands run to completion |
| anything else | "command not supported" | As the CCID specification requires |

A USB bus reset or unplug is the full session reset (logged out, nonces
discarded, new session epoch). Hosts limited to short APDUs can use ISO 7816
command chaining and GET RESPONSE (PROTOCOL.md §1.2).

While an APDU runs, the token sends a DataBlock with `bmCommandStatus` = time
extension every second, so drivers wait through RSA-2048 key generation and
other slow secure-element operations.

## Windows Plug and Play

When a card is inserted, Windows looks for a smart-card *minidriver* that
matches the card's ATR. None exists for QDSD (the token is not a CSP/KSP
card), so Device Manager may show "Smart card" with a yellow mark after a
Windows Update search. **PC/SC access still works**; only the minidriver is
missing.

To keep Device Manager clean, ship a small INF with the Ascert.en installer
that installs the inbox **null driver** for this card's id:

```
SCFILTER\CID_51445344417363657274454E
```

Windows builds that id from the ATR's historical bytes; confirm the exact
string on the first unit (Device Manager → the card → Details → Hardware Ids)
before writing the INF. Alternatively, an
administrator can turn off smart-card Plug and Play by group policy. The
Ascert.en signing providers (PKCS#11, CNG key-storage provider, macOS
CryptoTokenKit extension) talk to the agent, not to a minidriver, so no
minidriver is planned.

## Bring-up checks

See `docs/BRINGUP.md` §5.
