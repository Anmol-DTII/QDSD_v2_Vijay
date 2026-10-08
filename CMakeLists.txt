cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(qdsd_firmware VERSION 0.6.2)

# ── Include paths ─────────────────────────────────────────────────────────────
# One root: every header is included by subsystem, e.g. "token/token_engine.h",
# so the folder in an #include is the folder the code lives in.
target_include_directories(app PRIVATE
    include
)

# Production Platform SCP03 keys (scp03_prod_keys.h) live outside the repo:
#   west build ... -- -DQDSD_KEYS_DIR=/secure/path
if(DEFINED QDSD_KEYS_DIR)
    target_include_directories(app PRIVATE ${QDSD_KEYS_DIR})
endif()

# ── Source files ──────────────────────────────────────────────────────────────
target_sources(app PRIVATE
    src/main.c

    # Token: command processor, one file per flow (PROTOCOL.md)
    src/token/token_engine.c
    src/token/token_store.c
    src/token/token_journal.c
    src/token/token_receipt.c
    src/token/token_factory.c
    src/token/token_pairing.c
    src/token/token_dsc.c
    src/token/token_import.c
    src/token/token_sign.c
    src/token/token_update.c

    # Protocol encodings: TLV, signed statements, DER
    src/protocol/tlv.c
    src/protocol/stmt.c
    src/protocol/der.c

    # Lifecycle record + journal (stored in SE050)
    src/state_machine/state_record.c

    # Security: boot self-test
    src/security/self_test.c

    # Port: port.h on SE050 / SE052F / MCU
    src/port/port_trust.c
    src/port/port_dsc.c
    src/port/port_store.c
    src/port/port_crypto.c
    src/port/port_platform.c
    src/port/port_fw.c

    # Secure elements (Plug & Trust nano)
    src/se05x/se05x_bus.c
    src/se05x/se05x_link.c
    src/se05x/se05x_scp03_keys.c

    # Storage: MCU flash NVS (legacy records, read once)
    src/storage/nvs_store.c

    # USB: CCID smart-card reader class
    src/usb/ccid.c
    src/usb/token_usb.c

    # Board HAL (carried over from Phase 2)
    src/hal/hal_gpio.c
    src/hal/hal_i2c.c
    src/hal/hal_power.c
)

# USB device-stack private header (usb_descriptor.h).
zephyr_include_directories(${ZEPHYR_BASE}/subsys/usb/device)
