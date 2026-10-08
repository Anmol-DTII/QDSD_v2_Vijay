/**
 * @file token_engine.h
 * @brief QDSD token core — the only entry points the transport/main need.
 */
#ifndef TOKEN_ENGINE_H
#define TOKEN_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#include "qdsd/qdsd_config.h"

/* Status words (PROTOCOL.md §6) */
#define SW_OK                0x9000U
#define SW_WRONG_LENGTH      0x6700U
#define SW_SECURITY          0x6982U
#define SW_LOGGED_OUT        0x6983U
#define SW_STALE             0x6984U
#define SW_CONDITIONS        0x6985U
#define SW_SLOT_STATE        0x6986U
#define SW_WRONG_DATA        0x6A80U
#define SW_FILE_NOT_FOUND    0x6A82U
#define SW_NO_SPACE          0x6A84U
#define SW_WRONG_P1P2        0x6A86U
#define SW_NOT_FOUND         0x6A88U
#define SW_INS_NOT_SUPPORTED 0x6D00U
#define SW_CLA_NOT_SUPPORTED 0x6E00U
#define SW_INTERNAL          0x6F00U

/* Instruction bytes */
#define INS_SELECT              0xA4U
#define INS_GET_INFO            0xC1U
#define INS_GET_CERT            0xC3U
#define INS_WRITE_CERT          0xC5U
#define INS_GET_DEVICE_CERT     0xD0U
#define INS_ATTEST              0xD1U
#define INS_BIND                0xD2U
#define INS_GET_SESSION_NONCE   0xD3U
#define INS_SIGN                0xD4U
#define INS_KEYGEN              0xD5U
#define INS_SIGN_CSR            0xD6U
#define INS_REBIND              0xD7U
#define INS_RESET               0xD8U
#define INS_LOGIN               0xD9U
#define INS_LOGOUT              0xDAU
#define INS_POLICY              0xDBU
#define INS_DELETE_KEY          0xDCU
#define INS_GET_RECEIPT         0xDDU
#define INS_GET_KEY_ATTESTATION 0xDEU
#define INS_IMPORT_BEGIN        0xDFU
#define INS_IMPORT_DATA         0xCBU
#define INS_FACTORY_INIT        0xE0U
#define INS_FACTORY_PERSONALISE 0xE1U
#define INS_FACTORY_CLOSE       0xE2U
#define INS_FACTORY_WIPE        0xE3U
#define INS_FACTORY_DRIVE       0xE6U /* install-drive image (factory only) */
#define INS_UPDATE_BEGIN        0xE8U
#define INS_UPDATE_WRITE        0xE9U
#define INS_UPDATE_FINISH       0xEAU

/** token_engine_init(): token is FAULT but answers GET_INFO and FACTORY_WIPE. */
#define QDSD_INIT_SERVICE 1

/**
 * Load the lifecycle record, finish any interrupted BIND/REBIND/RESET, move
 * records left in MCU flash by firmware 0.3-0.5 into the secure elements,
 * finish signing receipts cut off by a power loss, and check that every
 * object the current state needs is present.
 * Returns 0 for normal service, QDSD_INIT_SERVICE if the token is FAULT
 * (only GET_INFO and FACTORY_WIPE are served), negative never.
 */
int token_engine_init(void);

/**
 * USB bus reset or unplug: deselect, end the login and pairing session, drop
 * every nonce, abort uploads, new session epoch.
 */
void token_engine_session_reset(void);

/**
 * Card power cycle (CCID IccPowerOn / IccPowerOff, e.g. SCardReconnect with
 * reset, pcsc-lite idle power-down): SELECT is needed again and uploads in
 * progress are aborted, but the login, the pairing session and the
 * outstanding nonces are kept (PROTOCOL.md §3.2).
 */
void token_engine_card_reset(void);

/**
 * Process one command APDU. Always writes at least a 2-byte status word.
 * rsp_cap must be >= 2.
 */
void token_engine_process(const uint8_t *apdu, size_t len,
		       uint8_t *rsp, size_t rsp_cap, size_t *rsp_len);

/** Current lifecycle state (LC_* from state.h). */
uint8_t token_engine_lifecycle(void);

#endif /* TOKEN_ENGINE_H */
