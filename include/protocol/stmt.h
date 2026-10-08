/**
 * @file stmt.h
 * @brief Signed statements: canonical "QDS3" || purpose || ordered TLV fields.
 */
#ifndef QDSD_STMT_H
#define QDSD_STMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "port/port.h"
#include "protocol/tlv.h"

#define STMT_MAGIC        "QDS3"
#define STMT_MAGIC_LEN    4U
#define STMT_HDR_LEN      (STMT_MAGIC_LEN + 1U)

/* Field tags (PROTOCOL.md §2.3) */
enum {
	F_DEVICE_ID        = 0x01,
	F_BINDING_NO       = 0x02,
	F_STATE            = 0x03,
	F_CHALLENGE        = 0x04,
	F_NONCE            = 0x05,
	F_H_TBS            = 0x06,
	F_H_CTX            = 0x07,
	F_REQUEST_ID       = 0x08,
	F_TIME             = 0x09,
	F_ACTIVATION_PUB   = 0x0A,
	F_NEW_KEY_HASH     = 0x0B,
	F_KEYGEN_SEQ       = 0x0C,
	F_SIGN_COUNTER     = 0x0D,
	F_KEY_SLOT         = 0x0E,
	F_DSC_PUB          = 0x0F,
	F_SIG_HASH         = 0x10,
	F_FW_VERSION       = 0x11,
	F_VALID_UNTIL      = 0x12,
	F_SETTING_REF      = 0x13,
	F_STATUS           = 0x14,
	F_KEYGEN_COUNTER   = 0x15,
	F_DEVICE_PUB       = 0x16,
	F_CMD_KEY_HASH     = 0x17,
	F_ACT_KEY_HASH     = 0x18,
	F_DEVICE_CERT_HASH = 0x19,
	F_POLICY_NO        = 0x1A,
	F_POLICY_FLAGS     = 0x1F,
	F_METHOD           = 0x26,
	F_SESSION          = 0x27,
	F_CERT_HASH        = 0x2C, /* v3.2: SHA-256 of a DER certificate      */
	F_KEY_ORIGIN       = 0x2D, /* v3.2: 0 generated in token, 1 imported  */
	F_IMPORT_PUB       = 0x2E, /* v3.2: token's ephemeral import key      */
	F_KEY_ALG          = 0x2F, /* v3.2: QDSD_ALG_*                        */
	F_MAX              = 0x2F,
};

/* Key origin (PROTOCOL.md §2.8) */
#define ORIGIN_GENERATED 0x00U
#define ORIGIN_IMPORTED  0x01U

/* Approval methods (PROTOCOL.md §2.4) */
#define METHOD_MIN 0x01U
#define METHOD_MAX 0x05U

/* Policy flags (PROTOCOL.md §2.5) */
#define POLICY_LOGIN_REQUIRED 0x01U
#define POLICY_DEFINED_BITS   0x01U

/* Purposes (PROTOCOL.md §2.7) */
enum {
	P_BIND            = 0x01,
	P_KEYGEN_CONSENT  = 0x02,
	P_KEYGEN_ENVELOPE = 0x03,
	P_SIGN_ASSERTION  = 0x04,
	P_REBIND          = 0x05,
	P_RESET           = 0x06,
	P_POLICY          = 0x07,
	P_LOGIN_ASSERTION = 0x08,
	P_DELETE_KEY      = 0x09,
	P_IMPORT_CONSENT  = 0x0A,
	P_WIPE            = 0x0B,
	P_ATTEST          = 0x81,
	P_FACTORY_RECEIPT = 0x82,
	P_BIND_RECEIPT    = 0x83,
	P_KEY_ATTEST      = 0x84,
	P_SIGN_RECEIPT    = 0x85,
	P_REBIND_RECEIPT  = 0x86,
	P_RESET_RECEIPT   = 0x87,
	P_POLICY_RECEIPT  = 0x88,
	P_LOGIN_RECEIPT   = 0x89,
	P_IMPORT_OFFER    = 0x8A,
	P_KEY_STATUS      = 0x8B,
	P_KEY_DELETED     = 0x8C,
};

typedef struct {
	uint8_t        purpose;
	const uint8_t *raw;          /* whole statement as signed */
	size_t         raw_len;
	const uint8_t *f[F_MAX + 1]; /* field value pointers (NULL if absent) */
	uint16_t       flen[F_MAX + 1];
} stmt_t;

/**
 * Parse a statement and validate it strictly against the schema of its
 * purpose. Returns 0, or -EBADMSG for any deviation from canonical form.
 */
int stmt_parse(const uint8_t *buf, size_t len, stmt_t *out);

/** Field accessors (caller has already parsed with the schema). */
uint32_t stmt_u32(const stmt_t *s, uint8_t tag);
uint8_t  stmt_u8(const stmt_t *s, uint8_t tag);

/** Start building a device statement into w. */
void stmt_begin(tlv_writer_t *w, uint8_t *buf, size_t cap, uint8_t purpose);

/**
 * Verify sig (raw or DER) over SHA-256(raw) with pub.
 * Returns 0 if valid, -EPERM if the signature does not verify.
 */
int stmt_verify(const stmt_t *s, const uint8_t *sig, size_t sig_len, const uint8_t pub[65]);

/**
 * Verify sig (raw or DER) over SHA-256(raw) with a key stored in the SE050;
 * the check runs inside the element. 0 valid, -EPERM invalid, -EIO/-ENOENT.
 */
int stmt_verify_stored(const stmt_t *s, const uint8_t *sig, size_t sig_len, port_pubkey_t which);

/** Self-check a statement the token built (used by tests and debug builds). */
bool stmt_schema_ok(const uint8_t *buf, size_t len);

#endif /* QDSD_STMT_H */
