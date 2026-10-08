/**
 * @file stmt.c
 * @brief Canonical signed statements (PROTOCOL.md §2.2–2.7).
 */
#include <errno.h>
#include <string.h>

#include "protocol/der.h"
#include "port/port.h"
#include "protocol/stmt.h"

typedef struct {
	uint8_t  tag;
	uint16_t min;
	uint16_t max;
} field_spec_t;

typedef struct {
	uint8_t             purpose;
	uint8_t             n;
	const field_spec_t *f;
} schema_t;

#define FX(t, l)      { (t), (l), (l) }
#define FR(t, lo, hi) { (t), (lo), (hi) }

static const field_spec_t s_bind[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_ACTIVATION_PUB, 65),
	FX(F_POLICY_FLAGS, 1),
};
static const field_spec_t s_keygen_consent[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_VALID_UNTIL, 8), FX(F_METHOD, 1),
};
static const field_spec_t s_keygen_env[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_SETTING_REF, 32),
};
static const field_spec_t s_sign_assert[] = {
	FX(F_DEVICE_ID, 16), FX(F_NONCE, 32), FX(F_H_TBS, 32), FX(F_H_CTX, 32),
	FX(F_REQUEST_ID, 16), FX(F_TIME, 8), FX(F_KEYGEN_SEQ, 4), FX(F_KEY_SLOT, 1),
	FX(F_METHOD, 1),
};
static const field_spec_t s_rebind[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_NEW_KEY_HASH, 32), FX(F_METHOD, 1),
};
static const field_spec_t s_policy[] = {
	FX(F_DEVICE_ID, 16), FX(F_TIME, 8), FX(F_POLICY_NO, 4), FX(F_POLICY_FLAGS, 1),
	FX(F_METHOD, 1),
};
static const field_spec_t s_login[] = {
	FX(F_DEVICE_ID, 16), FX(F_NONCE, 32), FX(F_TIME, 8), FX(F_METHOD, 1),
};
static const field_spec_t s_reset[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4),
};
static const field_spec_t s_attest[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_STATE, 1), FR(F_CHALLENGE, 16, 32),
	FX(F_SIGN_COUNTER, 4), FX(F_FW_VERSION, 4), FX(F_KEYGEN_COUNTER, 4),
	FX(F_CMD_KEY_HASH, 32), FX(F_ACT_KEY_HASH, 32), FX(F_POLICY_NO, 4),
	FX(F_POLICY_FLAGS, 1),
};
static const field_spec_t s_factory_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_STATE, 1), FX(F_SIGN_COUNTER, 4),
	FX(F_KEYGEN_COUNTER, 4), FX(F_CMD_KEY_HASH, 32), FX(F_DEVICE_CERT_HASH, 32),
};
static const field_spec_t s_bind_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_STATE, 1), FX(F_ACT_KEY_HASH, 32),
	FX(F_POLICY_NO, 4), FX(F_POLICY_FLAGS, 1),
};
static const field_spec_t s_key_attest[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_KEY_SLOT, 1), FR(F_DSC_PUB, 91, 294),
	FX(F_KEY_ORIGIN, 1),
};
static const field_spec_t s_sign_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_NONCE, 32), FX(F_H_TBS, 32), FX(F_H_CTX, 32),
	FX(F_REQUEST_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_SIGN_COUNTER, 4), FX(F_KEY_SLOT, 1),
	FX(F_SIG_HASH, 32), FX(F_STATUS, 1), FX(F_KEY_ORIGIN, 1),
};
/* v3.2 */
static const field_spec_t s_delete_key[] = {
	FX(F_DEVICE_ID, 16), FX(F_TIME, 8), FX(F_KEYGEN_SEQ, 4), FX(F_KEY_SLOT, 1),
	FX(F_METHOD, 1),
};
static const field_spec_t s_import_consent[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_VALID_UNTIL, 8), FX(F_METHOD, 1),
	FX(F_CERT_HASH, 32), FX(F_KEY_ALG, 1),
};
static const field_spec_t s_wipe[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4),
};
static const field_spec_t s_import_offer[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_CERT_HASH, 32), FX(F_IMPORT_PUB, 65),
	FX(F_KEY_ALG, 1),
};
static const field_spec_t s_key_status[] = {
	FX(F_DEVICE_ID, 16), FR(F_CHALLENGE, 16, 32), FX(F_KEYGEN_SEQ, 4), FX(F_KEY_SLOT, 1),
	FR(F_DSC_PUB, 91, 294), FX(F_STATUS, 1), FX(F_CERT_HASH, 32), FX(F_KEY_ORIGIN, 1),
};
static const field_spec_t s_key_deleted[] = {
	FX(F_DEVICE_ID, 16), FX(F_KEYGEN_SEQ, 4), FX(F_KEY_SLOT, 1),
};
static const field_spec_t s_rebind_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_ACT_KEY_HASH, 32),
};
static const field_spec_t s_reset_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_BINDING_NO, 4), FX(F_STATE, 1),
};
static const field_spec_t s_policy_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_POLICY_NO, 4), FX(F_POLICY_FLAGS, 1),
};
static const field_spec_t s_login_receipt[] = {
	FX(F_DEVICE_ID, 16), FX(F_NONCE, 32), FX(F_POLICY_NO, 4), FX(F_SESSION, 1),
};

#define SCHEMA(p, arr) { (p), (uint8_t)(sizeof(arr) / sizeof((arr)[0])), (arr) }

static const schema_t s_schemas[] = {
	SCHEMA(P_BIND, s_bind),
	SCHEMA(P_KEYGEN_CONSENT, s_keygen_consent),
	SCHEMA(P_KEYGEN_ENVELOPE, s_keygen_env),
	SCHEMA(P_SIGN_ASSERTION, s_sign_assert),
	SCHEMA(P_REBIND, s_rebind),
	SCHEMA(P_RESET, s_reset),
	SCHEMA(P_POLICY, s_policy),
	SCHEMA(P_LOGIN_ASSERTION, s_login),
	SCHEMA(P_ATTEST, s_attest),
	SCHEMA(P_FACTORY_RECEIPT, s_factory_receipt),
	SCHEMA(P_BIND_RECEIPT, s_bind_receipt),
	SCHEMA(P_KEY_ATTEST, s_key_attest),
	SCHEMA(P_SIGN_RECEIPT, s_sign_receipt),
	SCHEMA(P_REBIND_RECEIPT, s_rebind_receipt),
	SCHEMA(P_RESET_RECEIPT, s_reset_receipt),
	SCHEMA(P_POLICY_RECEIPT, s_policy_receipt),
	SCHEMA(P_LOGIN_RECEIPT, s_login_receipt),
	SCHEMA(P_DELETE_KEY, s_delete_key),
	SCHEMA(P_IMPORT_CONSENT, s_import_consent),
	SCHEMA(P_WIPE, s_wipe),
	SCHEMA(P_IMPORT_OFFER, s_import_offer),
	SCHEMA(P_KEY_STATUS, s_key_status),
	SCHEMA(P_KEY_DELETED, s_key_deleted),
};

static const schema_t *schema_for(uint8_t purpose)
{
	size_t i;

	for (i = 0U; i < (sizeof(s_schemas) / sizeof(s_schemas[0])); i++) {
		if (s_schemas[i].purpose == purpose) {
			return &s_schemas[i];
		}
	}
	return NULL;
}

int stmt_parse(const uint8_t *buf, size_t len, stmt_t *out)
{
	const schema_t *sc;
	tlv_reader_t r;
	tlv_item_t it;
	uint8_t idx = 0U;
	int rc;

	if ((buf == NULL) || (out == NULL)) {
		return -EINVAL;
	}
	memset(out, 0, sizeof(*out));

	if ((len < STMT_HDR_LEN) || (memcmp(buf, STMT_MAGIC, STMT_MAGIC_LEN) != 0)) {
		return -EBADMSG;
	}
	sc = schema_for(buf[STMT_MAGIC_LEN]);
	if (sc == NULL) {
		return -EBADMSG;
	}

	out->purpose = buf[STMT_MAGIC_LEN];
	out->raw = buf;
	out->raw_len = len;

	tlv_reader_init(&r, buf + STMT_HDR_LEN, len - STMT_HDR_LEN);
	while ((rc = tlv_next(&r, &it)) == 1) {
		const field_spec_t *fs;

		/* Exactly the schema fields, in schema (= ascending tag) order. */
		if (idx >= sc->n) {
			return -EBADMSG;
		}
		fs = &sc->f[idx];
		if ((it.tag != fs->tag) || (it.len < fs->min) || (it.len > fs->max)) {
			return -EBADMSG;
		}
		out->f[it.tag] = it.val;
		out->flen[it.tag] = (uint16_t)it.len;
		idx++;
	}
	if ((rc < 0) || (idx != sc->n)) {
		return -EBADMSG;
	}
	return 0;
}

uint32_t stmt_u32(const stmt_t *s, uint8_t tag)
{
	return ((s->f[tag] != NULL) && (s->flen[tag] == 4U)) ? tlv_be32(s->f[tag]) : 0U;
}

uint8_t stmt_u8(const stmt_t *s, uint8_t tag)
{
	return ((s->f[tag] != NULL) && (s->flen[tag] == 1U)) ? s->f[tag][0] : 0U;
}

void stmt_begin(tlv_writer_t *w, uint8_t *buf, size_t cap, uint8_t purpose)
{
	tlv_writer_init(w, buf, cap);
	tlv_put_raw(w, STMT_MAGIC, STMT_MAGIC_LEN);
	tlv_put_raw(w, &purpose, 1U);
}

int stmt_verify(const stmt_t *s, const uint8_t *sig, size_t sig_len, const uint8_t pub[65])
{
	uint8_t raw[64];
	uint8_t h[32];

	if ((s == NULL) || (sig == NULL) || (pub == NULL)) {
		return -EINVAL;
	}
	if (der_sig_any_to_raw(sig, sig_len, raw) != 0) {
		return -EPERM;
	}
	if (port_sha256(s->raw, s->raw_len, h) != 0) {
		return -EIO;
	}
	return (port_ecdsa_p256_verify(pub, h, raw) == 0) ? 0 : -EPERM;
}

int stmt_verify_stored(const stmt_t *s, const uint8_t *sig, size_t sig_len, port_pubkey_t which)
{
	uint8_t raw[64];
	uint8_t h[32];
	int rc;

	if ((s == NULL) || (sig == NULL)) {
		return -EINVAL;
	}
	if (der_sig_any_to_raw(sig, sig_len, raw) != 0) {
		return -EPERM;
	}
	if (port_sha256(s->raw, s->raw_len, h) != 0) {
		return -EIO;
	}
	rc = port_pubkey_verify(which, h, raw);
	if ((rc == 0) || (rc == -EPERM)) {
		return rc;
	}
	return (rc == -ENOENT) ? -ENOENT : -EIO;
}

bool stmt_schema_ok(const uint8_t *buf, size_t len)
{
	stmt_t s;

	return stmt_parse(buf, len, &s) == 0;
}
