/**
 * @file se05x_link.c
 * @brief SE050/SE052F sessions and object operations over Plug & Trust nano.
 *
 * Session open sequences are carried over unchanged from the Phase-2 firmware
 * (se050_pnt.c / se052f_pnt.c), where they were proven on the QDSD PCBA.
 * Object operations use the nano package Se05x_API_* calls; the one command it
 * lacks (WriteCounter) is built the same way the package builds its own.
 *
 * v3.2 adds: binary objects of any size (certificates, receipts), ECDSAVerify
 * with stored keys, private-key import (institutional .pfx), NIST P-256 curve
 * creation, and the FACTORY_RESET UserID session with DeleteAll. The UserID
 * session wrapping (ProcessSessionCmd) is the Phase-2 se052f_pnt.c sequence,
 * proven on the QDSD PCBA for PIN sessions.
 *
 * Items marked BRINGUP are new on this hardware and listed in docs/BRINGUP.md.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "protocol/der.h"
#include "qdsd/qdsd_objids.h"
#include "se05x/se05x_bus.h"
#include "se05x/se05x_link.h"
#include "se05x/se05x_scp03_keys.h"

LOG_MODULE_REGISTER(se05x_link, LOG_LEVEL_INF);

#if defined(CONFIG_PLUGANDTRUST)

#include "se05x/se05x_smlog_shim.h"
#include "se05x_APDU_apis.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "phNxpEse_Api.h"
#if defined(WITH_PLATFORM_SCP03)
#include "se05x_scp03.h"
/* Nano package keeps this prototype private to se05x_APDU_impl.c. */
smStatus_t Se05x_API_SCP03_CreateSession(pSe05xSession_t session_ctx);
#endif

struct se_handle {
	Se05xSession_t sess;
};

static struct se_handle s_h;
static int s_open = -1; /* qdsd_se_t of the open session, -1 = none */

static const uint8_t k_applet_aid[] = {
	0xA0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
	0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00,
};

static qdsd_se05x_bus_t bus_of(qdsd_se_t w)
{
	return (w == QDSD_SE_DEV) ? QDSD_SE05X_BUS_SE050 : QDSD_SE05X_BUS_SE052F;
}

/* ── Session open/close (from Phase-2 se050_pnt.c / se052f_pnt.c) ─── */

static int open_se050(Se05xSession_t *s)
{
	size_t rx_len;
	size_t tx_len;
	smStatus_t st;

	memset(s, 0, sizeof(*s));
#if defined(CONFIG_PLUGANDTRUST_SCP03)
	se05x_scp03_bind(0, s);
#endif
	rx_len = sizeof(s->apdu_buffer);
	st = smComT1oI2C_Init(&s->conn_context, NULL);
	if (st != SM_OK) {
		goto fail;
	}
	/* smComT1oI2C_Init restores the compile-time I2C0 alias. */
	if (qdsd_se05x_bus_select_locked(QDSD_SE05X_BUS_SE050) != 0) {
		goto fail;
	}
	st = smComT1oI2C_Open(s->conn_context, ESE_MODE_NORMAL, 0x00, s->apdu_buffer, &rx_len);
	if (st != SM_OK) {
		goto fail;
	}

	s->apdu_buffer[0] = 0x00U;
	s->apdu_buffer[1] = 0xA4U;
	s->apdu_buffer[2] = 0x04U;
	s->apdu_buffer[3] = 0x00U;
	s->apdu_buffer[4] = (uint8_t)sizeof(k_applet_aid);
	memcpy(&s->apdu_buffer[5], k_applet_aid, sizeof(k_applet_aid));
	tx_len = 5U + sizeof(k_applet_aid) + 1U;
	s->apdu_buffer[tx_len - 1U] = 0x00U;
	rx_len = sizeof(s->apdu_buffer);
	st = smComT1oI2C_TransceiveRaw(s->conn_context, s->apdu_buffer, tx_len,
				       s->apdu_buffer, &rx_len);
	if ((st != SM_OK) || (rx_len < 2U)) {
		goto fail;
	}
	st = ((smStatus_t)s->apdu_buffer[rx_len - 2U] << 8) | s->apdu_buffer[rx_len - 1U];
	if (st != SM_OK) {
		goto fail;
	}
	if (rx_len >= 6U) {
		s->applet_version = ((uint32_t)s->apdu_buffer[0] << 24) |
				    ((uint32_t)s->apdu_buffer[1] << 16) |
				    ((uint32_t)s->apdu_buffer[2] << 8) | s->apdu_buffer[3];
	}
#if defined(CONFIG_PLUGANDTRUST_SCP03) && defined(WITH_PLATFORM_SCP03)
	st = Se05x_API_SCP03_CreateSession(s);
	if (st != SM_OK) {
		LOG_ERR("SE050 SCP03 session failed: 0x%04x", (unsigned int)st);
		goto fail;
	}
#endif
	return 0;

fail:
	LOG_ERR("SE050 session open failed: 0x%04x", (unsigned int)st);
	if (s->conn_context != NULL) {
		(void)smComT1oI2C_Close(s->conn_context, 0);
	}
	memset(s, 0, sizeof(*s));
	return -EIO;
}

static int open_se052f(Se05xSession_t *s)
{
	smStatus_t st;

	memset(s, 0, sizeof(*s));
#if defined(CONFIG_PLUGANDTRUST_SCP03)
	se05x_scp03_bind(1, s);
#endif
	st = Se05x_API_SessionOpen(s);
	if (st != SM_OK) {
		LOG_ERR("SE052F session open failed: 0x%04x", (unsigned int)st);
		memset(s, 0, sizeof(*s));
		return -EIO;
	}
#if defined(CONFIG_PLUGANDTRUST_SCP03)
	if (s->scp03_session == 0U) {
		LOG_ERR("SE052F SCP03 not established");
		(void)Se05x_API_SessionClose(s);
		memset(s, 0, sizeof(*s));
		return -EIO;
	}
#endif
	return 0;
}

static void close_open_session(void)
{
	if (s_open < 0) {
		return;
	}
	if (qdsd_se05x_bus_select_locked(bus_of((qdsd_se_t)s_open)) == 0) {
		(void)Se05x_API_SessionClose(&s_h.sess);
	}
	memset(&s_h.sess, 0, sizeof(s_h.sess));
	s_open = -1;
}

se_handle_t *se_acquire(qdsd_se_t which)
{
	int rc;

	if (qdsd_se05x_bus_lock(bus_of(which)) != 0) {
		return NULL;
	}
	if (s_open == (int)which) {
		return &s_h;
	}
	close_open_session();
	if (qdsd_se05x_bus_select_locked(bus_of(which)) != 0) {
		qdsd_se05x_bus_unlock();
		return NULL;
	}
	rc = (which == QDSD_SE_DEV) ? open_se050(&s_h.sess) : open_se052f(&s_h.sess);
	if (rc != 0) {
		qdsd_se05x_bus_unlock();
		return NULL;
	}
	s_open = (int)which;
	return &s_h;
}

void se_release(se_handle_t *h, bool ok)
{
	if (h == NULL) {
		return;
	}
	if (!ok) {
		close_open_session();
	}
	qdsd_se05x_bus_unlock();
}

int se_link_init(void)
{
	se_handle_t *h;

	h = se_acquire(QDSD_SE_DEV);
	if (h == NULL) {
		return -EIO;
	}
	LOG_INF("SE050 applet 0x%08x", (unsigned int)h->sess.applet_version);
	se_release(h, true);

	h = se_acquire(QDSD_SE_DSC);
	if (h == NULL) {
		return -EIO;
	}
	LOG_INF("SE052F applet 0x%08x", (unsigned int)h->sess.applet_version);
	se_release(h, true);
	return 0;
}

static int sm_to_errno(smStatus_t st)
{
	const unsigned int sw = (unsigned int)st;

	if (st == SM_OK) {
		return 0;
	}
	if ((sw == 0x6A82U) || (sw == 0x6A88U)) {
		return -ENOENT; /* object not found / referenced data not found */
	}
	return -EIO;
}

/* ── Object operations ──────────────────────────────────────────────── */

int se_exists(se_handle_t *h, uint32_t id, bool *exists)
{
	SE05x_Result_t r = kSE05x_Result_NA;
	smStatus_t st = Se05x_API_CheckObjectExists(&h->sess, id, &r);

	if (st != SM_OK) {
		return -EIO;
	}
	*exists = (r == kSE05x_Result_SUCCESS);
	return 0;
}

int se_delete(se_handle_t *h, uint32_t id)
{
	bool ex = false;
	int rc = se_exists(h, id, &ex);

	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	return sm_to_errno(Se05x_API_DeleteSecureObject(&h->sess, id));
}

int se_gen_p256(se_handle_t *h, uint32_t id)
{
	smStatus_t st;
	bool ex = false;

	if ((se_exists(h, id, &ex) == 0) && ex) {
		(void)se_delete(h, id);
	}
	/* NULL policy: default access. BRINGUP: restrict to sign + read-public. */
	st = Se05x_API_WriteECKey(&h->sess, NULL, 0U, id, kSE05x_ECCurve_NIST_P256, NULL, 0U,
				  NULL, 0U, kSE05x_INS_NA, kSE05x_KeyPart_Pair);
	return sm_to_errno(st);
}

int se_write_p256_pub(se_handle_t *h, uint32_t id, const uint8_t pub[65])
{
	smStatus_t st;
	bool ex = false;

	if ((se_exists(h, id, &ex) == 0) && ex) {
		int rc = se_delete(h, id);

		if ((rc != 0) && (rc != -ENOENT)) {
			return rc;
		}
	}
	/* BRINGUP: public-only EC object write. */
	st = Se05x_API_WriteECKey(&h->sess, NULL, 0U, id, kSE05x_ECCurve_NIST_P256, NULL, 0U,
				  pub, 65U, kSE05x_INS_NA, kSE05x_KeyPart_Public);
	return sm_to_errno(st);
}

int se_read_p256_pub(se_handle_t *h, uint32_t id, uint8_t pub[65])
{
	uint8_t buf[128];
	size_t len = sizeof(buf);
	smStatus_t st;
	bool ex = false;
	int rc;

	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	/* Key objects: offset/length 0 (Phase-2 note: non-zero length -> 6A80). */
	st = Se05x_API_ReadObject(&h->sess, id, 0U, 0U, buf, &len);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	if ((len == 65U) && (buf[0] == 0x04U)) {
		memcpy(pub, buf, 65U);
		return 0;
	}
	/* Some applet versions return a DER SubjectPublicKeyInfo. */
	return (der_spki_p256_pubkey(buf, len, pub) == 0) ? 0 : -EBADMSG;
}

int se_sign_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], uint8_t sig[64])
{
	uint8_t der[80];
	size_t der_len = sizeof(der);
	smStatus_t st;

	st = Se05x_API_ECDSASign(&h->sess, id, kSE05x_ECSignatureAlgo_SHA_256, hash, 32U, der,
				 &der_len);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	return (der_sig_to_raw(der, der_len, sig) == 0) ? 0 : -EBADMSG;
}

/*
 * WriteCounter (AN12413): CLA 80, INS_WRITE, P1_COUNTER, P2_DEFAULT,
 * TAG_1 object id, TAG_2 size (creates). Without TAG_2/TAG_3 the counter is
 * incremented by one. The nano package has no wrapper, so the command is built
 * in the session APDU buffer exactly like its own Se05x_API_* functions do
 * (DoAPDUTx applies SCP03 in place).
 * P1_COUNTER = 0x08 is not in the nano enum; value from NXP's full
 * middleware (se05x_enums.h kSE05x_P1_COUNTER).
 */
#define QDSD_SE05X_P1_COUNTER 0x08U

static int counter_cmd(se_handle_t *h, uint32_t id, bool create)
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_WRITE, QDSD_SE05X_P1_COUNTER, kSE05x_P2_DEFAULT } };
	uint8_t *p = &h->sess.apdu_buffer[0];
	size_t n = 0U;
	int tlv;

	/* The nano TLVSET_* macros are statements (they end in ';'). */
	tlv = TLVSET_U32("id", &p, &n, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	if (create) {
		tlv = TLVSET_U16("size", &p, &n, kSE05x_TAG_2, 4U);
		if (tlv != 0) {
			return -EINVAL;
		}
	}
	return sm_to_errno(DoAPDUTx(&h->sess, &hdr, h->sess.apdu_buffer, n, 0U));
}

/*
 * RSA-2048 (v3.1). The nano package has no RSA wrappers; these commands use
 * the encodings of NXP's full Plug & Trust middleware (se05x_APDU_impl.h:
 * Se05x_API_WriteRSAKey / ReadRSA / RSASign), built in the session buffer and
 * sent with DoAPDUTx / DoAPDUTxRx like the package's own calls (SCP03 applied).
 */
#define QDSD_SE05X_P1_RSA              0x02U /* kSE05x_P1_RSA */
#define QDSD_SE05X_RSA_FORMAT_CRT      0x00U /* kSE05x_RSAKeyFormat_CRT */
#define QDSD_SE05X_RSA_COMP_MOD        0x00U /* kSE05x_RSAKeyComponent_MOD */
#define QDSD_SE05X_RSA_COMP_PUB_EXP    0x01U /* kSE05x_RSAKeyComponent_PUB_EXP */
#define QDSD_SE05X_RSA_SHA256_PKCS1    0x28U /* kSE05x_RSASignatureAlgo_SHA_256_PKCS1 */

int se_gen_rsa2048(se_handle_t *h, uint32_t id)
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_WRITE,
			      (uint8_t)(QDSD_SE05X_P1_RSA | kSE05x_P1_KEY_PAIR),
			      QDSD_SE05X_RSA_FORMAT_CRT } };
	uint8_t *p = &h->sess.apdu_buffer[0];
	size_t n = 0U;
	bool ex = false;
	int tlv;

	if ((se_exists(h, id, &ex) == 0) && ex) {
		(void)se_delete(h, id);
	}
	/* NULL policy (default access). BRINGUP: restrict to sign + read-public. */
	tlv = TLVSET_U32("id", &p, &n, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	tlv = TLVSET_U16("bits", &p, &n, kSE05x_TAG_2, 2048U);
	if (tlv != 0) {
		return -EINVAL;
	}
	return sm_to_errno(DoAPDUTx(&h->sess, &hdr, h->sess.apdu_buffer, n, 0U));
}

static int read_rsa_comp(se_handle_t *h, uint32_t id, uint8_t comp, uint8_t *out, size_t *len)
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_READ, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT } };
	uint8_t cmd[16];
	uint8_t *p = cmd;
	size_t n = 0U;
	uint8_t rsp[300];
	size_t rsp_len = sizeof(rsp);
	size_t idx = 0U;
	smStatus_t st;
	int tlv;

	tlv = TLVSET_U32("id", &p, &n, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	tlv = TLVSET_U8("comp", &p, &n, kSE05x_TAG_4, comp);
	if (tlv != 0) {
		return -EINVAL;
	}
	st = DoAPDUTxRx(&h->sess, &hdr, cmd, n, rsp, &rsp_len, 1U);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	if (tlvGet_u8buf(rsp, &idx, rsp_len, kSE05x_TAG_1, out, len) != 0) {
		return -EBADMSG;
	}
	return 0;
}

int se_read_rsa2048_mod(se_handle_t *h, uint32_t id, uint8_t mod[256])
{
	uint8_t buf[260];
	size_t len = sizeof(buf);
	const uint8_t *m = buf;
	int rc;

	rc = read_rsa_comp(h, id, QDSD_SE05X_RSA_COMP_PUB_EXP, buf, &len);
	if (rc != 0) {
		return rc;
	}
	/* The token's SPKI assumes e = 65537. */
	while ((len > 1U) && (*m == 0x00U)) {
		m++;
		len--;
	}
	if ((len != 3U) || (m[0] != 0x01U) || (m[1] != 0x00U) || (m[2] != 0x01U)) {
		return -ENOTSUP;
	}
	len = sizeof(buf);
	rc = read_rsa_comp(h, id, QDSD_SE05X_RSA_COMP_MOD, buf, &len);
	if (rc != 0) {
		return rc;
	}
	m = buf;
	if ((len == 257U) && (buf[0] == 0x00U)) {
		m++;
		len--;
	}
	if ((len != 256U) || ((m[0] & 0x80U) == 0U)) {
		return -EBADMSG;
	}
	memcpy(mod, m, 256U);
	return 0;
}

int se_sign_rsa2048_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], uint8_t sig[256])
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_CRYPTO, kSE05x_P1_SIGNATURE, kSE05x_P2_SIGN } };
	uint8_t cmd[64];
	uint8_t *p = cmd;
	size_t n = 0U;
	uint8_t rsp[300];
	size_t rsp_len = sizeof(rsp);
	size_t sig_len = 256U;
	size_t idx = 0U;
	smStatus_t st;
	int tlv;

	tlv = TLVSET_U32("id", &p, &n, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	tlv = TLVSET_U8("algo", &p, &n, kSE05x_TAG_2, QDSD_SE05X_RSA_SHA256_PKCS1);
	if (tlv != 0) {
		return -EINVAL;
	}
	/* BRINGUP: input is the SHA-256 digest, as for ECDSASign (AN12413 RSASign). */
	tlv = TLVSET_u8bufOptional("in", &p, &n, kSE05x_TAG_3, hash, 32U);
	if (tlv != 0) {
		return -EINVAL;
	}
	st = DoAPDUTxRx(&h->sess, &hdr, cmd, n, rsp, &rsp_len, 1U);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	if ((tlvGet_u8buf(rsp, &idx, rsp_len, kSE05x_TAG_1, sig, &sig_len) != 0) ||
	    (sig_len != 256U)) {
		return -EBADMSG;
	}
	return 0;
}

int se_counter_create(se_handle_t *h, uint32_t id)
{
	bool ex = false;
	int rc = se_exists(h, id, &ex);

	if (rc != 0) {
		return rc;
	}
	return ex ? 0 : counter_cmd(h, id, true);
}

int se_counter_inc(se_handle_t *h, uint32_t id)
{
	return counter_cmd(h, id, false);
}

int se_counter_read(se_handle_t *h, uint32_t id, uint32_t *v)
{
	uint8_t buf[8];
	size_t len = sizeof(buf);
	smStatus_t st;
	bool ex = false;
	int rc;

	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	st = Se05x_API_ReadObject(&h->sess, id, 0U, 0U, buf, &len);
	if ((st != SM_OK) || (len != 4U)) {
		return -EIO;
	}
	*v = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
	return 0;
}

int se_binary_read(se_handle_t *h, uint32_t id, uint8_t *buf, size_t cap, size_t *len)
{
	smStatus_t st;
	bool ex = false;
	int rc;

	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	*len = cap;
	st = Se05x_API_ReadObject(&h->sess, id, 0U, 0U, buf, len);
	return sm_to_errno(st);
}

int se_binary_write(se_handle_t *h, uint32_t id, const uint8_t *buf, size_t len)
{
	smStatus_t st;
	bool ex = false;
	int rc;

	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	/* Same create/update pattern as Phase-2 se050_attest.c. One APDU = atomic. */
	if (!ex) {
		st = Se05x_API_WriteBinary(&h->sess, NULL, id, 0U, (uint16_t)len, buf, len);
	} else {
		st = Se05x_API_WriteBinary(&h->sess, NULL, id, 0U, 0U, buf, len);
	}
	return sm_to_errno(st);
}

int se_read_uid(se_handle_t *h, uint8_t uid[18])
{
	size_t len = 18U;
	smStatus_t st = Se05x_API_ReadObject(&h->sess, OID_UNIQUE_ID, 0U, 18U, uid, &len);

	return ((st == SM_OK) && (len == 18U)) ? 0 : -EIO;
}

int se_read_attested(se_handle_t *h, uint32_t id, const uint8_t fresh[16], uint8_t *out,
		     size_t *out_len)
{
	/* The SE050 attestation signs the command and response together. */
	static uint8_t data[160];
	static uint8_t att[512];
	size_t data_len = sizeof(data);
	size_t att_len = sizeof(att);
	size_t need;
	smStatus_t st;

	/* BRINGUP: attested read of an EC key object (Phase 2 used a binary file). */
	st = Se05x_API_ReadObject_W_Attst(&h->sess, id, 0U, 0U, OID_NXP_ATT_KEY,
					  kSE05x_AttestationAlgo_EC_SHA_256, (uint8_t *)fresh,
					  16U, data, &data_len, att, &att_len);
	if (st != SM_OK) {
		return -EIO;
	}
	need = 4U + data_len + 4U + att_len;
	if ((need > *out_len) || (data_len > 0xFFFFU) || (att_len > 0xFFFFU)) {
		return -ENOSPC;
	}
	/* TLV 01 (command APDU) + TLV 02 (response incl. attestation), 0x82 lengths. */
	out[0] = 0x01U;
	out[1] = 0x82U;
	out[2] = (uint8_t)(data_len >> 8);
	out[3] = (uint8_t)data_len;
	memcpy(&out[4], data, data_len);
	out[4U + data_len] = 0x02U;
	out[5U + data_len] = 0x82U;
	out[6U + data_len] = (uint8_t)(att_len >> 8);
	out[7U + data_len] = (uint8_t)att_len;
	memcpy(&out[8U + data_len], att, att_len);
	*out_len = need;
	return 0;
}

/* ── v3.2: binary objects of any size ───────────────────────────────── */

int se_binary_size(se_handle_t *h, uint32_t id, size_t *size)
{
	uint16_t sz = 0U;
	smStatus_t st;
	bool ex = false;
	int rc;

	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	st = Se05x_API_ReadSize(&h->sess, id, &sz);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	*size = sz;
	return 0;
}

int se_binary_read_at(se_handle_t *h, uint32_t id, size_t off, uint8_t *buf, size_t n)
{
	size_t got = n;
	smStatus_t st;

	if ((n == 0U) || (n > SE_BINARY_CHUNK) || (off > 0x7FFFU)) {
		return -EINVAL;
	}
	st = Se05x_API_ReadObject(&h->sess, id, (uint16_t)off, (uint16_t)n, buf, &got);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	return (got == n) ? 0 : -EIO;
}

int se_binary_create(se_handle_t *h, uint32_t id, size_t total, const uint8_t *first, size_t n)
{
	if ((n == 0U) || (n > SE_BINARY_CHUNK) || (n > total) || (total > 0x7FFFU)) {
		return -EINVAL;
	}
	/* TAG_3 (length) creates the file; NULL policy (BRINGUP §3: restrict). */
	return sm_to_errno(Se05x_API_WriteBinary(&h->sess, NULL, id, 0U, (uint16_t)total, first, n));
}

int se_binary_write_at(se_handle_t *h, uint32_t id, size_t off, const uint8_t *buf, size_t n)
{
	if ((n == 0U) || (n > SE_BINARY_CHUNK) || (off > 0x7FFFU)) {
		return -EINVAL;
	}
	/* One WriteBinary APDU: the applet applies it all or nothing (BRINGUP). */
	return sm_to_errno(Se05x_API_WriteBinary(&h->sess, NULL, id, (uint16_t)off, 0U, buf, n));
}

/* ── v3.2: verify, import, curve ────────────────────────────────────── */

int se_verify_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], const uint8_t sig[64])
{
	uint8_t der[72];
	size_t der_len = 0U;
	SE05x_Result_t res = kSE05x_Result_NA;
	smStatus_t st;

	if (der_sig_from_raw(sig, der, sizeof(der), &der_len) != 0) {
		return -EPERM;
	}
	st = Se05x_API_ECDSAVerify(&h->sess, id, kSE05x_ECSignatureAlgo_SHA_256, hash, 32U, der,
				   der_len, &res);
	if (st != SM_OK) {
		return sm_to_errno(st);
	}
	return (res == kSE05x_Result_SUCCESS) ? 0 : -EPERM;
}

int se_write_p256_pair(se_handle_t *h, uint32_t id, const uint8_t d[32], const uint8_t pub[65])
{
	bool ex = false;

	if ((se_exists(h, id, &ex) == 0) && ex) {
		(void)se_delete(h, id);
	}
	/* BRINGUP: private-key write accepted by the SE052F in its FIPS configuration. */
	return sm_to_errno(Se05x_API_WriteECKey(&h->sess, NULL, 0U, id, kSE05x_ECCurve_NIST_P256, d,
						32U, pub, 65U, kSE05x_INS_NA, kSE05x_KeyPart_Pair));
}

/*
 * WriteRSAKey, CRT key pair, one component per APDU (NXP middleware
 * sss_se05x_key_store_set_rsa_key: P first with policy and size, then q, dp,
 * dq, qInv, e, n with key part NA). TAG_3..TAG_7 CRT parts, TAG_8 e, TAG_10 n.
 */
static int rsa_write_comp(se_handle_t *h, uint32_t id, bool first, uint8_t tag,
			  const uint8_t *v, size_t n)
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_WRITE,
			      (uint8_t)(QDSD_SE05X_P1_RSA | (first ? kSE05x_P1_KEY_PAIR : 0U)),
			      QDSD_SE05X_RSA_FORMAT_CRT } };
	uint8_t *p = &h->sess.apdu_buffer[0];
	size_t len = 0U;
	int tlv;

	tlv = TLVSET_U32("id", &p, &len, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	if (first) {
		tlv = TLVSET_U16("bits", &p, &len, kSE05x_TAG_2, 2048U);
		if (tlv != 0) {
			return -EINVAL;
		}
	}
	tlv = TLVSET_u8bufOptional("comp", &p, &len, (SE05x_TAG_t)tag, v, n);
	if (tlv != 0) {
		return -EINVAL;
	}
	return sm_to_errno(DoAPDUTx(&h->sess, &hdr, h->sess.apdu_buffer, len, (len > 255U) ? 1U : 0U));
}

int se_write_rsa2048_crt(se_handle_t *h, uint32_t id, const uint8_t comp[640],
			 const uint8_t mod[256])
{
	static const uint8_t e[3] = { 0x01, 0x00, 0x01 };
	bool ex = false;
	int rc;
	int i;

	if ((se_exists(h, id, &ex) == 0) && ex) {
		(void)se_delete(h, id);
	}
	/* BRINGUP: 7 APDUs; a failure part-way leaves a partial object, deleted below. */
	for (i = 0; i < 5; i++) {
		rc = rsa_write_comp(h, id, i == 0, (uint8_t)(kSE05x_TAG_3 + i), &comp[i * 128], 128U);
		if (rc != 0) {
			goto fail;
		}
	}
	rc = rsa_write_comp(h, id, false, (uint8_t)kSE05x_TAG_8, e, sizeof(e));
	if (rc == 0) {
		rc = rsa_write_comp(h, id, false, (uint8_t)kSE05x_TAG_10, mod, 256U);
	}
	if (rc == 0) {
		return 0;
	}
fail:
	(void)se_delete(h, id);
	return rc;
}

/* NIST P-256 domain parameters (SEC 2), as NXP's se05x_ecc_curves_values.h. */
static const uint8_t k_p256_prime[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};
static const uint8_t k_p256_a[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
};
static const uint8_t k_p256_b[32] = {
	0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
	0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
};
static const uint8_t k_p256_g[65] = {
	0x04,
	0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
	0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
	0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
	0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
};
static const uint8_t k_p256_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

#define QDSD_SE05X_SW_EXISTS 0x6A89U /* "object already exists" (BRINGUP §2 m) */

static int set_p256_params(se_handle_t *h, bool must)
{
	static const struct {
		SE05x_ECCurveParam_t p;
		const uint8_t *v;
		size_t n;
	} k[] = {
		{ kSE05x_ECCurveParam_PARAM_A, k_p256_a, sizeof(k_p256_a) },
		{ kSE05x_ECCurveParam_PARAM_B, k_p256_b, sizeof(k_p256_b) },
		{ kSE05x_ECCurveParam_PARAM_G, k_p256_g, sizeof(k_p256_g) },
		{ kSE05x_ECCurveParam_PARAM_N, k_p256_n, sizeof(k_p256_n) },
		{ kSE05x_ECCurveParam_PARAM_PRIME, k_p256_prime, sizeof(k_p256_prime) },
	};
	size_t i;

	for (i = 0U; i < ARRAY_SIZE(k); i++) {
		smStatus_t st = Se05x_API_SetECCurveParam(&h->sess, kSE05x_ECCurve_NIST_P256, k[i].p,
							  k[i].v, k[i].n);

		if ((st != SM_OK) && must) {
			return -EIO;
		}
	}
	return 0;
}

/*
 * Create the NIST P-256 curve with its parameters. If it already exists, the
 * parameters are applied again and refusals ignored: a curve whose creation
 * was cut off before its parameters were set gets them now, and a complete
 * curve is left as it is. A failed fresh creation deletes the curve so the
 * next attempt starts clean.
 */
int se_create_p256_curve(se_handle_t *h)
{
	smStatus_t st = Se05x_API_CreateECCurve(&h->sess, kSE05x_ECCurve_NIST_P256);

	if ((unsigned int)st == QDSD_SE05X_SW_EXISTS) {
		return set_p256_params(h, false);
	}
	if (st != SM_OK) {
		LOG_ERR("CreateECCurve: 0x%04x", (unsigned int)st);
		return -EIO;
	}
	if (set_p256_params(h, true) != 0) {
		(void)Se05x_API_DeleteECCurve(&h->sess, kSE05x_ECCurve_NIST_P256);
		return -EIO;
	}
	return 0;
}

/* ── v3.2: UserID objects and sessions (FACTORY_RESET) ──────────────── */

#define SE_SESSION_ID_LEN 8U
#define QDSD_SE05X_P2_DELETE_ALL 0x2AU /* kSE05x_P2_DELETE_ALL, full middleware */

int se_userid_write(se_handle_t *h, uint32_t id, const uint8_t *secret, size_t len)
{
	tlvHeader_t hdr = { { 0x80, kSE05x_INS_WRITE | kSE05x_INS_AUTH_OBJECT, kSE05x_P1_UserID,
			      kSE05x_P2_DEFAULT } };
	uint8_t *p = &h->sess.apdu_buffer[0];
	size_t n = 0U;
	bool ex = false;
	int tlv;

	if ((len < 4U) || (len > 16U)) {
		return -EINVAL;
	}
	if ((se_exists(h, id, &ex) == 0) && ex) {
		int rc = se_delete(h, id);

		if ((rc != 0) && (rc != -ENOENT)) {
			return rc;
		}
	}
	/* AN12413 WriteUserID: TAG_1 id, TAG_2 value, TAG_MAX_ATTEMPTS (Phase-2 encoding). */
	tlv = TLVSET_U32("id", &p, &n, kSE05x_TAG_1, id);
	if (tlv != 0) {
		return -EINVAL;
	}
	tlv = TLVSET_u8buf("userId", &p, &n, kSE05x_TAG_2, secret, len);
	if (tlv != 0) {
		return -EINVAL;
	}
	tlv = TLVSET_MaxAttemps("maxAttempt", &p, &n, kSE05x_TAG_MAX_ATTEMPTS, 0U);
	if (tlv != 0) {
		return -EINVAL;
	}
	return sm_to_errno(DoAPDUTx(&h->sess, &hdr, h->sess.apdu_buffer, n, 0U));
}

static uint8_t s_usr_sid[SE_SESSION_ID_LEN];
static bool s_usr_open;
#if defined(WITH_PLATFORM_SCP03)
static uint8_t s_usr_tx[255];
static uint8_t s_usr_rx[255];
#endif

/* ProcessSessionCmd payload (AN12413 §4.5.1.3): session id + wrapped inner APDU. */
static int usr_payload(const tlvHeader_t *inner, const uint8_t *data, size_t dlen, uint8_t *out,
		       size_t *out_len)
{
	size_t i = 0U;
	size_t body = 4U + ((dlen > 0U) ? (1U + dlen) : 0U);

	if ((dlen > 0xFEU) || ((2U + SE_SESSION_ID_LEN + 2U + body) > *out_len) || (body > 0x7FU)) {
		return -EINVAL;
	}
	out[i++] = kSE05x_TAG_SESSION_ID;
	out[i++] = SE_SESSION_ID_LEN;
	memcpy(&out[i], s_usr_sid, SE_SESSION_ID_LEN);
	i += SE_SESSION_ID_LEN;
	out[i++] = kSE05x_TAG_1;
	out[i++] = (uint8_t)body;
	memcpy(&out[i], inner, 4U);
	i += 4U;
	if (dlen > 0U) {
		out[i++] = (uint8_t)dlen;
		memcpy(&out[i], data, dlen);
		i += dlen;
	}
	*out_len = i;
	return 0;
}

/* Send ProcessSessionCmd; SCP03 wrapping exactly as Phase-2 se052f_pnt.c. */
static smStatus_t usr_transmit(se_handle_t *h, const uint8_t *payload, size_t len)
{
	tlvHeader_t proc = { { 0x80, kSE05x_INS_PROCESS, kSE05x_P1_DEFAULT, kSE05x_P2_DEFAULT } };
	size_t rsp_len = sizeof(h->sess.apdu_buffer);
	smStatus_t st;
#if defined(WITH_PLATFORM_SCP03)
	size_t tx_len = sizeof(s_usr_tx);
	size_t rx_len = sizeof(s_usr_rx);

	if (h->sess.scp03_session != 0U) {
		memcpy(s_usr_tx, payload, len);
		st = Se05x_API_SCP03_Encrypt(&h->sess, &proc, s_usr_tx, len, 0U, s_usr_tx, &tx_len);
		if (st != SM_OK) {
			return st;
		}
		st = smComT1oI2C_TransceiveRaw(h->sess.conn_context, s_usr_tx, tx_len, s_usr_rx,
					       &rx_len);
		if (st != SM_OK) {
			return st;
		}
		return Se05x_API_SCP03_Decrypt(&h->sess, len, s_usr_rx, rx_len, h->sess.apdu_buffer,
					       &rsp_len);
	}
#endif
	st = DoAPDUTxRx(&h->sess, &proc, (uint8_t *)payload, len, h->sess.apdu_buffer, &rsp_len, 0U);
	return st;
}

static smStatus_t usr_cmd(se_handle_t *h, uint8_t p2, const uint8_t *data, size_t dlen)
{
	tlvHeader_t inner = { { 0x80, kSE05x_INS_MGMT, kSE05x_P1_DEFAULT, p2 } };
	uint8_t payload[64];
	size_t n = sizeof(payload);

	if (usr_payload(&inner, data, dlen, payload, &n) != 0) {
		return SM_NOT_OK;
	}
	return usr_transmit(h, payload, n);
}

void se_user_session_close(se_handle_t *h)
{
	if (s_usr_open) {
		(void)usr_cmd(h, kSE05x_P2_SESSION_CLOSE, NULL, 0U);
	}
	s_usr_open = false;
	memset(s_usr_sid, 0, sizeof(s_usr_sid));
}

int se_user_session_open(se_handle_t *h, uint32_t id, const uint8_t *secret, size_t len)
{
	uint8_t inner[20];
	size_t sid_len = sizeof(s_usr_sid);
	smStatus_t st;
	bool ex = false;
	int rc;

	if ((len < 4U) || (len > 16U)) {
		return -EINVAL;
	}
	se_user_session_close(h);
	rc = se_exists(h, id, &ex);
	if (rc != 0) {
		return rc;
	}
	if (!ex) {
		return -ENOENT;
	}
	st = Se05x_API_CreateSession(&h->sess, id, s_usr_sid, &sid_len);
	if ((st != SM_OK) || (sid_len != SE_SESSION_ID_LEN)) {
		LOG_WRN("CreateSession(0x%08x): 0x%04x", (unsigned int)id, (unsigned int)st);
		return -EIO;
	}
	s_usr_open = true;
	/* VerifySessionUserID: TAG_1 = UserID value. */
	inner[0] = kSE05x_TAG_1;
	inner[1] = (uint8_t)len;
	memcpy(&inner[2], secret, len);
	st = usr_cmd(h, kSE05x_P2_SESSION_UserID, inner, 2U + len);
	memset(inner, 0, sizeof(inner));
	if (st != SM_OK) {
		LOG_WRN("VerifySessionUserID: 0x%04x", (unsigned int)st);
		se_user_session_close(h);
		return -EACCES;
	}
	return 0;
}

int se_user_delete_all(se_handle_t *h)
{
	smStatus_t st;

	if (!s_usr_open) {
		return -EACCES;
	}
	/* BRINGUP: DeleteAll keeps NXP trust-provisioned objects and SCP03 keys. */
	st = usr_cmd(h, QDSD_SE05X_P2_DELETE_ALL, NULL, 0U);
	s_usr_open = false; /* the applet ends every session after DeleteAll */
	memset(s_usr_sid, 0, sizeof(s_usr_sid));
	return (st == SM_OK) ? 0 : -EIO;
}

#else /* !CONFIG_PLUGANDTRUST */

int se_link_init(void)
{
	return -ENOTSUP;
}

se_handle_t *se_acquire(qdsd_se_t which)
{
	ARG_UNUSED(which);
	return NULL;
}

void se_release(se_handle_t *h, bool ok)
{
	ARG_UNUSED(h);
	ARG_UNUSED(ok);
}

#endif /* CONFIG_PLUGANDTRUST */
