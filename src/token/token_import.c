/**
 * @file token_import.c
 * @brief Institutional certificate import (.pfx): IMPORT_BEGIN and IMPORT_DATA.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Institutional certificate import (.pfx, v3.2) ──────────────────── */

/*
 * IMPORT_BEGIN: the phone has approved importing a certificate (named by its
 * hash) and its key. The token answers with a fresh ephemeral key signed by
 * the device key, so the agent knows it encrypts to this very token.
 */
uint16_t h_import_begin(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	uint32_t cur;
	uint32_t seq;
	uint8_t alg;
	uint8_t slot;
	uint16_t sw;
	int rc;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((a->p1 != 0x00U) || (a->p2 != 0x00U)) {
		return SW_WRONG_P1P2;
	}
	sw = get_signed(a, P_IMPORT_CONSENT, P_IMPORT_CONSENT, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_KEYGEN, &cur) != 0) {
		return SW_INTERNAL;
	}
	seq = stmt_u32(&st, F_KEYGEN_SEQ);
	if (seq != cur + 1U) {
		return SW_STALE;
	}
	alg = stmt_u8(&st, F_KEY_ALG);
	if (!alg_ok(alg) || !method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	rc = pick_slot(&slot);
	if (rc == -ENOSPC) {
		return SW_NO_SPACE;
	}
	if (rc != 0) {
		return SW_INTERNAL;
	}

	import_abort();
	certw_abort();
	if (port_ecdh_begin(g_tk.imp.pub) != 0) {
		return SW_INTERNAL;
	}
	g_tk.imp.active = true;
	g_tk.imp.alg = alg;
	g_tk.imp.seq = seq;
	memcpy(g_tk.imp.cert_hash, st.f[F_CERT_HASH], 32U);

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_IMPORT_OFFER);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_KEYGEN_SEQ, seq);
	tlv_put(&w, F_CERT_HASH, g_tk.imp.cert_hash, 32U);
	tlv_put(&w, F_IMPORT_PUB, g_tk.imp.pub, QDSD_P256_PUB_LEN);
	tlv_put_u8(&w, F_KEY_ALG, alg);
	sw = emit_device_signed(rsp, &w);
	if (sw != SW_OK) {
		import_abort();
	}
	return sw;
}

/* Decrypt the wrapped key in pkg into pt; the key is bound to this import. */
static uint16_t import_unwrap(const tlv_item_t *agent, const tlv_item_t *ct, uint8_t *pt,
			      size_t pt_len)
{
	uint8_t kdf[IMPORT_KDF_LABEL_LEN + 32U + 2U * QDSD_P256_PUB_LEN];
	uint8_t aad[QDSD_DEVICE_ID_LEN + 4U + 32U + 1U];
	uint8_t z[32];
	uint8_t key[32];
	int rc;

	if ((agent->len != QDSD_P256_PUB_LEN) || (port_p256_pubkey_check(agent->val) != 0) ||
	    (ct->len != IMPORT_IV_LEN + pt_len + IMPORT_TAG_LEN)) {
		return SW_WRONG_DATA;
	}
	if (port_ecdh_finish(agent->val, z) != 0) {
		return SW_INTERNAL;
	}
	memcpy(kdf, IMPORT_KDF_LABEL, IMPORT_KDF_LABEL_LEN);
	memcpy(&kdf[IMPORT_KDF_LABEL_LEN], z, 32U);
	memcpy(&kdf[IMPORT_KDF_LABEL_LEN + 32U], g_tk.imp.pub, QDSD_P256_PUB_LEN);
	memcpy(&kdf[IMPORT_KDF_LABEL_LEN + 32U + QDSD_P256_PUB_LEN], agent->val,
	       QDSD_P256_PUB_LEN);
	rc = port_sha256(kdf, sizeof(kdf), key);
	secure_zero(z, sizeof(z));
	secure_zero(kdf, sizeof(kdf));
	if (rc != 0) {
		return SW_INTERNAL;
	}

	memcpy(aad, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_wr_be32(&aad[QDSD_DEVICE_ID_LEN], g_tk.imp.seq);
	memcpy(&aad[QDSD_DEVICE_ID_LEN + 4U], g_tk.imp.cert_hash, 32U);
	aad[sizeof(aad) - 1U] = g_tk.imp.alg;
	rc = port_aes256gcm_decrypt(key, ct->val, aad, sizeof(aad), &ct->val[IMPORT_IV_LEN],
				    pt_len, &ct->val[IMPORT_IV_LEN + pt_len], pt);
	secure_zero(key, sizeof(key));
	if (rc == -EBADMSG) {
		return SW_WRONG_DATA;
	}
	return (rc == 0) ? SW_OK : SW_INTERNAL;
}

/* Install an unwrapped key + certificate into a slot; marks it IMPORTED. */
static uint16_t import_install(const uint8_t *cert, size_t cert_len, const der_key_t *ck,
			       uint8_t *pt, size_t pt_len, tlv_writer_t *rsp)
{
	uint8_t probe[32];
	uint8_t sig[QDSD_DSC_SIG_MAX];
	uint8_t pbuf[sizeof(IMPORT_CHECK_LABEL) - 1U + 4U];
	size_t sig_len = 0U;
	size_t spki_len = 0U;
	slot_meta_t m;
	uint32_t cur;
	uint8_t slot;
	int rc;

	/* A KEYGEN or another import may have run since IMPORT_BEGIN. */
	if (port_counter_read(PORT_CTR_KEYGEN, &cur) != 0) {
		return SW_INTERNAL;
	}
	if (g_tk.imp.seq != cur + 1U) {
		return SW_STALE;
	}
	rc = pick_slot(&slot);
	if (rc == -ENOSPC) {
		return SW_NO_SPACE;
	}
	if (rc != 0) {
		return SW_INTERNAL;
	}
	/* Spend the approval first: it can never install a second key. */
	if (port_counter_inc(PORT_CTR_KEYGEN) != 0) {
		return SW_INTERNAL;
	}
	if ((slot_save_empty(slot) != 0) || (slot_certs_delete(slot) != 0)) {
		return SW_INTERNAL;
	}
	rc = port_dsc_import(slot, g_tk.imp.alg, pt, pt_len, ck->key, ck->key_len);
	secure_zero(pt, pt_len);
	if (rc != 0) {
		(void)port_dsc_delete(slot);
		return (rc == -EINVAL) ? SW_WRONG_DATA : SW_INTERNAL;
	}

	/* Prove the private key belongs to the certificate before using it. */
	memcpy(pbuf, IMPORT_CHECK_LABEL, sizeof(IMPORT_CHECK_LABEL) - 1U);
	tlv_wr_be32(&pbuf[sizeof(IMPORT_CHECK_LABEL) - 1U], g_tk.imp.seq);
	if ((port_sha256(pbuf, sizeof(pbuf), probe) != 0) ||
	    (port_dsc_sign(slot, g_tk.imp.alg, probe, sig, sizeof(sig), &sig_len) != 0)) {
		(void)port_dsc_delete(slot);
		return SW_INTERNAL;
	}
	if (port_sig_verify(g_tk.imp.alg, ck->key, ck->key_len, probe, sig, sig_len) != 0) {
		(void)port_dsc_delete(slot);
		return SW_WRONG_DATA; /* key does not match the certificate */
	}

	memset(&m, 0, sizeof(m));
	m.status = SLOT_CERTIFIED;
	m.alg = g_tk.imp.alg;
	m.origin = ORIGIN_IMPORTED;
	m.csr_mode = CSR_NONE;
	m.seq = g_tk.imp.seq;
	if (slot_cert_store(slot, &m, cert, cert_len) != 0) {
		return SW_INTERNAL;
	}
	if ((g_tk.st.lc == LC_BOUND) && (set_lc(LC_READY) != 0)) {
		return SW_INTERNAL;
	}
	if (der_spki_build(g_tk.imp.alg, ck->key, ck->key_len, g_tk.spki, sizeof(g_tk.spki), &spki_len) !=
	    0) {
		return SW_INTERNAL;
	}
	return emit_key_attest(rsp, g_tk.imp.seq, slot, g_tk.spki, spki_len, ORIGIN_IMPORTED);
}

static uint16_t import_complete(tlv_writer_t *rsp)
{
	tlv_item_t cert;
	tlv_item_t agent;
	tlv_item_t ct;
	der_key_t ck;
	uint8_t pt[IMPORT_PT_RSA];
	uint8_t h[32];
	size_t pt_len;
	size_t n = g_tk.imp.total;
	uint16_t sw;

	if ((tlv_find(g_tk.imp_buf, n, T_IMPORT_CERT, &cert) != 0) ||
	    (tlv_find(g_tk.imp_buf, n, T_AGENT_PUB, &agent) != 0) ||
	    (tlv_find(g_tk.imp_buf, n, T_IMPORT_CT, &ct) != 0) ||
	    (cert.len == 0U) || (cert.len > QDSD_CERT_MAX)) {
		return SW_WRONG_DATA;
	}
	/* The certificate must be the one the Subscriber approved... */
	if ((port_sha256(cert.val, cert.len, h) != 0)) {
		return SW_INTERNAL;
	}
	if (!ct_equal(h, g_tk.imp.cert_hash, sizeof(h))) {
		return SW_WRONG_DATA;
	}
	/* ...and carry a key of the approved type. */
	if ((der_cert_key(cert.val, cert.len, &ck) != 0) || (ck.alg != g_tk.imp.alg)) {
		return SW_WRONG_DATA;
	}
	pt_len = (g_tk.imp.alg == QDSD_ALG_RSA2048) ? IMPORT_PT_RSA : IMPORT_PT_P256;
	sw = import_unwrap(&agent, &ct, pt, pt_len);
	if (sw == SW_OK) {
		sw = import_install(cert.val, cert.len, &ck, pt, pt_len, rsp);
	}
	secure_zero(pt, sizeof(pt));
	return sw;
}

uint16_t h_import_data(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t total;
	tlv_item_t chunk;
	uint16_t sw;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((a->p1 != 0x00U) || (a->p2 > 0x01U)) {
		return SW_WRONG_P1P2;
	}
	if (!g_tk.imp.active) {
		return SW_CONDITIONS;
	}
	if (tlv_find(a->data, a->lc, T_CHUNK, &chunk) != 0) {
		return SW_WRONG_DATA;
	}
	if (a->p2 == 0x00U) {
		uint16_t t;

		if ((tlv_find(a->data, a->lc, T_TOTAL, &total) != 0) || (total.len != 2U)) {
			return SW_WRONG_DATA;
		}
		t = tlv_be16(total.val);
		if ((t == 0U) || (t > QDSD_IMPORT_MAX)) {
			return SW_WRONG_DATA;
		}
		g_tk.imp.total = t;
		g_tk.imp.got = 0U;
	} else if (g_tk.imp.total == 0U) {
		return SW_CONDITIONS;
	}
	if (chunk.len > (size_t)(g_tk.imp.total - g_tk.imp.got)) {
		import_abort();
		return SW_WRONG_DATA;
	}
	memcpy(&g_tk.imp_buf[g_tk.imp.got], chunk.val, chunk.len);
	g_tk.imp.got = (uint16_t)(g_tk.imp.got + chunk.len);
	if (g_tk.imp.got < g_tk.imp.total) {
		return SW_OK;
	}
	/* One attempt per IMPORT_BEGIN: the ephemeral key is used up either way. */
	sw = import_complete(rsp);
	import_abort();
	return sw;
}

