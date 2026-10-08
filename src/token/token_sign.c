/**
 * @file token_sign.c
 * @brief Signing (Flow 4): GET_SESSION_NONCE and SIGN with persistent receipts.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Signing (Flow 4) ───────────────────────────────────────────────── */

uint16_t h_get_nonce(const apdu_t *a, tlv_writer_t *rsp)
{
	size_t i;
	size_t pick = 0U;
	uint32_t oldest = UINT32_MAX;

	(void)a;
	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	/* Free slot, else replace the oldest outstanding nonce. */
	for (i = 0U; i < QDSD_NONCE_SLOTS; i++) {
		if (!g_tk.nonce[i].valid) {
			pick = i;
			break;
		}
		if (g_tk.nonce[i].order < oldest) {
			oldest = g_tk.nonce[i].order;
			pick = i;
		}
	}
	nonce_drop_at(pick, (g_tk.nonce[pick].valid &&
			     ((port_uptime_ms() - g_tk.nonce[pick].issued_ms) > QDSD_NONCE_TTL_MS)) ?
				    NONCE_WHY_EXPIRED : NONCE_WHY_REPLACED);
	if (port_random(g_tk.nonce[pick].v, sizeof(g_tk.nonce[pick].v)) != 0) {
		nonce_drop_at(pick, NONCE_WHY_DISCARDED);
		return SW_INTERNAL;
	}
	g_tk.nonce[pick].valid = true;
	g_tk.nonce[pick].issued_ms = port_uptime_ms();
	g_tk.nonce[pick].order = ++g_tk.nonce_order;
	tlv_put(rsp, F_NONCE, g_tk.nonce[pick].v, sizeof(g_tk.nonce[pick].v));
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

static bool field_eq(const stmt_t *st, uint8_t tag, const tlv_item_t *plain, size_t len)
{
	return (plain->len == len) && (st->flen[tag] == len) && ct_equal(st->f[tag], plain->val, len);
}

static void build_sign_receipt(tlv_writer_t *w, const uint8_t *nonce, const uint8_t *htbs,
			       const uint8_t *hctx, const uint8_t *rid, uint32_t ctr,
			       uint8_t slot, const slot_meta_t *m, const uint8_t *sig_hash,
			       uint8_t status)
{
	stmt_begin(w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_SIGN_RECEIPT);
	tlv_put(w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put(w, F_NONCE, nonce, 32U);
	tlv_put(w, F_H_TBS, htbs, 32U);
	tlv_put(w, F_H_CTX, hctx, 32U);
	tlv_put(w, F_REQUEST_ID, rid, 16U);
	tlv_put_u32(w, F_KEYGEN_SEQ, m->seq);
	tlv_put_u32(w, F_SIGN_COUNTER, ctr);
	tlv_put_u8(w, F_KEY_SLOT, slot);
	tlv_put(w, F_SIG_HASH, sig_hash, 32U);
	tlv_put_u8(w, F_STATUS, status);
	tlv_put_u8(w, F_KEY_ORIGIN, m->origin);
}

/*
 * SIGN with a persistent receipt (v3.2):
 *   1. count the signature (sign counter + 1);
 *   2. save a pending receipt (status 02 "interrupted") in the SE050 ring;
 *   3. make the DSC signature in the SE052F;
 *   4. save the final receipt and the signature itself;
 *   5. only then release the signature.
 * A power cut after 2 leaves a pending entry that the next boot signs as
 * "interrupted"; one after 4 leaves the final receipt and the signature, so
 * the middleware can fetch both with GET_RECEIPT.
 */
uint16_t h_sign(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	tlv_item_t htbs;
	tlv_item_t hctx;
	tlv_item_t rid;
	tlv_item_t kslot;
	stmt_t st;
	slot_meta_t m;
	uint8_t nonce[32];
	uint8_t dsc_sig[QDSD_DSC_SIG_MAX];
	uint8_t devsig[QDSD_P256_SIG_LEN];
	size_t dsc_sig_len = 0U;
	uint8_t sig_hash[32];
	uint8_t status;
	uint8_t slot;
	uint32_t ctr;
	uint16_t sw;
	int ni;

	if (g_tk.st.lc != LC_READY) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, F_H_TBS, &htbs) != 0) ||
	    (tlv_find(a->data, a->lc, F_H_CTX, &hctx) != 0) ||
	    (tlv_find(a->data, a->lc, F_REQUEST_ID, &rid) != 0) ||
	    (tlv_find(a->data, a->lc, F_KEY_SLOT, &kslot) != 0) || (kslot.len != 1U)) {
		return SW_WRONG_DATA;
	}
	sw = get_signed(a, P_SIGN_ASSERTION, P_SIGN_ASSERTION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}

	/* The assertion must cover an outstanding nonce and exactly these values. */
	ni = nonce_find(st.f[F_NONCE]);
	if (ni < 0) {
		return nonce_stale(rsp, st.f[F_NONCE], 0U);
	}
	if (!field_eq(&st, F_H_TBS, &htbs, 32U) || !field_eq(&st, F_H_CTX, &hctx, 32U) ||
	    !field_eq(&st, F_REQUEST_ID, &rid, 16U) || !field_eq(&st, F_KEY_SLOT, &kslot, 1U) ||
	    !method_ok(&st)) {
		return SW_WRONG_DATA;
	}

	slot = kslot.val[0];
	if (slot >= QDSD_DSC_SLOTS) {
		return SW_WRONG_DATA;
	}
	if (slot_load(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	if (m.status != SLOT_CERTIFIED) {
		return SW_SLOT_STATE;
	}
	/*
	 * The approval names the key, not only the slot: a key deleted, and a new
	 * one put in the same slot, cannot be used with an earlier approval. The
	 * nonce stays usable for a fresh approval.
	 */
	if (stmt_u32(&st, F_KEYGEN_SEQ) != m.seq) {
		return nonce_stale(rsp, st.f[F_NONCE], NONCE_WHY_KEY_CHANGED);
	}

	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		if (sw == SW_SECURITY) {
			nonce_fail(ni);
		}
		return sw;
	}

	/* Consume the nonce, then count the signature before making it. */
	memcpy(nonce, g_tk.nonce[ni].v, sizeof(nonce));
	nonce_drop_at((size_t)ni, NONCE_WHY_USED);
	if ((port_counter_inc(PORT_CTR_SIGN) != 0) ||
	    (port_counter_read(PORT_CTR_SIGN, &ctr) != 0)) {
		return SW_INTERNAL;
	}

	memset(sig_hash, 0, sizeof(sig_hash));
	build_sign_receipt(&w, nonce, htbs.val, hctx.val, rid.val, ctr, slot, &m, sig_hash,
			   RCPT_STATUS_INTERRUPTED);
	if (!tlv_ok(&w) || (rcpt_put_head(ctr, RCPT_PENDING, w.buf, w.len, 0U) != 0)) {
		return SW_INTERNAL; /* nothing signed; the counter gap is visible */
	}

	port_event(PORT_EVT_SIGNING_START, slot);
	if (port_dsc_sign(slot, m.alg, htbs.val, dsc_sig, sizeof(dsc_sig), &dsc_sig_len) == 0) {
		status = RCPT_STATUS_OK;
		if (port_sha256(dsc_sig, dsc_sig_len, sig_hash) != 0) {
			secure_zero(dsc_sig, sizeof(dsc_sig));
			return SW_INTERNAL;
		}
	} else {
		status = RCPT_STATUS_SE_FAILED;
		dsc_sig_len = 0U;
	}
	port_event(PORT_EVT_SIGNING_DONE, status);

	build_sign_receipt(&w, nonce, htbs.val, hctx.val, rid.val, ctr, slot, &m, sig_hash,
			   status);
	if ((device_sign(&w, devsig) != 0) ||
	    (rcpt_put_final(ctr, w.buf, w.len, devsig, dsc_sig, dsc_sig_len) != 0)) {
		/* Not saved, not released: the entry stays pending ("interrupted"). */
		secure_zero(dsc_sig, sizeof(dsc_sig));
		return SW_INTERNAL;
	}

	if (status == RCPT_STATUS_OK) {
		tlv_put(rsp, T_DSC_SIG_RAW, dsc_sig, dsc_sig_len);
	}
	secure_zero(dsc_sig, sizeof(dsc_sig));
	tlv_put(rsp, T_STMT, w.buf, w.len);
	tlv_put(rsp, T_STMT_SIG, devsig, sizeof(devsig));
	if (!tlv_ok(rsp)) {
		return SW_INTERNAL;
	}
	if (status != RCPT_STATUS_OK) {
		g_tk.keep_data_on_error = true;
		return SW_INTERNAL;
	}
	return SW_OK;
}

