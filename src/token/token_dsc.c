/**
 * @file token_dsc.c
 * @brief DSC keys: KEYGEN, SIGN_CSR, WRITE_CERT, DELETE_KEY, GET_KEY_ATTESTATION (Flow 3).
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── DSC issuance (Flow 3) ──────────────────────────────────────────── */

int pick_slot(uint8_t *out)
{
	slot_meta_t m;
	bool have_pending = false;
	uint32_t best_seq = 0U;
	uint8_t best = 0U;
	uint8_t i;

	for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
		if (slot_load(i, &m) != 0) {
			return -EIO;
		}
		if (m.status == SLOT_EMPTY) {
			*out = i;
			return 0;
		}
		if ((m.status == SLOT_PENDING) && (!have_pending || (m.seq < best_seq))) {
			have_pending = true;
			best_seq = m.seq;
			best = i;
		}
	}
	if (have_pending) {
		*out = best;
		return 0;
	}
	return -ENOSPC;
}

/* KEYGEN / import receipt: the device key vouches for a new slot key. */
uint16_t emit_key_attest(tlv_writer_t *rsp, uint32_t seq, uint8_t slot,
				const uint8_t *spki, size_t spki_len, uint8_t origin)
{
	tlv_writer_t w;

	tlv_put_u8(rsp, F_KEY_SLOT, slot);
	tlv_put(rsp, F_DSC_PUB, spki, spki_len);
	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_KEY_ATTEST);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_KEYGEN_SEQ, seq);
	tlv_put_u8(&w, F_KEY_SLOT, slot);
	tlv_put(&w, F_DSC_PUB, spki, spki_len);
	tlv_put_u8(&w, F_KEY_ORIGIN, origin);
	return emit_device_signed(rsp, &w);
}

uint16_t h_keygen(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t sig;
	stmt_t st;
	slot_meta_t m;
	uint8_t raw[QDSD_RSA_MOD_LEN];
	size_t raw_len = 0U;
	size_t spki_len = 0U;
	uint32_t cur;
	uint32_t seq;
	uint8_t slot;
	uint8_t alg = a->p1;
	uint16_t sw;
	int rc;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if (!alg_ok(alg) || (a->p2 != 0x00U)) {
		return SW_WRONG_P1P2;
	}
	sw = get_signed(a, P_KEYGEN_CONSENT, P_KEYGEN_ENVELOPE, &st, &sig);
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
	if ((st.purpose == P_KEYGEN_CONSENT) && !method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	sw = verify_with((st.purpose == P_KEYGEN_CONSENT) ? PORT_PUBKEY_ACTIVATION :
							    PORT_PUBKEY_CMD,
			 &st, &sig);
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

	/* Spend the authorisation first: no replay even if power fails below. */
	if (port_counter_inc(PORT_CTR_KEYGEN) != 0) {
		return SW_INTERNAL;
	}

	certw_abort();
	/* Outstanding SIGN approvals name the key (keygen_seq), so they stay valid
	 * for the keys they were given for, and cannot apply to this one. */
	if ((slot_save_empty(slot) != 0) || (slot_certs_delete(slot) != 0)) {
		return SW_INTERNAL;
	}
	if ((port_dsc_generate(slot, alg, raw, sizeof(raw), &raw_len) != 0) ||
	    (der_spki_build(alg, raw, raw_len, g_tk.spki, sizeof(g_tk.spki), &spki_len) != 0)) {
		return SW_INTERNAL;
	}
	memset(&m, 0, sizeof(m));
	m.status = SLOT_PENDING;
	m.alg = alg;
	m.origin = ORIGIN_GENERATED;
	m.csr_mode = CSR_NONE;
	m.seq = seq;
	if (slot_save(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	return emit_key_attest(rsp, seq, slot, g_tk.spki, spki_len, ORIGIN_GENERATED);
}

/* Sign with a DSC key and return 72 (raw) and, for P-256, 73 (DER). */
static uint16_t put_dsc_sig(tlv_writer_t *rsp, uint8_t slot, uint8_t alg, const uint8_t h[32])
{
	uint8_t sig[QDSD_DSC_SIG_MAX];
	uint8_t der[72];
	size_t sig_len = 0U;
	size_t der_len = 0U;

	if (port_dsc_sign(slot, alg, h, sig, sizeof(sig), &sig_len) != 0) {
		return SW_INTERNAL;
	}
	tlv_put(rsp, T_DSC_SIG_RAW, sig, sig_len);
	if (alg == QDSD_ALG_P256) {
		if (der_sig_from_raw(sig, der, sizeof(der), &der_len) != 0) {
			return SW_INTERNAL;
		}
		tlv_put(rsp, T_DSC_SIG_DER, der, der_len);
	}
	secure_zero(sig, sizeof(sig));
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

/*
 * Proof-of-possession signature for a key that has no certificate yet.
 *   P2 = 00: full CertificationRequestInfo; the token checks the key inside it.
 *            Repeatable (a CA retry can resubmit).
 *   P2 = 01: bare SHA-256 digest (Windows CNG NCryptSignHash, PKCS#11 CKM_ECDSA).
 *            The token cannot see what it signs, so this is the key's ONLY
 *            signature before certification: if a compromised PC spends it on
 *            anything other than the real request, no valid request can be made
 *            for the key, the CA never certifies it, and the stray signature
 *            never chains to a DSC.
 */
uint16_t h_sign_csr(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t in;
	slot_meta_t m;
	der_key_t ks;
	der_key_t kc;
	uint8_t h[32];
	size_t spki_len = 0U;
	uint8_t slot = a->p1;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((slot >= QDSD_DSC_SLOTS) || (a->p2 > 0x01U)) {
		return SW_WRONG_P1P2;
	}
	if (slot_load(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	if ((m.status != SLOT_PENDING) || (m.csr_mode == CSR_DIGEST)) {
		return SW_SLOT_STATE;
	}

	if (a->p2 == 0x00U) {
		if (tlv_find(a->data, a->lc, T_CRI, &in) != 0) {
			return SW_WRONG_DATA;
		}
		if ((slot_spki(slot, m.alg, g_tk.spki, sizeof(g_tk.spki), &spki_len) != 0) ||
		    (der_spki_key(g_tk.spki, spki_len, &ks) != 0)) {
			return SW_INTERNAL;
		}
		/* Only a CSR body carrying exactly this slot's key can be signed. */
		if ((der_cri_key(in.val, in.len, &kc) != 0) || !der_key_equal(&ks, &kc)) {
			return SW_WRONG_DATA;
		}
		if (port_sha256(in.val, in.len, h) != 0) {
			return SW_INTERNAL;
		}
		if (m.csr_mode != CSR_FULL) {
			m.csr_mode = CSR_FULL;
			if (slot_save(slot, &m) != 0) {
				return SW_INTERNAL;
			}
		}
	} else {
		if (m.csr_mode != CSR_NONE) {
			return SW_SLOT_STATE; /* key already signed something */
		}
		if ((tlv_find(a->data, a->lc, T_CSR_DIGEST, &in) != 0) || (in.len != 32U)) {
			return SW_WRONG_DATA;
		}
		memcpy(h, in.val, sizeof(h));
		/* Spend the one-shot first, so a power cut can't allow a second. */
		m.csr_mode = CSR_DIGEST;
		if (slot_save(slot, &m) != 0) {
			return SW_INTERNAL;
		}
	}
	return put_dsc_sig(rsp, slot, m.alg, h);
}

uint16_t h_write_cert(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t total;
	tlv_item_t chunk;
	slot_meta_t m;
	der_key_t ks;
	der_key_t kc;
	size_t spki_len = 0U;
	uint8_t slot = a->p1;

	(void)rsp;
	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((slot >= QDSD_DSC_SLOTS) || (a->p2 > 0x01U)) {
		return SW_WRONG_P1P2;
	}
	if (slot_load(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	if (m.status == SLOT_EMPTY) {
		return SW_SLOT_STATE;
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
		if ((t == 0U) || (t > QDSD_CERT_MAX)) {
			return SW_WRONG_DATA;
		}
		g_tk.certw.active = true;
		g_tk.certw.slot = slot;
		g_tk.certw.total = t;
		g_tk.certw.got = 0U;
	} else if (!g_tk.certw.active || (g_tk.certw.slot != slot)) {
		return SW_CONDITIONS;
	}

	if (chunk.len > (size_t)(g_tk.certw.total - g_tk.certw.got)) {
		certw_abort();
		return SW_WRONG_DATA;
	}
	memcpy(&g_tk.certw_buf[g_tk.certw.got], chunk.val, chunk.len);
	g_tk.certw.got = (uint16_t)(g_tk.certw.got + chunk.len);
	if (g_tk.certw.got < g_tk.certw.total) {
		return SW_OK; /* more chunks expected */
	}

	/* Complete: accept only a certificate for exactly this slot's key. */
	if ((slot_spki(slot, m.alg, g_tk.spki, sizeof(g_tk.spki), &spki_len) != 0) ||
	    (der_spki_key(g_tk.spki, spki_len, &ks) != 0)) {
		certw_abort();
		return SW_INTERNAL;
	}
	if ((der_cert_key(g_tk.certw_buf, g_tk.certw.total, &kc) != 0) || !der_key_equal(&ks, &kc)) {
		certw_abort();
		return SW_WRONG_DATA;
	}
	if (slot_cert_store(slot, &m, g_tk.certw_buf, g_tk.certw.total) != 0) {
		certw_abort();
		return SW_INTERNAL;
	}
	certw_abort();
	if ((g_tk.st.lc == LC_BOUND) && (set_lc(LC_READY) != 0)) {
		return SW_INTERNAL;
	}
	return SW_OK;
}

/* ── Certificate lifecycle (v3.2) ───────────────────────────────────── */

/*
 * Remove a DSC: key, certificate and slot record, approved on the phone.
 * The approval names the slot and the keygen number of the key in it, so it
 * can never apply to a later key in the same slot. Revocation itself is done
 * at the CA; this erases the token's copy.
 */
uint16_t h_delete_key(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	slot_meta_t m;
	uint8_t slot = a->p1;
	uint16_t sw;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((slot >= QDSD_DSC_SLOTS) || (a->p2 != 0x00U)) {
		return SW_WRONG_P1P2;
	}
	sw = get_signed(a, P_DELETE_KEY, P_DELETE_KEY, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if ((stmt_u8(&st, F_KEY_SLOT) != slot) || !method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	if (slot_load(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	if (m.status == SLOT_EMPTY) {
		return SW_SLOT_STATE;
	}
	if (stmt_u32(&st, F_KEYGEN_SEQ) != m.seq) {
		return SW_STALE; /* approval was for an earlier key in this slot */
	}
	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}

	if (g_tk.certw.active && (g_tk.certw.slot == slot)) {
		certw_abort();
	}
	/* Outstanding nonces are kept: SIGN approvals name the key (keygen_seq),
	 * so none can apply to a key later put into this slot (§4.8). */
	if (slot_erase(slot) != 0) {
		return SW_INTERNAL;
	}
	if ((g_tk.st.lc == LC_READY) && !any_certified() && (set_lc(LC_BOUND) != 0)) {
		return SW_INTERNAL;
	}

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_KEY_DELETED);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_KEYGEN_SEQ, m.seq);
	tlv_put_u8(&w, F_KEY_SLOT, slot);
	return emit_device_signed(rsp, &w);
}

/*
 * DSC key attestation, separate from device attestation (ATTEST):
 *   - KEY_STATUS statement signed by the device key (SE050): slot, key,
 *     origin, certificate hash, challenge;
 *   - the SE052F's own NXP attestation of the key object, which also states
 *     whether the element generated the key or it was written from outside.
 */
uint16_t h_get_key_attestation(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t ch;
	slot_meta_t m;
	uint8_t uid[QDSD_CHIP_UID_LEN];
	uint8_t zero[32];
	size_t spki_len = 0U;
	size_t att_len = sizeof(g_tk.read_buf);
	uint8_t slot = a->p1;
	uint16_t sw;
	int rc;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((slot >= QDSD_DSC_SLOTS) || (a->p2 != 0x00U)) {
		return SW_WRONG_P1P2;
	}
	if ((tlv_find(a->data, a->lc, F_CHALLENGE, &ch) != 0) || (ch.len < 16U) ||
	    (ch.len > 32U)) {
		return SW_WRONG_DATA;
	}
	if (slot_load(slot, &m) != 0) {
		return SW_INTERNAL;
	}
	if (m.status == SLOT_EMPTY) {
		return SW_SLOT_STATE;
	}
	if (slot_spki(slot, m.alg, g_tk.spki, sizeof(g_tk.spki), &spki_len) != 0) {
		return SW_INTERNAL;
	}
	memset(zero, 0, sizeof(zero));

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_KEY_STATUS);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put(&w, F_CHALLENGE, ch.val, ch.len);
	tlv_put_u32(&w, F_KEYGEN_SEQ, m.seq);
	tlv_put_u8(&w, F_KEY_SLOT, slot);
	tlv_put(&w, F_DSC_PUB, g_tk.spki, spki_len);
	tlv_put_u8(&w, F_STATUS, m.status);
	tlv_put(&w, F_CERT_HASH, (m.cert_len > 0U) ? m.cert_hash : zero, 32U);
	tlv_put_u8(&w, F_KEY_ORIGIN, m.origin);
	sw = emit_device_signed(rsp, &w);
	if (sw != SW_OK) {
		return sw;
	}

	if (port_dsc_chip_uid(uid) != 0) {
		return SW_INTERNAL;
	}
	tlv_put(rsp, T_DSC_UID, uid, sizeof(uid));
	rc = port_dsc_vendor_attest(slot, m.alg, ch.val, g_tk.read_buf, &att_len);
	if (rc == 0) {
		tlv_put(rsp, T_KEY_VENDOR_ATT, g_tk.read_buf, att_len);
	} else if (rc != -ENOTSUP) {
		return SW_INTERNAL;
	}
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

