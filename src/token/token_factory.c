/**
 * @file token_factory.c
 * @brief Factory flow: FACTORY_INIT, PERSONALISE, CLOSE and FACTORY_WIPE.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Factory (Flow 1) ───────────────────────────────────────────────── */

uint16_t h_factory_init(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t ch;
	uint8_t uid[QDSD_CHIP_UID_LEN];
	uint8_t pub[QDSD_P256_PUB_LEN];
	uint8_t idsrc[DEVID_PREFIX_LEN + QDSD_CHIP_UID_LEN + QDSD_P256_PUB_LEN];
	uint8_t h[32];
	size_t att_len = sizeof(g_tk.read_buf);

	if (g_tk.st.lc != LC_MANUFACTURING) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, F_CHALLENGE, &ch) != 0) || (ch.len < 16U) ||
	    (ch.len > 32U)) {
		return SW_WRONG_DATA;
	}
	if ((port_se_prepare(PORT_SE_DEV) != 0) || (port_se_prepare(PORT_SE_DSC) != 0) ||
	    (port_devkey_ensure() != 0) || (port_devkey_pubkey(pub) != 0) ||
	    (port_chip_uid(uid) != 0)) {
		return SW_INTERNAL;
	}

	/*
	 * v3.2: the device id also covers the device key. A token that is wiped
	 * and re-made gets a new key, so a new id, so nothing signed for its
	 * previous life (BIND, RESET, WIPE envelopes) can ever apply again.
	 */
	memcpy(idsrc, DEVID_PREFIX, DEVID_PREFIX_LEN);
	memcpy(&idsrc[DEVID_PREFIX_LEN], uid, sizeof(uid));
	memcpy(&idsrc[DEVID_PREFIX_LEN + sizeof(uid)], pub, sizeof(pub));
	if (port_sha256(idsrc, sizeof(idsrc), h) != 0) {
		return SW_INTERNAL;
	}
	if (!g_tk.st.has_device_id || (memcmp(g_tk.st.device_id, h, QDSD_DEVICE_ID_LEN) != 0)) {
		g_tk.st.has_device_id = true;
		memcpy(g_tk.st.device_id, h, QDSD_DEVICE_ID_LEN);
		if (state_save(&g_tk.st) != 0) {
			return SW_INTERNAL;
		}
	}

	if (port_devkey_vendor_attest(ch.val, ch.len, g_tk.read_buf, &att_len) != 0) {
		return SW_INTERNAL;
	}

	tlv_put(rsp, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put(rsp, F_DEVICE_PUB, pub, sizeof(pub));
	tlv_put(rsp, T_CHIP_UID, uid, sizeof(uid));
	tlv_put(rsp, T_VENDOR_ATT, g_tk.read_buf, att_len);
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

uint16_t h_factory_personalise(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t cert;
	tlv_item_t cmd;
	tlv_item_t wdev;
	tlv_item_t wdsc;
	uint8_t devpub[QDSD_P256_PUB_LEN];
	uint8_t certpub[QDSD_P256_PUB_LEN];

	(void)rsp;
	if ((g_tk.st.lc != LC_MANUFACTURING) || !g_tk.st.has_device_id) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, T_DEVICE_CERT, &cert) != 0) ||
	    (tlv_find(a->data, a->lc, T_CMD_PUB, &cmd) != 0) ||
	    (tlv_find(a->data, a->lc, T_WIPE_SECRET_DEV, &wdev) != 0) ||
	    (tlv_find(a->data, a->lc, T_WIPE_SECRET_DSC, &wdsc) != 0) ||
	    (cert.len == 0U) || (cert.len > QDSD_CERT_MAX) ||
	    (cmd.len != QDSD_P256_PUB_LEN) || (wdev.len != QDSD_WIPE_SECRET_LEN) ||
	    (wdsc.len != QDSD_WIPE_SECRET_LEN)) {
		return SW_WRONG_DATA;
	}
	if (port_p256_pubkey_check(cmd.val) != 0) {
		return SW_WRONG_DATA;
	}
	if (port_devkey_pubkey(devpub) != 0) {
		return SW_INTERNAL;
	}
	if ((der_cert_p256_pubkey(cert.val, cert.len, certpub) != 0) ||
	    !ct_equal(certpub, devpub, sizeof(devpub))) {
		return SW_WRONG_DATA;
	}
	if ((port_obj_write(PORT_OBJ_DEVICE_CERT, 0U, cert.val, cert.len) != 0) ||
	    (port_pubkey_write(PORT_PUBKEY_CMD, cmd.val) != 0) ||
	    (port_wipe_auth_set(PORT_SE_DEV, wdev.val) != 0) ||
	    (port_wipe_auth_set(PORT_SE_DSC, wdsc.val) != 0)) {
		return SW_INTERNAL;
	}
	return SW_OK;
}

uint16_t h_factory_close(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	uint8_t cmd_hash[32];
	uint8_t cert_hash[32];
	uint8_t pub[QDSD_P256_PUB_LEN];
	uint32_t b;
	uint32_t k;
	uint32_t s;
	size_t clen = 0U;
	port_counter_t c;

	(void)a;
	if ((g_tk.st.lc != LC_MANUFACTURING) || !g_tk.st.has_device_id) {
		return SW_CONDITIONS;
	}
	if ((port_pubkey_read(PORT_PUBKEY_CMD, pub) != 0) ||
	    (port_obj_read(PORT_OBJ_DEVICE_CERT, 0U, g_tk.read_buf, sizeof(g_tk.read_buf), &clen) != 0)) {
		return SW_CONDITIONS;
	}
	if ((port_sha256(pub, sizeof(pub), cmd_hash) != 0) ||
	    (port_sha256(g_tk.read_buf, clen, cert_hash) != 0)) {
		return SW_INTERNAL;
	}
	for (c = PORT_CTR_BINDING; c < PORT_CTR_COUNT; c++) {
		if (port_counter_ensure(c) != 0) {
			return SW_INTERNAL;
		}
	}
	if ((rcpt_ensure() != 0) || (read_counters(&b, &k, &s) != 0)) {
		return SW_INTERNAL;
	}

	g_tk.st.policy_flags = 0U;
	if (set_lc(LC_UNASSIGNED) != 0) {
		return SW_INTERNAL;
	}

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_FACTORY_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_BINDING_NO, b);
	tlv_put_u8(&w, F_STATE, g_tk.st.lc);
	tlv_put_u32(&w, F_SIGN_COUNTER, s);
	tlv_put_u32(&w, F_KEYGEN_COUNTER, k);
	tlv_put(&w, F_CMD_KEY_HASH, cmd_hash, 32U);
	tlv_put(&w, F_DEVICE_CERT_HASH, cert_hash, 32U);
	return emit_device_signed(rsp, &w);
}

/*
 * Factory reset of both secure elements (v3.2). The element itself enforces
 * the gate: DeleteAll only runs in a session opened with the FACTORY_RESET
 * secret, which only DTI holds (per-device, set at FACTORY_PERSONALISE).
 * On a paired or unassigned token a DTI command-key WIPE statement is
 * required as well, so a leaked factory secret alone cannot erase a
 * Subscriber's token. The secrets alone are enough only in MANUFACTURING,
 * to finish a wipe cut off by power loss, or when the lifecycle record is
 * corrupt or missing (no statement could be checked): the repair paths.
 */
static void forget_legacy_nvs(void)
{
	uint8_t i;

	(void)port_nvs_delete(NVS_DEVICE_CERT);
	for (i = 0U; i < NVS_LEGACY_SLOTS; i++) {
		(void)port_nvs_delete(NVS_SLOT_META(i));
		(void)port_nvs_delete(NVS_SLOT_CERT(i));
	}
}

static uint16_t wipe_secret_sw(int rc)
{
	if (rc == -EACCES) {
		return SW_SECURITY;
	}
	return (rc == -ENOENT) ? SW_CONDITIONS : SW_INTERNAL;
}

uint16_t h_factory_wipe(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t wdev;
	tlv_item_t wdsc;
	tlv_item_t sig;
	stmt_t st;
	uint32_t cur;
	bool need_stmt;
	bool skip_dsc;
	uint16_t sw;
	int rc_dsc;
	int rc;

	if ((tlv_find(a->data, a->lc, T_WIPE_SECRET_DEV, &wdev) != 0) ||
	    (tlv_find(a->data, a->lc, T_WIPE_SECRET_DSC, &wdsc) != 0) ||
	    (wdev.len != QDSD_WIPE_SECRET_LEN) || (wdsc.len != QDSD_WIPE_SECRET_LEN)) {
		return SW_WRONG_DATA;
	}
	/*
	 * DTI's WIPE statement can only be skipped when it cannot exist or is not
	 * needed: a wipe already under way, a lifecycle record that is corrupt or
	 * gone, or a token still in MANUFACTURING. Any other FAULT (for example a
	 * passing secure-element error at boot) still needs it.
	 */
	need_stmt = !g_tk.wipe_pending && !g_tk.state_lost && (g_tk.st.lc != LC_MANUFACTURING);
	if (need_stmt) {
		sw = get_signed(a, P_WIPE, P_WIPE, &st, &sig);
		if (sw != SW_OK) {
			return sw;
		}
		if (port_counter_read(PORT_CTR_BINDING, &cur) != 0) {
			return SW_INTERNAL;
		}
		if (stmt_u32(&st, F_BINDING_NO) != cur) {
			return SW_STALE;
		}
		sw = verify_with(PORT_PUBKEY_CMD, &st, &sig);
		if (sw != SW_OK) {
			return sw;
		}
	}

	/*
	 * Both secrets must be right before anything is touched. The SE052F is
	 * wiped first, so when finishing a cut-off wipe it may already be empty
	 * (no FACTORY_RESET object left); the SE050 never is, because it still
	 * holds the journal that says a wipe is pending.
	 */
	rc_dsc = port_wipe_auth_check(PORT_SE_DSC, wdsc.val);
	rc = port_wipe_auth_check(PORT_SE_DEV, wdev.val);
	skip_dsc = g_tk.wipe_pending && (rc_dsc == -ENOENT);
	if (rc != 0) {
		return wipe_secret_sw(rc);
	}
	if ((rc_dsc != 0) && !skip_dsc) {
		return wipe_secret_sw(rc_dsc);
	}

	/* Journal: if power fails part-way, the token boots FAULT and accepts
	 * the secrets alone to finish. Best effort when the record is corrupt. */
	nonce_drop_all(NONCE_WHY_DISCARDED);
	certw_abort();
	import_abort();
	if (!g_tk.wipe_pending) {
		g_tk.st.j_op = J_WIPE;
		g_tk.st.j_target = 0U;
		g_tk.st.j_next_lc = LC_MANUFACTURING;
		if ((state_save(&g_tk.st) != 0) && !g_tk.fault) {
			g_tk.st.j_op = J_NONE;
			return SW_INTERNAL;
		}
	}
	g_tk.wipe_pending = true;
	g_tk.fault = true;

	forget_legacy_nvs();
	/* DSC element first: the SE050 still holds the journal until the end. */
	rc = skip_dsc ? 0 : port_se_wipe(PORT_SE_DSC, wdsc.val);
	if (rc == 0) {
		rc = port_se_wipe(PORT_SE_DEV, wdev.val);
	}
	if (rc != 0) {
		port_event(PORT_EVT_STATE_CHANGED, LC_FAULT);
		return SW_INTERNAL;
	}

	/* Both elements are empty: a fresh MANUFACTURING token. */
	state_defaults(&g_tk.st);
	g_tk.fault = false;
	g_tk.wipe_pending = false;
	g_tk.state_lost = false;
	g_tk.sess.started = false;
	g_tk.sess.card_auth = false;
	g_tk.sess.logged_in = false;
	new_epoch(); /* the session is over: tell the agent */
	g_tk.sess.pairing = false;
	port_event(PORT_EVT_STATE_CHANGED, g_tk.st.lc);
	tlv_put_u8(rsp, F_STATE, g_tk.st.lc);
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

