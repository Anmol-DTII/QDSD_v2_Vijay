/**
 * @file token_pairing.c
 * @brief Pairing, phone change, lost phone, login and settings (Flows 2, 2b, 5).
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Pairing (Flow 2) ───────────────────────────────────────────────── */

uint16_t h_attest(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t ch;
	uint8_t cmd_hash[32];
	uint8_t act_hash[32];
	uint8_t fw[4];
	uint32_t b;
	uint32_t k;
	uint32_t s;
	uint32_t pn;

	if (g_tk.st.lc == LC_MANUFACTURING) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, F_CHALLENGE, &ch) != 0) || (ch.len < 16U) ||
	    (ch.len > 32U)) {
		return SW_WRONG_DATA;
	}
	if ((read_counters(&b, &k, &s) != 0) || (port_counter_read(PORT_CTR_POLICY, &pn) != 0) ||
	    (pubkey_hash(PORT_PUBKEY_CMD, cmd_hash) != 0) ||
	    (pubkey_hash(PORT_PUBKEY_ACTIVATION, act_hash) != 0)) {
		return SW_INTERNAL;
	}
	fw_version(fw);

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_ATTEST);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_BINDING_NO, b);
	tlv_put_u8(&w, F_STATE, g_tk.st.lc);
	tlv_put(&w, F_CHALLENGE, ch.val, ch.len);
	tlv_put_u32(&w, F_SIGN_COUNTER, s);
	tlv_put(&w, F_FW_VERSION, fw, sizeof(fw));
	tlv_put_u32(&w, F_KEYGEN_COUNTER, k);
	tlv_put(&w, F_CMD_KEY_HASH, cmd_hash, 32U);
	tlv_put(&w, F_ACT_KEY_HASH, act_hash, 32U);
	tlv_put_u32(&w, F_POLICY_NO, pn);
	tlv_put_u8(&w, F_POLICY_FLAGS, g_tk.st.policy_flags);
	return emit_device_signed(rsp, &w);
}

uint16_t h_bind(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	uint8_t act_hash[32];
	uint32_t pn;
	uint32_t cur;
	uint32_t want;
	uint16_t sw;

	if (g_tk.st.lc != LC_UNASSIGNED) {
		return SW_CONDITIONS;
	}
	sw = get_signed(a, P_BIND, P_BIND, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_BINDING, &cur) != 0) {
		return SW_INTERNAL;
	}
	want = stmt_u32(&st, F_BINDING_NO);
	if (want != cur + 1U) {
		return SW_STALE;
	}
	if ((port_p256_pubkey_check(st.f[F_ACTIVATION_PUB]) != 0) ||
	    !policy_flags_ok(stmt_u8(&st, F_POLICY_FLAGS))) {
		return SW_WRONG_DATA;
	}
	sw = verify_with(PORT_PUBKEY_CMD, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_POLICY, &pn) != 0) {
		return SW_INTERNAL;
	}

	sw = journal_run(J_BIND, want, st.f[F_ACTIVATION_PUB], stmt_u8(&st, F_POLICY_FLAGS),
			 LC_BOUND);
	if (sw != SW_OK) {
		return sw;
	}
	/* The session opened by pairing lasts until the token is unplugged. */
	g_tk.sess.pairing = true;
	g_tk.sess.card_auth = true;
	session_recompute();

	if (port_sha256(st.f[F_ACTIVATION_PUB], QDSD_P256_PUB_LEN, act_hash) != 0) {
		return SW_INTERNAL;
	}
	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_BIND_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_BINDING_NO, want);
	tlv_put_u8(&w, F_STATE, g_tk.st.lc);
	tlv_put(&w, F_ACT_KEY_HASH, act_hash, 32U);
	tlv_put_u32(&w, F_POLICY_NO, pn);
	tlv_put_u8(&w, F_POLICY_FLAGS, g_tk.st.policy_flags);
	return emit_device_signed(rsp, &w);
}

/* ── Phone change / lost phone (Flow 5) ─────────────────────────────── */

uint16_t h_rebind(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	tlv_item_t newkey;
	stmt_t st;
	uint8_t h[32];
	uint32_t cur;
	uint32_t want;
	uint16_t sw;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, F_ACTIVATION_PUB, &newkey) != 0) ||
	    (newkey.len != QDSD_P256_PUB_LEN)) {
		return SW_WRONG_DATA;
	}
	sw = get_signed(a, P_REBIND, P_REBIND, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_BINDING, &cur) != 0) {
		return SW_INTERNAL;
	}
	want = stmt_u32(&st, F_BINDING_NO);
	if (want != cur + 1U) {
		return SW_STALE;
	}
	if ((port_sha256(newkey.val, newkey.len, h) != 0)) {
		return SW_INTERNAL;
	}
	if (!ct_equal(h, st.f[F_NEW_KEY_HASH], 32U) || (port_p256_pubkey_check(newkey.val) != 0) ||
	    !method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}

	nonce_drop_all(NONCE_WHY_DISCARDED);
	import_abort();
	sw = journal_run(J_REBIND, want, newkey.val, g_tk.st.policy_flags, g_tk.st.lc);
	if (sw != SW_OK) {
		return sw;
	}

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_REBIND_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_BINDING_NO, want);
	tlv_put(&w, F_ACT_KEY_HASH, h, 32U);
	return emit_device_signed(rsp, &w);
}

uint16_t h_reset(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	uint32_t cur;
	uint32_t want;
	uint16_t sw;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	sw = get_signed(a, P_RESET, P_RESET, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_BINDING, &cur) != 0) {
		return SW_INTERNAL;
	}
	want = stmt_u32(&st, F_BINDING_NO);
	if (want != cur + 1U) {
		return SW_STALE;
	}
	sw = verify_with(PORT_PUBKEY_CMD, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}

	nonce_drop_all(NONCE_WHY_DISCARDED);
	certw_abort();
	import_abort();
	sw = journal_run(J_RESET, want, NULL, 0U, LC_UNASSIGNED);
	if (sw != SW_OK) {
		return sw;
	}
	session_recompute();

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_RESET_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_BINDING_NO, want);
	tlv_put_u8(&w, F_STATE, g_tk.st.lc);
	return emit_device_signed(rsp, &w);
}

/* ── Login and settings (Flow 2b, QDSD settings) ────────────────────── */

uint16_t h_policy(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	uint32_t cur;
	uint32_t want;
	uint8_t flags;
	bool was_required;
	uint16_t sw;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	sw = get_signed(a, P_POLICY, P_POLICY, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	if (port_counter_read(PORT_CTR_POLICY, &cur) != 0) {
		return SW_INTERNAL;
	}
	want = stmt_u32(&st, F_POLICY_NO);
	if (want != cur + 1U) {
		return SW_STALE;
	}
	flags = stmt_u8(&st, F_POLICY_FLAGS);
	if (!policy_flags_ok(flags) || !method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}

	was_required = login_required();
	sw = journal_run(J_POLICY, want, NULL, flags, g_tk.st.lc);
	if (sw != SW_OK) {
		return sw;
	}
	/* Turning login approval on logs out at once; turning it off logs in. */
	if (!was_required && login_required()) {
		g_tk.sess.pairing = false;
		g_tk.sess.logged_in = false;
	}
	session_recompute();

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_POLICY_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put_u32(&w, F_POLICY_NO, want);
	tlv_put_u8(&w, F_POLICY_FLAGS, g_tk.st.policy_flags);
	return emit_device_signed(rsp, &w);
}

uint16_t h_login(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_writer_t w;
	tlv_item_t sig;
	stmt_t st;
	uint8_t nonce[32];
	uint32_t pn;
	uint16_t sw;
	int ni;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	sw = get_signed(a, P_LOGIN_ASSERTION, P_LOGIN_ASSERTION, &st, &sig);
	if (sw != SW_OK) {
		return sw;
	}
	ni = nonce_find(st.f[F_NONCE]);
	if (ni < 0) {
		return nonce_stale(rsp, st.f[F_NONCE], 0U);
	}
	if (!method_ok(&st)) {
		return SW_WRONG_DATA;
	}
	if (port_counter_read(PORT_CTR_POLICY, &pn) != 0) {
		return SW_INTERNAL;
	}
	sw = verify_with(PORT_PUBKEY_ACTIVATION, &st, &sig);
	if (sw != SW_OK) {
		if (sw == SW_SECURITY) {
			nonce_fail(ni);
		}
		return sw;
	}

	memcpy(nonce, g_tk.nonce[ni].v, sizeof(nonce));
	nonce_drop_at((size_t)ni, NONCE_WHY_USED);
	g_tk.sess.logged_in = true;
	g_tk.sess.card_auth = true;
	g_tk.sess.last_ms = port_uptime_ms();

	stmt_begin(&w, g_tk.stmt_buf, sizeof(g_tk.stmt_buf), P_LOGIN_RECEIPT);
	tlv_put(&w, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	tlv_put(&w, F_NONCE, nonce, sizeof(nonce));
	tlv_put_u32(&w, F_POLICY_NO, pn);
	tlv_put_u8(&w, F_SESSION, 0x01U);
	return emit_device_signed(rsp, &w);
}

uint16_t h_logout(const apdu_t *a, tlv_writer_t *rsp)
{
	(void)a;
	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	/* Outstanding nonces are kept; they may belong to other pending
	 * signing requests, and none of them grants anything on its own. */
	g_tk.sess.pairing = false;
	g_tk.sess.logged_in = false;
	if (!login_required()) {
		g_tk.sess.logged_in = true; /* stays logged in until next plug-in */
	}
	tlv_put_u8(rsp, F_SESSION, session_byte());
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

