/**
 * @file token_engine.c
 * @brief Command dispatch, session, nonces, GET_INFO and reads, init.
 *
 * QDSD token command processor (Ascert.en Flows v3.4, PROTOCOL.md v3.2).
 * Single-threaded: the transport calls token_engine_process() for one APDU at
 * a time. No dynamic memory. Private keys stay in the secure elements, with
 * one exception: an institutional key being imported (.pfx) passes through
 * RAM in plaintext between decryption and the write into the SE052F, and is
 * wiped immediately after (token_import.c).
 *
 * Every persistent record lives in a secure element:
 *   SE050  : lifecycle record, counters, command/activation keys, device key,
 *            device certificate, signing-receipt ring.
 *   SE052F : DSC keys, slot records, DSC certificates.
 * MCU flash (NVS) is only read at boot to move records written by 0.3-0.5.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

#define MIN_SZ(x, y) (((x) < (y)) ? (x) : (y))


/** The one token context. */
token_ctx_t g_tk;

static const uint8_t k_aid[] = { 0xA0, 0x00, 0x00, 0x00, 0x44, 0x54, 0x49, 0x49, 0x4C, 0x03 };

/* ── Small helpers ──────────────────────────────────────────────────── */

void secure_zero(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0U) {
		*v++ = 0U;
	}
}

bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t d = 0U;
	size_t i;

	for (i = 0U; i < n; i++) {
		d |= (uint8_t)(a[i] ^ b[i]);
	}
	return d == 0U;
}

bool lc_is(uint8_t a, uint8_t b)
{
	return g_tk.st.lc == a || g_tk.st.lc == b;
}

bool alg_ok(uint8_t alg)
{
	return (alg == QDSD_ALG_P256) || (alg == QDSD_ALG_RSA2048);
}

void fw_version(uint8_t v[4])
{
	v[0] = QDSD_FW_MAJOR;
	v[1] = QDSD_FW_MINOR;
	v[2] = QDSD_FW_PATCH;
	v[3] = QDSD_FW_BUILD;
}

int pubkey_hash(port_pubkey_t which, uint8_t h[32])
{
	uint8_t pub[QDSD_P256_PUB_LEN];
	int rc = port_pubkey_read(which, pub);

	if (rc == -ENOENT) {
		memset(h, 0, 32U);
		return 0;
	}
	if (rc != 0) {
		return rc;
	}
	return port_sha256(pub, sizeof(pub), h);
}

int read_counters(uint32_t *binding, uint32_t *keygen, uint32_t *sign)
{
	if ((port_counter_read(PORT_CTR_BINDING, binding) != 0) ||
	    (port_counter_read(PORT_CTR_KEYGEN, keygen) != 0) ||
	    (port_counter_read(PORT_CTR_SIGN, sign) != 0)) {
		return -EIO;
	}
	return 0;
}

/* Bring a counter up to target (used by journal roll-forward). */
int counter_to(port_counter_t c, uint32_t target)
{
	uint32_t v;
	int rc = port_counter_read(c, &v);

	if (rc != 0) {
		return rc;
	}
	if (v == target) {
		return 0;
	}
	if ((v > target) || ((target - v) != 1U)) {
		return -ERANGE;
	}
	rc = port_counter_inc(c);
	if (rc != 0) {
		return rc;
	}
	rc = port_counter_read(c, &v);
	return ((rc == 0) && (v == target)) ? 0 : -EIO;
}

bool ok_or_absent(int rc)
{
	return (rc == 0) || (rc == -ENOENT);
}

int set_lc(uint8_t lc)
{
	uint8_t old = g_tk.st.lc;

	if (old == lc) {
		return 0;
	}
	g_tk.st.lc = lc;
	if (state_save(&g_tk.st) != 0) {
		g_tk.st.lc = old;
		return -EIO;
	}
	port_event(PORT_EVT_STATE_CHANGED, g_tk.st.lc);
	return 0;
}

/* ── Nonce pool ─────────────────────────────────────────────────────── */

/* Drop nonce i, remembering why (nonces are not secret; 8 bytes identify it). */
void nonce_drop_at(size_t i, uint8_t why)
{
	if (g_tk.nonce[i].valid) {
		uint8_t g = g_tk.grave_next;

		memcpy(g_tk.grave[g].pfx, g_tk.nonce[i].v, NONCE_PFX);
		g_tk.grave[g].why = why;
		g_tk.grave_next = (uint8_t)((g + 1U) % NONCE_GRAVE);
	}
	secure_zero(&g_tk.nonce[i], sizeof(g_tk.nonce[i]));
}

void nonce_drop_all(uint8_t why)
{
	size_t i;

	for (i = 0U; i < QDSD_NONCE_SLOTS; i++) {
		nonce_drop_at(i, why);
	}
}

/*
 * 6984 for a SIGN or LOGIN whose nonce is not usable, with the reason in
 * T_NONCE_STATUS so the app can say "timed out" or "cancelled, try again"
 * (PROTOCOL.md §4.8). why = 0: look the nonce up among the dropped ones.
 */
uint16_t nonce_stale(tlv_writer_t *rsp, const uint8_t *v, uint8_t why)
{
	uint8_t i;

	if (why == 0U) {
		why = NONCE_WHY_UNKNOWN;
		for (i = 1U; i <= NONCE_GRAVE; i++) { /* newest first */
			uint8_t g = (uint8_t)((g_tk.grave_next + NONCE_GRAVE - i) % NONCE_GRAVE);

			if ((g_tk.grave[g].why != 0U) &&
			    (memcmp(g_tk.grave[g].pfx, v, NONCE_PFX) == 0)) {
				why = g_tk.grave[g].why;
				break;
			}
		}
	}
	tlv_put_u8(rsp, T_NONCE_STATUS, why);
	g_tk.keep_data_on_error = tlv_ok(rsp);
	return SW_STALE;
}

/* Index of the live nonce equal to v, or -1. Expired nonces are dropped. */
int nonce_find(const uint8_t *v)
{
	uint64_t now = port_uptime_ms();
	int found = -1;
	size_t i;

	for (i = 0U; i < QDSD_NONCE_SLOTS; i++) {
		if (!g_tk.nonce[i].valid) {
			continue;
		}
		if ((now - g_tk.nonce[i].issued_ms) > QDSD_NONCE_TTL_MS) {
			nonce_drop_at(i, NONCE_WHY_EXPIRED);
			continue;
		}
		if (ct_equal(g_tk.nonce[i].v, v, sizeof(g_tk.nonce[i].v))) {
			found = (int)i;
		}
	}
	return found;
}

/* A failed signature check counts against that nonce only. */
void nonce_fail(int i)
{
	g_tk.nonce[i].fails++;
	if (g_tk.nonce[i].fails >= QDSD_NONCE_MAX_FAILS) {
		nonce_drop_at((size_t)i, NONCE_WHY_FAILS);
	}
}

void certw_abort(void)
{
	g_tk.certw.active = false;
	g_tk.certw.got = 0U;
	g_tk.certw.total = 0U;
}

void import_abort(void)
{
	if (g_tk.imp.active) {
		port_ecdh_clear();
	}
	secure_zero(&g_tk.imp, sizeof(g_tk.imp));
	secure_zero(g_tk.imp_buf, sizeof(g_tk.imp_buf));
}

bool login_required(void)
{
	return (g_tk.st.policy_flags & POLICY_LOGIN_REQUIRED) != 0U;
}

bool session_exists(void)
{
	return lc_is(LC_BOUND, LC_READY);
}

/* Session at SELECT, after BIND/POLICY, or on LOGOUT. */
void session_recompute(void)
{
	if (!session_exists()) {
		g_tk.sess.logged_in = false;
		g_tk.sess.pairing = false;
		return;
	}
	if (!login_required() || g_tk.sess.pairing) {
		g_tk.sess.logged_in = true;
	}
	g_tk.sess.last_ms = port_uptime_ms();
}

/* Current session, applying the idle timeout. */
bool session_logged_in(void)
{
	if (!session_exists()) {
		return false;
	}
	if (!login_required() || g_tk.sess.pairing) {
		return true;
	}
	if (g_tk.sess.logged_in && ((port_uptime_ms() - g_tk.sess.last_ms) > QDSD_SESSION_IDLE_MS)) {
		g_tk.sess.logged_in = false;
	}
	return g_tk.sess.logged_in;
}

uint8_t session_byte(void)
{
	return session_logged_in() ? 0x01U : 0x00U;
}

/* Approval method in a phone-signed statement (PROTOCOL.md §2.4). */
bool method_ok(const stmt_t *st)
{
	uint8_t m = stmt_u8(st, F_METHOD);

	return (m >= METHOD_MIN) && (m <= METHOD_MAX);
}

bool policy_flags_ok(uint8_t flags)
{
	return (flags & (uint8_t)~POLICY_DEFINED_BITS) == 0U;
}

/* Device-key signature over the statement built in w. */
int device_sign(const tlv_writer_t *w, uint8_t sig[QDSD_P256_SIG_LEN])
{
	uint8_t h[32];

	if (!tlv_ok(w)) {
		return -ENOSPC;
	}
	if ((port_sha256(w->buf, w->len, h) != 0) || (port_devkey_sign(h, sig) != 0)) {
		return -EIO;
	}
	return 0;
}

/* Sign stmt (built in w) with the device key and append 70/71 to rsp. */
uint16_t emit_device_signed(tlv_writer_t *rsp, const tlv_writer_t *w)
{
	uint8_t sig[QDSD_P256_SIG_LEN];

	if (device_sign(w, sig) != 0) {
		return SW_INTERNAL;
	}
	tlv_put(rsp, T_STMT, w->buf, w->len);
	tlv_put(rsp, T_STMT_SIG, sig, sizeof(sig));
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

/* Extract and canonically parse the 70/71 signed statement in data. */
uint16_t get_signed(const apdu_t *a, uint8_t purpose_a, uint8_t purpose_b,
			   stmt_t *st, tlv_item_t *sig)
{
	tlv_item_t s;

	if ((tlv_find(a->data, a->lc, T_STMT, &s) != 0) ||
	    (tlv_find(a->data, a->lc, T_STMT_SIG, sig) != 0)) {
		return SW_WRONG_DATA;
	}
	if (stmt_parse(s.val, s.len, st) != 0) {
		return SW_WRONG_DATA;
	}
	if ((st->purpose != purpose_a) && (st->purpose != purpose_b)) {
		return SW_WRONG_DATA;
	}
	if (!g_tk.st.has_device_id ||
	    !ct_equal(st->f[F_DEVICE_ID], g_tk.st.device_id, QDSD_DEVICE_ID_LEN)) {
		return SW_WRONG_DATA;
	}
	return SW_OK;
}

/* Signature check inside the SE050 against a stored key. */
uint16_t verify_with(port_pubkey_t which, const stmt_t *st, const tlv_item_t *sig)
{
	int rc = stmt_verify_stored(st, sig->val, sig->len, which);

	if (rc == 0) {
		return SW_OK;
	}
	return (rc == -EPERM) ? SW_SECURITY : SW_INTERNAL;
}

/* ── Handlers ───────────────────────────────────────────────────────── */

/*
 * SELECT. A SELECT that fails (other AID, wrong P1/P2 or CLA) leaves the
 * current selection as it is (ISO 7816-4, Java Card): Windows and other
 * token software SELECT their own AIDs on every card. Re-SELECTing our AID
 * keeps the session: only the first SELECT of a USB connection sets the
 * starting session (PROTOCOL.md §3.2, §4.1).
 */
static uint16_t h_select(const apdu_t *a, tlv_writer_t *rsp)
{
	(void)rsp;
	if (a->cla != 0x00U) {
		return SW_CLA_NOT_SUPPORTED;
	}
	if ((a->p1 != 0x04U) || (a->p2 != 0x00U)) {
		return SW_WRONG_P1P2;
	}
	if ((a->lc != sizeof(k_aid)) || (memcmp(a->data, k_aid, sizeof(k_aid)) != 0)) {
		return SW_FILE_NOT_FOUND;
	}
	g_tk.selected = true;
	if (!g_tk.sess.started) {
		g_tk.sess.started = true;
		g_tk.sess.logged_in = false;
		session_recompute();
	}
	return SW_OK;
}

static uint16_t h_get_info(const apdu_t *a, tlv_writer_t *rsp)
{
	uint32_t b;
	uint32_t k;
	uint32_t s;
	uint32_t pn;
	uint8_t fw[4];
	uint8_t i;
	bool full;

	(void)a;
	/* While LOGGED_OUT only identity and state are shown (Flows v3.3). */
	full = !g_tk.fault && (!session_exists() || session_logged_in());
	fw_version(fw);

	tlv_put_u8(rsp, T_PROTO_VER, QDSD_PROTOCOL_VERSION);
	tlv_put_u8(rsp, T_PROTO_MINOR, QDSD_PROTOCOL_MINOR);
	if (g_tk.st.has_device_id) {
		tlv_put(rsp, F_DEVICE_ID, g_tk.st.device_id, QDSD_DEVICE_ID_LEN);
	}
	tlv_put_u8(rsp, F_STATE, g_tk.fault ? (uint8_t)LC_FAULT : g_tk.st.lc);
	tlv_put_u32(rsp, T_SESSION_EPOCH, g_tk.epoch);
	if (session_exists() && !g_tk.fault) {
		tlv_put_u8(rsp, F_SESSION, session_byte());
	}
	if (!full) {
		tlv_put_u8(rsp, F_POLICY_FLAGS, g_tk.st.policy_flags);
		tlv_put(rsp, F_FW_VERSION, fw, sizeof(fw));
		return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
	}

	if (read_counters(&b, &k, &s) == 0) {
		tlv_put_u32(rsp, F_BINDING_NO, b);
		tlv_put_u32(rsp, F_SIGN_COUNTER, s);
		tlv_put_u32(rsp, F_KEYGEN_COUNTER, k);
	}
	if (port_counter_read(PORT_CTR_POLICY, &pn) == 0) {
		tlv_put_u32(rsp, F_POLICY_NO, pn);
	}
	tlv_put_u8(rsp, F_POLICY_FLAGS, g_tk.st.policy_flags);
	tlv_put(rsp, F_FW_VERSION, fw, sizeof(fw));
	tlv_put_u8(rsp, T_SLOT_COUNT, QDSD_DSC_SLOTS);

	if (lc_is(LC_BOUND, LC_READY)) {
		for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
			slot_meta_t m;
			uint8_t e[9];

			if (slot_load(i, &m) != 0) {
				continue;
			}
			e[0] = i;
			e[1] = m.status;
			e[2] = m.alg;
			tlv_wr_be32(&e[3], m.seq);
			e[7] = (m.cert_len > 0U) ? 1U : 0U;
			e[8] = m.origin; /* v3.2: appended, older parsers read 8 bytes */
			tlv_put(rsp, T_SLOT_ENTRY, e, sizeof(e));
		}
	}
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

/* Chunked read of a record already loaded into buf. */
static uint16_t chunked_reply(const uint8_t *buf, size_t len, const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t off;
	uint16_t o;
	size_t n;

	if ((tlv_find(a->data, a->lc, T_OFFSET, &off) != 0) || (off.len != 2U)) {
		return SW_WRONG_DATA;
	}
	o = tlv_be16(off.val);
	if (o > len) {
		return SW_WRONG_DATA;
	}
	n = len - o;
	if (n > QDSD_READ_CHUNK) {
		n = QDSD_READ_CHUNK;
	}
	tlv_put_u16(rsp, T_TOTAL, (uint16_t)len);
	tlv_put(rsp, T_CHUNK, &buf[o], n);
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

static uint16_t h_get_device_cert(const apdu_t *a, tlv_writer_t *rsp)
{
	size_t len = 0U;
	int rc;

	if (g_tk.st.lc == LC_MANUFACTURING) {
		return SW_CONDITIONS;
	}
	rc = port_obj_read(PORT_OBJ_DEVICE_CERT, 0U, g_tk.read_buf, sizeof(g_tk.read_buf), &len);
	if (rc == -ENOENT) {
		return SW_NOT_FOUND;
	}
	if (rc != 0) {
		return SW_INTERNAL;
	}
	return chunked_reply(g_tk.read_buf, len, a, rsp);
}

static uint16_t h_get_cert(const apdu_t *a, tlv_writer_t *rsp)
{
	slot_meta_t m;
	size_t len = 0U;
	int rc;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	if (a->p1 >= QDSD_DSC_SLOTS) {
		return SW_WRONG_P1P2;
	}
	if (slot_load(a->p1, &m) != 0) {
		return SW_INTERNAL;
	}
	rc = slot_cert_read(a->p1, &m, g_tk.read_buf, sizeof(g_tk.read_buf), &len);
	if (rc == -ENOENT) {
		return SW_NOT_FOUND;
	}
	if (rc != 0) {
		return SW_INTERNAL;
	}
	return chunked_reply(g_tk.read_buf, len, a, rsp);
}

/* ── Dispatch ───────────────────────────────────────────────────────── */

/*
 * ISO 7816-3 cases 1, 2S/E, 3S/E, 4S/E. a->ext is set for the extended forms:
 * the host takes the whole response in one exchange. For short forms a
 * response over 256 bytes goes out with 61xx and GET RESPONSE.
 */
static int parse_apdu(const uint8_t *b, size_t n, apdu_t *a)
{
	memset(a, 0, sizeof(*a));
	if (n < 4U) {
		return -1;
	}
	a->cla = b[0];
	a->ins = b[1];
	a->p1 = b[2];
	a->p2 = b[3];

	if (n == 4U) {
		return 0; /* case 1 */
	}
	if (n == 5U) {
		a->le = (b[4] != 0U) ? b[4] : 256U; /* case 2S */
		return 0;
	}
	if (b[4] != 0x00U) {
		a->lc = b[4];
		if (n == 5U + a->lc) {
			a->data = &b[5]; /* case 3S */
			return 0;
		}
		if (n == 6U + a->lc) {
			a->data = &b[5]; /* case 4S */
			a->le = (b[n - 1U] != 0U) ? b[n - 1U] : 256U;
			return 0;
		}
		return -1;
	}
	/* Extended length */
	if (n < 7U) {
		return -1;
	}
	a->ext = true;
	if (n == 7U) {
		a->le = ((size_t)b[5] << 8) | b[6]; /* case 2E */
		if (a->le == 0U) {
			a->le = 65536U;
		}
		return 0;
	}
	a->lc = ((size_t)b[5] << 8) | b[6];
	if (a->lc == 0U) {
		return -1;
	}
	a->data = &b[7];
	if (n == 7U + a->lc) {
		return 0; /* case 3E */
	}
	if (n == 9U + a->lc) {
		a->le = ((size_t)b[n - 2U] << 8) | b[n - 1U]; /* case 4E */
		if (a->le == 0U) {
			a->le = 65536U;
		}
		return 0;
	}
	return -1;
}

typedef uint16_t (*handler_t)(const apdu_t *a, tlv_writer_t *rsp);

static handler_t lookup(uint8_t ins)
{
	switch (ins) {
	case INS_GET_INFO:            return h_get_info;
	case INS_GET_CERT:            return h_get_cert;
	case INS_WRITE_CERT:          return h_write_cert;
	case INS_IMPORT_DATA:         return h_import_data;
	case INS_GET_DEVICE_CERT:     return h_get_device_cert;
	case INS_ATTEST:              return h_attest;
	case INS_BIND:                return h_bind;
	case INS_GET_SESSION_NONCE:   return h_get_nonce;
	case INS_SIGN:                return h_sign;
	case INS_KEYGEN:              return h_keygen;
	case INS_SIGN_CSR:            return h_sign_csr;
	case INS_REBIND:              return h_rebind;
	case INS_RESET:               return h_reset;
	case INS_LOGIN:               return h_login;
	case INS_LOGOUT:              return h_logout;
	case INS_POLICY:              return h_policy;
	case INS_DELETE_KEY:          return h_delete_key;
	case INS_GET_RECEIPT:         return h_get_receipt;
	case INS_GET_KEY_ATTESTATION: return h_get_key_attestation;
	case INS_IMPORT_BEGIN:        return h_import_begin;
	case INS_FACTORY_INIT:        return h_factory_init;
	case INS_FACTORY_PERSONALISE: return h_factory_personalise;
	case INS_FACTORY_CLOSE:       return h_factory_close;
	case INS_FACTORY_WIPE:        return h_factory_wipe;
	case INS_FACTORY_DRIVE:       return h_factory_drive;
	case INS_UPDATE_BEGIN:        return h_update_begin;
	case INS_UPDATE_WRITE:        return h_update_write;
	case INS_UPDATE_FINISH:       return h_update_finish;
	default:                      return NULL;
	}
}

/* Run one complete command (after chaining) through the handlers. */
static uint16_t dispatch(const apdu_t *a, tlv_writer_t *w)
{
	handler_t h;
	uint16_t sw;

	if (a->ins == INS_SELECT) {
		return h_select(a, w);
	}
	if (a->cla != 0x80U) {
		return SW_CLA_NOT_SUPPORTED;
	}
	if (!g_tk.selected) {
		return SW_SECURITY;
	}
	h = lookup(a->ins);
	if (h == NULL) {
		return SW_INS_NOT_SUPPORTED;
	}
	if (g_tk.fault && (a->ins != INS_GET_INFO) && (a->ins != INS_FACTORY_WIPE)) {
		return SW_INTERNAL; /* service mode: identify, or wipe with DTI's secrets */
	}
	(void)session_logged_in(); /* apply idle timeout before the command */
	sw = h(a, w);
	if ((sw == SW_OK) && g_tk.sess.logged_in) {
		g_tk.sess.last_ms = port_uptime_ms();
	}
	return sw;
}

static void chain_abort(void)
{
	g_tk.chain.active = false;
	g_tk.chain.len = 0U;
}

/*
 * ISO 7816-4 command chaining (CLA bit 0x10): pieces with the same INS, P1,
 * P2 are collected, each answered 9000; the last piece (bit clear) runs the
 * whole command. For hosts whose driver cannot send extended APDUs.
 * Returns true with *a rewritten when the command is complete and should run;
 * false with *sw set otherwise.
 */
static bool chain_step(apdu_t *a, uint16_t *sw)
{
	bool more = (a->cla & CLA_CHAIN) != 0U;
	uint8_t cla = (uint8_t)(a->cla & ~CLA_CHAIN);

	if (!more && !g_tk.chain.active) {
		return true; /* ordinary command */
	}
	if (!more && (a->ins == INS_SELECT)) {
		chain_abort(); /* a SELECT ends any chain and runs (agent restart) */
		return true;
	}
	if (more && ((a->ins == INS_SELECT) || (cla != 0x80U))) {
		chain_abort();
		*sw = SW_CLA_NOT_SUPPORTED;
		return false;
	}
	if (g_tk.chain.active &&
	    ((g_tk.chain.cla != cla) || (g_tk.chain.ins != a->ins) || (g_tk.chain.p1 != a->p1) ||
	     (g_tk.chain.p2 != a->p2))) {
		chain_abort();
		*sw = SW_CHAIN_LAST_EXPECTED;
		return false;
	}
	if (!g_tk.chain.active) {
		g_tk.chain.active = true;
		g_tk.chain.cla = cla;
		g_tk.chain.ins = a->ins;
		g_tk.chain.p1 = a->p1;
		g_tk.chain.p2 = a->p2;
		g_tk.chain.len = 0U;
	}
	if (a->lc > (sizeof(g_tk.chain_buf) - g_tk.chain.len)) {
		chain_abort();
		*sw = SW_WRONG_LENGTH;
		return false;
	}
	if (a->lc > 0U) {
		memcpy(&g_tk.chain_buf[g_tk.chain.len], a->data, a->lc);
		g_tk.chain.len = (uint16_t)(g_tk.chain.len + a->lc);
	}
	if (more) {
		*sw = SW_OK;
		return false;
	}
	a->cla = cla;
	a->lc = g_tk.chain.len;
	a->data = (a->lc > 0U) ? g_tk.chain_buf : NULL;
	a->ext = false; /* the host used short APDUs: short responses too */
	g_tk.chain.active = false;
	return true;
}

/* GET RESPONSE (00 C0 00 00 Le): the next part of a held response. */
static void get_response(const apdu_t *a, uint8_t *rsp, size_t cap, size_t *rsp_len)
{
	size_t data_total = (size_t)g_tk.gr.len - 2U;
	size_t rem = data_total - g_tk.gr.off;
	size_t n = (a->le == 0U) ? SHORT_RSP_MAX : a->le;

	if ((a->p1 != 0U) || (a->p2 != 0U) || (a->lc != 0U)) {
		rsp[0] = (uint8_t)(SW_WRONG_P1P2 >> 8);
		rsp[1] = (uint8_t)SW_WRONG_P1P2;
		*rsp_len = 2U;
		return;
	}
	if (!a->ext && (n > SHORT_RSP_MAX)) {
		n = SHORT_RSP_MAX;
	}
	n = MIN_SZ(MIN_SZ(n, rem), cap - 2U);
	memcpy(rsp, &g_tk.gr_buf[g_tk.gr.off], n);
	g_tk.gr.off = (uint16_t)(g_tk.gr.off + n);
	rem -= n;
	if (rem > 0U) {
		rsp[n] = 0x61U;
		rsp[n + 1U] = (rem > 0xFFU) ? 0x00U : (uint8_t)rem;
	} else {
		rsp[n] = g_tk.gr_buf[g_tk.gr.len - 2U];
		rsp[n + 1U] = g_tk.gr_buf[g_tk.gr.len - 1U];
		g_tk.gr.len = 0U;
	}
	*rsp_len = n + 2U;
}

void token_engine_process(const uint8_t *apdu, size_t len,
		       uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
	tlv_writer_t w;
	apdu_t a;
	uint16_t sw = SW_INTERNAL;
	bool parsed;

	if ((rsp == NULL) || (rsp_len == NULL) || (rsp_cap < 2U)) {
		return;
	}
	tlv_writer_init(&w, rsp, rsp_cap - 2U);
	g_tk.keep_data_on_error = false;

	parsed = (apdu != NULL) && (len <= QDSD_APDU_MAX) && (parse_apdu(apdu, len, &a) == 0);
	if (!parsed) {
		chain_abort();
		g_tk.gr.len = 0U;
		sw = SW_WRONG_LENGTH;
	} else if ((a.ins == INS_GET_RESPONSE) && ((a.cla == 0x00U) || (a.cla == 0x80U))) {
		chain_abort(); /* any other command drops a chain */
		if (g_tk.gr.len == 0U) {
			sw = SW_CONDITIONS;
		} else {
			get_response(&a, rsp, rsp_cap, rsp_len);
			return;
		}
	} else {
		g_tk.gr.len = 0U; /* any other command drops a held response */
		if (((a.cla & CLA_CHAIN) != 0U) && (a.ins == INS_SELECT)) {
			chain_abort();
			sw = SW_CLA_NOT_SUPPORTED; /* SELECT cannot be chained */
		} else if (!g_tk.selected && ((a.cla & CLA_CHAIN) != 0U)) {
			chain_abort();
			sw = SW_SECURITY;
		} else if (chain_step(&a, &sw)) {
			sw = dispatch(&a, &w);
		}
	}

	if (!tlv_ok(&w) || ((sw != SW_OK) && !g_tk.keep_data_on_error)) {
		w.len = 0U;
	}
	if (parsed && !a.ext && (w.len > SHORT_RSP_MAX)) {
		/* Short-APDU host: first 256 bytes now, the rest by GET RESPONSE. */
		size_t rem = w.len - SHORT_RSP_MAX;

		if (w.len + 2U > sizeof(g_tk.gr_buf)) {
			rsp[0] = (uint8_t)(SW_INTERNAL >> 8);
			rsp[1] = (uint8_t)SW_INTERNAL;
			*rsp_len = 2U;
			return;
		}
		memcpy(g_tk.gr_buf, rsp, w.len);
		g_tk.gr_buf[w.len] = (uint8_t)(sw >> 8);
		g_tk.gr_buf[w.len + 1U] = (uint8_t)sw;
		g_tk.gr.len = (uint16_t)(w.len + 2U);
		g_tk.gr.off = SHORT_RSP_MAX;
		rsp[SHORT_RSP_MAX] = 0x61U;
		rsp[SHORT_RSP_MAX + 1U] = (rem > 0xFFU) ? 0x00U : (uint8_t)rem;
		*rsp_len = SHORT_RSP_MAX + 2U;
		return;
	}
	rsp[w.len] = (uint8_t)(sw >> 8);
	rsp[w.len + 1U] = (uint8_t)sw;
	*rsp_len = w.len + 2U;
}

static int enter_service(void)
{
	g_tk.fault = true;
	port_event(PORT_EVT_STATE_CHANGED, LC_FAULT);
	return QDSD_INIT_SERVICE;
}

int token_engine_init(void)
{
	int rc;

	memset(&g_tk, 0, sizeof(g_tk));
	new_epoch();
	drive_boot_check(); /* the install drive does not depend on the token state */
	rc = state_load(&g_tk.st);
	if (rc == -ENOENT) {
		uint8_t pub[QDSD_P256_PUB_LEN];
		int prc = port_pubkey_read(PORT_PUBKEY_CMD, pub);

		state_defaults(&g_tk.st);
		if (prc == 0) {
			/*
			 * A personalised token without its lifecycle record is never
			 * "fresh": factory commands must not open up again.
			 */
			g_tk.state_lost = true;
			return enter_service();
		}
		if (prc != -ENOENT) {
			return enter_service(); /* cannot tell: stay closed */
		}
		rc = 0;
	} else if (rc != 0) {
		state_defaults(&g_tk.st);
		/* Corrupt record: only DTI's secrets can repair (FACTORY_WIPE).
		 * A read error is not proof of anything: no relaxed wipe. */
		g_tk.state_lost = (rc == -EBADMSG);
		return enter_service();
	}
	if ((rc == 0) && (g_tk.st.j_op == J_WIPE)) {
		g_tk.wipe_pending = true; /* finish with FACTORY_WIPE + secrets */
		return enter_service();
	}
	if ((rc == 0) && (g_tk.st.j_op != J_NONE)) {
		rc = journal_apply();
	}
	if ((rc == 0) && g_tk.st.migrated) {
		/* Rewrite a firmware-0.3 record in the current layout. */
		g_tk.st.migrated = false;
		rc = state_save(&g_tk.st);
	}
	if (rc == 0) {
		rc = migrate_legacy();
	}
	if (rc == 0) {
		rc = check_objects();
	}
	if ((rc == 0) && (g_tk.st.lc != LC_MANUFACTURING)) {
		rc = rcpt_recover();
	}
	if (rc != 0) {
		return enter_service();
	}
	port_event(PORT_EVT_STATE_CHANGED, g_tk.st.lc);
	return 0;
}

/* New random session epoch (GET_INFO 39): boot, USB reset, factory wipe. */
void new_epoch(void)
{
	uint32_t e = g_tk.epoch;

	if (port_random((uint8_t *)&g_tk.epoch, sizeof(g_tk.epoch)) != 0) {
		/* No RNG (should not happen): still vary across boots. */
		uint32_t ctr = 0U;

		(void)port_counter_read(PORT_CTR_SIGN, &ctr);
		g_tk.epoch = (e + 0x9E3779B9U) ^ (uint32_t)port_uptime_ms() ^ (ctr * 0x85EBCA6BU);
	}
	if (g_tk.epoch == e) {
		g_tk.epoch = e + 1U;
	}
}

void token_engine_card_reset(void)
{
	g_tk.selected = false;
	g_tk.sess.card_auth = false; /* firmware update needs a login made after this */
	g_tk.chain.active = false;
	g_tk.gr.len = 0U;
	certw_abort();
	import_abort();
	fw_abort();
	drive_abort();
}

void token_engine_session_reset(void)
{
	token_engine_card_reset();
	g_tk.sess.started = false;
	g_tk.sess.logged_in = false;
	g_tk.sess.pairing = false;
	nonce_drop_all(NONCE_WHY_DISCARDED);
	new_epoch();
}

uint8_t token_engine_lifecycle(void)
{
	return g_tk.fault ? (uint8_t)LC_FAULT : g_tk.st.lc;
}

