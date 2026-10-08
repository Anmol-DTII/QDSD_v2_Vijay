/**
 * @file token_receipt.c
 * @brief Signing-receipt ring in the SE050 and GET_RECEIPT.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Signing receipts (SE050 ring) ──────────────────────────────────── */

static uint8_t rcpt_idx(uint32_t ctr)
{
	return (uint8_t)(ctr % QDSD_RECEIPT_RING);
}

int rcpt_put_head(uint32_t ctr, uint8_t kind, const uint8_t *stmt, size_t len,
			 size_t dsc_len)
{
	if (len > RCPT_STMT_CAP) {
		return -ENOSPC;
	}
	memset(g_tk.rcpt_head, 0, sizeof(g_tk.rcpt_head));
	g_tk.rcpt_head[0] = 'R';
	g_tk.rcpt_head[1] = kind;
	tlv_wr_be16(&g_tk.rcpt_head[2], (uint16_t)len);
	tlv_wr_be16(&g_tk.rcpt_head[4], (uint16_t)dsc_len);
	if (len > 0U) {
		memcpy(&g_tk.rcpt_head[RCPT_HDR], stmt, len);
	}
	return port_obj_patch(PORT_OBJ_RECEIPT, rcpt_idx(ctr), 0U, g_tk.rcpt_head, RCPT_HEAD_LEN);
}

/*
 * Final receipt: tail (signatures) first, head last. Until the head is
 * written the entry still reads as pending, with its pending statement intact.
 */
int rcpt_put_final(uint32_t ctr, const uint8_t *stmt, size_t len,
			  const uint8_t devsig[QDSD_P256_SIG_LEN], const uint8_t *dsc, size_t dsc_len)
{
	if (dsc_len > QDSD_DSC_SIG_MAX) {
		return -EINVAL;
	}
	memset(g_tk.rcpt_tail, 0, sizeof(g_tk.rcpt_tail));
	memcpy(g_tk.rcpt_tail, devsig, QDSD_P256_SIG_LEN);
	if (dsc_len > 0U) {
		memcpy(&g_tk.rcpt_tail[QDSD_P256_SIG_LEN], dsc, dsc_len);
	}
	if (port_obj_patch(PORT_OBJ_RECEIPT, rcpt_idx(ctr), RCPT_HEAD_LEN, g_tk.rcpt_tail,
			   RCPT_TAIL_LEN) != 0) {
		return -EIO;
	}
	return rcpt_put_head(ctr, RCPT_FINAL, stmt, len, dsc_len);
}

/* Create missing ring entries (factory close, or tokens from firmware <= 0.5). */
int rcpt_ensure(void)
{
	size_t len = 0U;
	uint8_t i;
	int rc;

	for (i = 0U; i < QDSD_RECEIPT_RING; i++) {
		rc = port_obj_read(PORT_OBJ_RECEIPT, i, NULL, 0U, &len);
		if ((rc == 0) && (len == RCPT_LEN)) {
			continue;
		}
		if ((rc != 0) && (rc != -ENOENT)) {
			return -EIO;
		}
		memset(g_tk.read_buf, 0, RCPT_LEN);
		if (port_obj_write(PORT_OBJ_RECEIPT, i, g_tk.read_buf, RCPT_LEN) != 0) {
			return -EIO;
		}
	}
	return 0;
}

/* Forget all receipts (lost-phone RESET: they belong to the old Subscriber). */
int rcpt_clear_all(void)
{
	uint8_t i;
	int rc;

	memset(g_tk.rcpt_head, 0, sizeof(g_tk.rcpt_head));
	for (i = 0U; i < QDSD_RECEIPT_RING; i++) {
		rc = port_obj_patch(PORT_OBJ_RECEIPT, i, 0U, g_tk.rcpt_head, RCPT_HEAD_LEN);
		if (!ok_or_absent(rc)) {
			return -EIO;
		}
	}
	return 0;
}

/* Read ring entry for ctr into g_tk.read_buf. Returns kind, or negative. */
static int rcpt_load(uint8_t idx, size_t *stmt_len, size_t *dsc_len)
{
	size_t len = 0U;
	int rc = port_obj_read(PORT_OBJ_RECEIPT, idx, g_tk.read_buf, sizeof(g_tk.read_buf), &len);

	if (rc != 0) {
		return (rc == -ENOENT) ? -ENOENT : -EIO;
	}
	if ((len != RCPT_LEN) || (g_tk.read_buf[0] != 'R') || (g_tk.read_buf[1] > RCPT_FINAL)) {
		return RCPT_EMPTY;
	}
	*stmt_len = tlv_be16(&g_tk.read_buf[2]);
	*dsc_len = tlv_be16(&g_tk.read_buf[4]);
	if ((*stmt_len > RCPT_STMT_CAP) || (*dsc_len > QDSD_DSC_SIG_MAX)) {
		return RCPT_EMPTY;
	}
	return g_tk.read_buf[1];
}

/*
 * Boot: a pending entry means power was lost between counting a signature
 * and saving its receipt. Its statement already says status 02 (interrupted),
 * so sign it as it is and make it final. The DSC signature, if one was made,
 * was never released.
 */
int rcpt_recover(void)
{
	uint8_t stmt[RCPT_STMT_CAP];
	uint8_t sig[QDSD_P256_SIG_LEN];
	uint8_t h[32];
	size_t slen = 0U;
	size_t dlen = 0U;
	stmt_t st;
	uint8_t i;
	int kind;

	for (i = 0U; i < QDSD_RECEIPT_RING; i++) {
		kind = rcpt_load(i, &slen, &dlen);
		if (kind < 0) {
			return (kind == -ENOENT) ? 0 : -EIO;
		}
		if (kind != (int)RCPT_PENDING) {
			continue;
		}
		memcpy(stmt, &g_tk.read_buf[RCPT_HDR], slen);
		if ((stmt_parse(stmt, slen, &st) != 0) || (st.purpose != P_SIGN_RECEIPT) ||
		    (stmt_u8(&st, F_STATUS) != RCPT_STATUS_INTERRUPTED) ||
		    (rcpt_idx(stmt_u32(&st, F_SIGN_COUNTER)) != i)) {
			memset(g_tk.rcpt_head, 0, sizeof(g_tk.rcpt_head));
			(void)port_obj_patch(PORT_OBJ_RECEIPT, i, 0U, g_tk.rcpt_head, RCPT_HEAD_LEN);
			continue;
		}
		if ((port_sha256(stmt, slen, h) != 0) || (port_devkey_sign(h, sig) != 0) ||
		    (rcpt_put_final(stmt_u32(&st, F_SIGN_COUNTER), stmt, slen, sig, NULL, 0U) != 0)) {
			return -EIO;
		}
	}
	return 0;
}

/*
 * GET_RECEIPT (v3.2): the saved receipt (and DSC signature) for a sign
 * counter value, or for the latest signature if no counter is given.
 * Allowed while logged out: a receipt reveals nothing the cloud does not
 * already hold, and the middleware needs it after a lost reply.
 */
/*
 * Newest final receipt whose request_id is rid (the cloud's signing request);
 * 0 if none is in the ring. The agent uses it after a lost SIGN reply (nonce
 * status 05) without knowing the signature's counter.
 */
static int rcpt_find_request(const uint8_t *rid, uint32_t *found)
{
	stmt_t st;
	size_t slen = 0U;
	size_t dlen = 0U;
	uint32_t ctr;
	uint8_t i;
	int kind;

	*found = 0U;
	for (i = 0U; i < QDSD_RECEIPT_RING; i++) {
		kind = rcpt_load(i, &slen, &dlen);
		if (kind == -ENOENT) {
			continue;
		}
		if (kind < 0) {
			return -EIO;
		}
		if ((kind != (int)RCPT_FINAL) ||
		    (stmt_parse(&g_tk.read_buf[RCPT_HDR], slen, &st) != 0) ||
		    (st.purpose != P_SIGN_RECEIPT) ||
		    (memcmp(st.f[F_REQUEST_ID], rid, 16U) != 0)) {
			continue;
		}
		ctr = stmt_u32(&st, F_SIGN_COUNTER);
		if ((rcpt_idx(ctr) == i) && (ctr > *found)) {
			*found = ctr;
		}
	}
	return 0;
}

uint16_t h_get_receipt(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t c;
	tlv_item_t r;
	stmt_t st;
	uint32_t want;
	size_t slen = 0U;
	size_t dlen = 0U;
	bool by_ctr;
	bool by_rid;
	int kind;

	if (!lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	by_ctr = (tlv_find(a->data, a->lc, F_SIGN_COUNTER, &c) == 0);
	by_rid = (tlv_find(a->data, a->lc, F_REQUEST_ID, &r) == 0);
	if (by_ctr && by_rid) {
		return SW_WRONG_DATA; /* one selector at a time */
	}
	if (by_rid) {
		if (r.len != 16U) {
			return SW_WRONG_DATA;
		}
		if (rcpt_find_request(r.val, &want) != 0) {
			return SW_INTERNAL;
		}
	} else if (by_ctr) {
		if (c.len != 4U) {
			return SW_WRONG_DATA;
		}
		want = tlv_be32(c.val);
	} else if (a->lc == 0U) {
		if (port_counter_read(PORT_CTR_SIGN, &want) != 0) {
			return SW_INTERNAL;
		}
	} else {
		return SW_WRONG_DATA;
	}
	if (want == 0U) {
		return SW_NOT_FOUND;
	}
	kind = rcpt_load(rcpt_idx(want), &slen, &dlen);
	if (kind == -ENOENT) {
		return SW_NOT_FOUND;
	}
	if (kind < 0) {
		return SW_INTERNAL;
	}
	if ((kind != (int)RCPT_FINAL) || (stmt_parse(&g_tk.read_buf[RCPT_HDR], slen, &st) != 0) ||
	    (st.purpose != P_SIGN_RECEIPT) || (stmt_u32(&st, F_SIGN_COUNTER) != want)) {
		return SW_NOT_FOUND; /* overwritten by a newer one, or never made */
	}
	if (dlen > 0U) {
		tlv_put(rsp, T_DSC_SIG_RAW, &g_tk.read_buf[RCPT_DSCSIG_OFF], dlen);
	}
	tlv_put(rsp, T_STMT, &g_tk.read_buf[RCPT_HDR], slen);
	tlv_put(rsp, T_STMT_SIG, &g_tk.read_buf[RCPT_DEVSIG_OFF], QDSD_P256_SIG_LEN);
	return tlv_ok(rsp) ? SW_OK : SW_INTERNAL;
}

