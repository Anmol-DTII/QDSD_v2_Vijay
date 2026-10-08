/**
 * @file token_update.c
 * @brief Firmware update over the token interface (MCUboot secondary slot).
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Firmware update over the token interface ───────────────────────── */

void fw_abort(void)
{
	if (g_tk.fw.active) {
		port_fw_abort();
	}
	memset(&g_tk.fw, 0, sizeof(g_tk.fw));
}

static uint16_t update_allowed(void)
{
	if ((g_tk.st.lc != LC_UNASSIGNED) && !lc_is(LC_BOUND, LC_READY)) {
		return SW_CONDITIONS;
	}
	/*
	 * With login approval on, an update needs a login (or the pairing) made
	 * since the last card power cycle: the login itself survives card resets
	 * (§3.2), but a program that reaches the card later must not inherit the
	 * right to install firmware.
	 */
	if (session_exists() && login_required() &&
	    !(session_logged_in() && g_tk.sess.card_auth)) {
		return SW_LOGGED_OUT;
	}
	return SW_OK;
}

uint16_t h_update_begin(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t size;
	tlv_item_t hash;
	uint32_t total;
	uint16_t sw;

	(void)rsp;
	sw = update_allowed();
	if (sw != SW_OK) {
		return sw;
	}
	if ((tlv_find(a->data, a->lc, T_IMAGE_SIZE, &size) != 0) || (size.len != 4U) ||
	    (tlv_find(a->data, a->lc, T_IMAGE_SHA256, &hash) != 0) || (hash.len != 32U)) {
		return SW_WRONG_DATA;
	}
	total = tlv_be32(size.val);
	if ((total < MCUBOOT_HDR_MIN) || (total > port_fw_slot_size())) {
		return SW_WRONG_DATA;
	}
	fw_abort();
	if (port_fw_begin(total) != 0) {
		return SW_INTERNAL;
	}
	g_tk.fw.active = true;
	g_tk.fw.total = total;
	memcpy(g_tk.fw.sha256, hash.val, sizeof(g_tk.fw.sha256));
	return SW_OK;
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* Refuse a non-MCUboot file or an older version early (MCUboot checks again). */
static bool fw_header_ok(const uint8_t *h)
{
	uint32_t img;
	uint32_t cur;

	if (le32(h) != MCUBOOT_MAGIC) {
		return false;
	}
	/* ih_ver at offset 20: major u8, minor u8, revision u16 LE */
	img = ((uint32_t)h[20] << 24) | ((uint32_t)h[21] << 16) | ((uint32_t)h[23] << 8) | h[22];
	cur = ((uint32_t)QDSD_FW_MAJOR << 24) | ((uint32_t)QDSD_FW_MINOR << 16) | QDSD_FW_PATCH;
	return img >= cur;
}

uint16_t h_update_write(const apdu_t *a, tlv_writer_t *rsp)
{
	tlv_item_t off;
	tlv_item_t chunk;

	(void)rsp;
	if (!g_tk.fw.active) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, T_IMAGE_OFFSET, &off) != 0) || (off.len != 4U) ||
	    (tlv_find(a->data, a->lc, T_CHUNK, &chunk) != 0) || (chunk.len == 0U) ||
	    (chunk.len > QDSD_FW_CHUNK_MAX)) {
		return SW_WRONG_DATA;
	}
	if ((tlv_be32(off.val) != g_tk.fw.written) || (chunk.len > (g_tk.fw.total - g_tk.fw.written))) {
		return SW_WRONG_DATA; /* chunks must arrive in order */
	}
	if (g_tk.fw.written == 0U) {
		if ((chunk.len < MCUBOOT_HDR_MIN) || !fw_header_ok(chunk.val)) {
			fw_abort();
			return SW_WRONG_DATA;
		}
		g_tk.fw.header_ok = true;
	}
	if (port_fw_write(chunk.val, chunk.len) != 0) {
		fw_abort();
		return SW_INTERNAL;
	}
	g_tk.fw.written += (uint32_t)chunk.len;
	return SW_OK;
}

uint16_t h_update_finish(const apdu_t *a, tlv_writer_t *rsp)
{
	uint16_t sw;
	int rc;

	(void)a;
	(void)rsp;
	if (!g_tk.fw.active || !g_tk.fw.header_ok || (g_tk.fw.written != g_tk.fw.total)) {
		return SW_CONDITIONS;
	}
	sw = update_allowed();
	if (sw != SW_OK) {
		return sw;
	}
	rc = port_fw_finish(g_tk.fw.sha256);
	memset(&g_tk.fw, 0, sizeof(g_tk.fw));
	if (rc == -EBADMSG) {
		port_fw_abort();
		return SW_WRONG_DATA; /* image hash mismatch */
	}
	if (rc != 0) {
		port_fw_abort();
		return SW_INTERNAL;
	}
	/* Reply first; the port reboots shortly after so MCUboot installs it. */
	port_event(PORT_EVT_UPDATE_REBOOT, 0U);
	return SW_OK;
}

