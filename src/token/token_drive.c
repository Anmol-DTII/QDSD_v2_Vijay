/**
 * @file token_drive.c
 * @brief FACTORY_DRIVE — write the install-drive image (docs/INSTALL_DRIVE.md).
 *
 * The install drive is the token's external QSPI flash, shown to the PC as a
 * read-only USB disk carrying the Ascert.en installer. Only the Factory Tool
 * writes it, and only in MANUFACTURING: after FACTORY_CLOSE nothing can
 * change it (the USB side is read-only, and this command answers 6985).
 *
 *   80 E6 00 00  BEGIN   28 image size (u32, multiple of 512), 29 SHA-256
 *   80 E6 01 00  WRITE   2A offset (u32, = bytes written so far), 25 chunk
 *   80 E6 02 00  FINISH  reads the whole image back and checks the SHA-256
 *
 * The SHA-256 is a transfer check, not a signature (no content-signing key,
 * by decision of 8 Oct 2026): it proves the flash holds exactly what the
 * Factory Tool sent. The first 512 bytes (the FAT boot sector) are kept in
 * RAM and written only after the check passes, so a power cut or a failed
 * upload leaves flash without a boot sector, and the PC sees "no medium",
 * never a half-written disk. While an upload runs the drive shows "no medium".
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

#define DRIVE_P1_BEGIN  0x00U
#define DRIVE_P1_WRITE  0x01U
#define DRIVE_P1_FINISH 0x02U

#define BLOCK 512U

static uint8_t s_buf[BLOCK];

static uint32_t drive_blocks(void)
{
	return port_drive_size() / BLOCK;
}

/* A FAT boot sector: jump, 512-byte sectors, signature 55 AA. */
static bool image_valid(void)
{
	if ((port_drive_size() < BLOCK) || (port_drive_read(0U, s_buf, BLOCK) != 0)) {
		return false;
	}
	return ((s_buf[0] == 0xEBU) || (s_buf[0] == 0xE9U)) && (s_buf[11] == 0x00U) &&
	       (s_buf[12] == 0x02U) && (s_buf[510] == 0x55U) && (s_buf[511] == 0xAAU);
}

void drive_boot_check(void)
{
	if (port_drive_size() == 0U) {
		return;
	}
	port_drive_medium(image_valid(), drive_blocks());
}

void drive_abort(void)
{
	if (g_tk.drive.active) {
		/* Upload cut off: the old image is intact only if nothing was erased. */
		port_drive_medium((g_tk.drive.erased_to == 0U) && image_valid(), drive_blocks());
	}
	memset(&g_tk.drive, 0, sizeof(g_tk.drive));
}

static uint16_t drive_begin(const apdu_t *a)
{
	tlv_item_t size;
	tlv_item_t hash;
	uint32_t total;

	if ((tlv_find(a->data, a->lc, T_IMAGE_SIZE, &size) != 0) || (size.len != 4U) ||
	    (tlv_find(a->data, a->lc, T_IMAGE_SHA256, &hash) != 0) || (hash.len != 32U)) {
		return SW_WRONG_DATA;
	}
	total = tlv_be32(size.val);
	if ((total < BLOCK) || ((total % BLOCK) != 0U) || (total > port_drive_size())) {
		return SW_WRONG_DATA;
	}
	memset(&g_tk.drive, 0, sizeof(g_tk.drive));
	port_drive_medium(false, drive_blocks()); /* the PC sees "no medium" meanwhile */
	g_tk.drive.active = true;
	g_tk.drive.total = total;
	memcpy(g_tk.drive.sha256, hash.val, sizeof(g_tk.drive.sha256));
	return SW_OK;
}

static uint16_t drive_write(const apdu_t *a)
{
	tlv_item_t off;
	tlv_item_t chunk;
	uint32_t end;

	if (!g_tk.drive.active) {
		return SW_CONDITIONS;
	}
	if ((tlv_find(a->data, a->lc, T_IMAGE_OFFSET, &off) != 0) || (off.len != 4U) ||
	    (tlv_find(a->data, a->lc, T_CHUNK, &chunk) != 0) || (chunk.len == 0U) ||
	    (chunk.len > QDSD_DRIVE_CHUNK_MAX)) {
		return SW_WRONG_DATA;
	}
	if ((tlv_be32(off.val) != g_tk.drive.written) ||
	    (chunk.len > (g_tk.drive.total - g_tk.drive.written))) {
		return SW_WRONG_DATA; /* in order, and not past the announced size */
	}
	end = g_tk.drive.written + (uint32_t)chunk.len;
	while (g_tk.drive.erased_to < end) {
		if (port_drive_erase(g_tk.drive.erased_to, QDSD_DRIVE_ERASE_BLOCK) != 0) {
			drive_abort();
			return SW_INTERNAL;
		}
		g_tk.drive.erased_to += QDSD_DRIVE_ERASE_BLOCK;
	}
	{
		/* Bytes of block 0 go to RAM; the rest straight to flash. */
		uint32_t pos = g_tk.drive.written;
		const uint8_t *src = chunk.val;
		size_t left = chunk.len;

		if (pos < BLOCK) {
			size_t n = BLOCK - pos;

			if (n > left) {
				n = left;
			}
			memcpy(&g_tk.drive.head[pos], src, n);
			pos += (uint32_t)n;
			src += n;
			left -= n;
		}
		if ((left > 0U) && (port_drive_write(pos, src, left) != 0)) {
			drive_abort();
			return SW_INTERNAL;
		}
	}
	g_tk.drive.written = end;
	return SW_OK;
}

static uint16_t drive_finish(void)
{
	uint8_t h[QDSD_SHA256_LEN];
	uint32_t off;
	bool ok;

	if (!g_tk.drive.active || (g_tk.drive.written != g_tk.drive.total)) {
		return SW_CONDITIONS;
	}
	ok = (port_sha256_begin() == 0) &&
	     (port_sha256_update(g_tk.drive.head, BLOCK) == 0);
	for (off = BLOCK; ok && (off < g_tk.drive.total); off += BLOCK) {
		ok = (port_drive_read(off, s_buf, BLOCK) == 0) &&
		     (port_sha256_update(s_buf, BLOCK) == 0);
	}
	ok = ok && (port_sha256_finish(h) == 0) &&
	     (memcmp(h, g_tk.drive.sha256, sizeof(h)) == 0);
	/* Only now the boot sector, and check it landed. */
	ok = ok && (port_drive_write(0U, g_tk.drive.head, BLOCK) == 0) &&
	     (port_drive_read(0U, s_buf, BLOCK) == 0) &&
	     (memcmp(s_buf, g_tk.drive.head, BLOCK) == 0);
	if (!ok) {
		/* Never show a disk that is not exactly what the factory sent. */
		(void)port_drive_erase(0U, QDSD_DRIVE_ERASE_BLOCK);
		memset(&g_tk.drive, 0, sizeof(g_tk.drive));
		port_drive_medium(false, drive_blocks());
		return SW_WRONG_DATA;
	}
	memset(&g_tk.drive, 0, sizeof(g_tk.drive));
	port_drive_medium(image_valid(), drive_blocks());
	return SW_OK;
}

uint16_t h_factory_drive(const apdu_t *a, tlv_writer_t *rsp)
{
	(void)rsp;
	if (port_drive_size() == 0U) {
		return SW_INS_NOT_SUPPORTED; /* board or build without the drive */
	}
	if (g_tk.st.lc != LC_MANUFACTURING) {
		return SW_CONDITIONS;
	}
	if (a->p2 != 0U) {
		return SW_WRONG_P1P2;
	}
	switch (a->p1) {
	case DRIVE_P1_BEGIN:
		return drive_begin(a);
	case DRIVE_P1_WRITE:
		return drive_write(a);
	case DRIVE_P1_FINISH:
		return drive_finish();
	default:
		return SW_WRONG_P1P2;
	}
}
