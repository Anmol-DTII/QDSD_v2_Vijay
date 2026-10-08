/**
 * @file port_fw.c
 * @brief port.h firmware-update functions: stream the image into MCUboot's
 *        secondary slot from the running app (no bootloader USB mode).
 *
 * MCUboot (overwrite-only, ECDSA P-256 signed images, downgrade prevention)
 * checks the signature and version at the next boot before installing.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/dfu/flash_img.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include "port/port.h"

LOG_MODULE_REGISTER(port_fw, LOG_LEVEL_INF);

#define SLOT1_ID   FIXED_PARTITION_ID(slot1_partition)
#define SLOT1_SIZE FIXED_PARTITION_SIZE(slot1_partition)

static struct flash_img_context s_ctx;
static uint32_t s_total;
static bool s_open;

uint32_t port_fw_slot_size(void)
{
	return (uint32_t)SLOT1_SIZE;
}

int port_fw_begin(uint32_t total)
{
	const struct flash_area *fa;
	int rc;

	if (total > SLOT1_SIZE) {
		return -ENOSPC;
	}
	/* Erase first so a stale image can never be mixed with the new one. */
	rc = flash_area_open(SLOT1_ID, &fa);
	if (rc != 0) {
		return rc;
	}
	rc = flash_area_erase(fa, 0, fa->fa_size);
	flash_area_close(fa);
	if (rc != 0) {
		return rc;
	}
	rc = flash_img_init_id(&s_ctx, SLOT1_ID);
	if (rc != 0) {
		return rc;
	}
	s_total = total;
	s_open = true;
	LOG_INF("Update: receiving %u bytes", (unsigned int)total);
	return 0;
}

int port_fw_write(const uint8_t *data, size_t len)
{
	if (!s_open) {
		return -EINVAL;
	}
	return flash_img_buffered_write(&s_ctx, data, len, false);
}

int port_fw_finish(const uint8_t sha256[QDSD_SHA256_LEN])
{
	struct flash_img_check fic = { .match = sha256, .clen = s_total };
	int rc;

	if (!s_open) {
		return -EINVAL;
	}
	rc = flash_img_buffered_write(&s_ctx, NULL, 0, true);
	if (rc != 0) {
		return rc;
	}
	if (flash_img_bytes_written(&s_ctx) != s_total) {
		return -EIO;
	}
	rc = flash_img_check(&s_ctx, &fic, SLOT1_ID);
	if (rc != 0) {
		LOG_ERR("Update: image hash mismatch");
		return -EBADMSG;
	}
	rc = boot_request_upgrade(BOOT_UPGRADE_PERMANENT);
	if (rc != 0) {
		return rc;
	}
	s_open = false;
	LOG_INF("Update: image staged, MCUboot will verify and install");
	return 0;
}

void port_fw_abort(void)
{
	s_open = false;
	s_total = 0U;
}
