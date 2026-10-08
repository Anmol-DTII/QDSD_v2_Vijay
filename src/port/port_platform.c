/**
 * @file port_platform.c
 * @brief port.h MCU functions: RNG, legacy NVS records, time, events.
 *
 * MCU-side cryptography is in port_crypto.c (shared with the host tests).
 * NVS only holds records left by firmware 0.3-0.5 until the core moves them
 * into the secure elements at first boot.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/fs/nvs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/reboot.h>

#include "hal/hal_gpio.h"
#include "storage/nvs_store.h"
#include "port/port.h"
#include "state_machine/state_record.h"

LOG_MODULE_REGISTER(port_platform, LOG_LEVEL_INF);

/* ── RNG ────────────────────────────────────────────────────────────── */

int port_random(uint8_t *buf, size_t len)
{
	return sys_csrand_get(buf, len) == 0 ? 0 : -EIO;
}

/* ── NVS ────────────────────────────────────────────────────────────── */

int port_nvs_read(uint16_t id, void *buf, size_t cap, size_t *len)
{
	struct nvs_fs *fs = qdsd_nvs_fs();
	uint8_t probe;
	ssize_t rc;

	if (fs == NULL) {
		return -ENODEV;
	}
	/* nvs_read returns the full item size even if it copied less. */
	rc = (buf == NULL) ? nvs_read(fs, id, &probe, sizeof(probe)) : nvs_read(fs, id, buf, cap);
	if (rc < 0) {
		return (rc == -ENOENT) ? -ENOENT : -EIO;
	}
	if ((buf != NULL) && ((size_t)rc > cap)) {
		return -ENOSPC;
	}
	*len = (size_t)rc;
	return 0;
}

int port_nvs_write(uint16_t id, const void *buf, size_t len)
{
	struct nvs_fs *fs = qdsd_nvs_fs();
	ssize_t rc;

	if (fs == NULL) {
		return -ENODEV;
	}
	rc = nvs_write(fs, id, buf, len);
	return (rc >= 0) ? 0 : -EIO; /* 0 = identical data already stored */
}

int port_nvs_delete(uint16_t id)
{
	struct nvs_fs *fs = qdsd_nvs_fs();
	size_t len = 0U;
	int rc;

	if (fs == NULL) {
		return -ENODEV;
	}
	rc = port_nvs_read(id, NULL, 0U, &len);
	if (rc != 0) {
		return rc;
	}
	return (nvs_delete(fs, id) == 0) ? 0 : -EIO;
}

/* ── System ─────────────────────────────────────────────────────────── */

uint64_t port_uptime_ms(void)
{
	return (uint64_t)k_uptime_get();
}

static uint8_t s_lc_pattern = LED_PATTERN_BOOT;

static void reboot_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	LOG_INF("Rebooting so MCUboot installs the staged image");
	sys_reboot(SYS_REBOOT_WARM);
}

static K_WORK_DELAYABLE_DEFINE(s_reboot_work, reboot_work_fn);

static led_pattern_t lc_pattern(uint32_t lc)
{
	switch (lc) {
	case LC_MANUFACTURING: return LED_PATTERN_MANUFACTURING;
	case LC_UNASSIGNED:    return LED_PATTERN_UNASSIGNED;
	case LC_BOUND:         return LED_PATTERN_BOUND;
	case LC_READY:         return LED_PATTERN_READY;
	default:               return LED_PATTERN_FAULT;
	}
}

void port_event(port_event_t evt, uint32_t arg)
{
	switch (evt) {
	case PORT_EVT_STATE_CHANGED:
		s_lc_pattern = (uint8_t)lc_pattern(arg);
		(void)hal_gpio_led_set_pattern((led_pattern_t)s_lc_pattern);
		LOG_INF("Lifecycle -> %s", state_lc_name((uint8_t)arg));
		break;
	case PORT_EVT_SIGNING_START:
		(void)hal_gpio_led_set_pattern(LED_PATTERN_SIGNING);
		break;
	case PORT_EVT_SIGNING_DONE:
		(void)hal_gpio_led_set_pattern((led_pattern_t)s_lc_pattern);
		if (arg != 0U) {
			LOG_ERR("DSC signing failed in SE052F");
		}
		break;
	case PORT_EVT_UPDATE_REBOOT:
		(void)hal_gpio_led_set_pattern(LED_PATTERN_UPDATE);
		/* Let the 9000 response reach the host before rebooting. */
		k_work_schedule(&s_reboot_work, K_MSEC(300));
		break;
	default:
		break;
	}
}
