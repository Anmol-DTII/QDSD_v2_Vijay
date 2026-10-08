/**
 * @file port_drive.c
 * @brief port.h install-drive functions on the external QSPI NOR flash
 *        (Infineon S25FL064L, devicetree label ext_flash; docs/INSTALL_DRIVE.md).
 *
 * The whole chip is the drive. If the flash does not answer at boot (JEDEC
 * id mismatch, not fitted), the driver is not ready, port_drive_size() is 0,
 * and the token works on without the drive: FACTORY_DRIVE answers 6D00 and
 * the PC sees an empty removable drive.
 */
#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>

#include "port/port.h"
#include "usb/token_msc.h"

LOG_MODULE_REGISTER(port_drive, LOG_LEVEL_INF);

#define DRIVE_NODE DT_NODELABEL(ext_flash)

#if !DT_NODE_HAS_STATUS(DRIVE_NODE, okay)
#error "CONFIG_QDSD_INSTALL_DRIVE needs the QSPI flash node 'ext_flash' (docs/board/qdsd_qspi_flash.overlay)."
#endif

#define DRIVE_BYTES DT_PROP_OR(DRIVE_NODE, size_in_bytes, DT_PROP_OR(DRIVE_NODE, size, 0) / 8)

static const struct device *const s_flash = DEVICE_DT_GET(DRIVE_NODE);

uint32_t port_drive_size(void)
{
	static bool logged;

	if (!device_is_ready(s_flash)) {
		if (!logged) {
			LOG_ERR("QSPI flash not ready: install drive off");
			logged = true;
		}
		return 0U;
	}
	return (uint32_t)DRIVE_BYTES;
}

int port_drive_read(uint32_t off, void *buf, size_t len)
{
	return flash_read(s_flash, (off_t)off, buf, len);
}

int port_drive_erase(uint32_t off, uint32_t len)
{
	return flash_erase(s_flash, (off_t)off, len);
}

int port_drive_write(uint32_t off, const void *buf, size_t len)
{
	return flash_write(s_flash, (off_t)off, buf, len);
}

void port_drive_medium(bool present, uint32_t blocks)
{
	token_msc_set_medium(present, blocks);
}
