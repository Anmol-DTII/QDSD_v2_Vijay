/**
 * @file port_drive_none.c
 * @brief port.h install-drive functions for boards without the QSPI flash
 *        (CONFIG_QDSD_INSTALL_DRIVE=n): no drive, FACTORY_DRIVE answers 6D00.
 */
#include <errno.h>

#include "port/port.h"

uint32_t port_drive_size(void)
{
	return 0U;
}

int port_drive_read(uint32_t off, void *buf, size_t len)
{
	(void)off;
	(void)buf;
	(void)len;
	return -ENOTSUP;
}

int port_drive_erase(uint32_t off, uint32_t len)
{
	(void)off;
	(void)len;
	return -ENOTSUP;
}

int port_drive_write(uint32_t off, const void *buf, size_t len)
{
	(void)off;
	(void)buf;
	(void)len;
	return -ENOTSUP;
}

void port_drive_medium(bool present, uint32_t blocks)
{
	(void)present;
	(void)blocks;
}
