/**
 * @file port_fw_none.c
 * @brief port.h firmware-update functions when CONFIG_QDSD_FW_UPDATE=n.
 *
 * For early board bring-up without MCUboot. A slot size of 0 tells the token
 * there is no update path: UPDATE_BEGIN / WRITE / FINISH answer 6D00. Never
 * ship a product image built this way: it cannot be updated in the field.
 */
#include <errno.h>

#include "port/port.h"

uint32_t port_fw_slot_size(void)
{
	return 0U;
}

int port_fw_begin(uint32_t total)
{
	(void)total;
	return -ENOTSUP;
}

int port_fw_write(const uint8_t *data, size_t len)
{
	(void)data;
	(void)len;
	return -ENOTSUP;
}

int port_fw_finish(const uint8_t sha256[QDSD_SHA256_LEN])
{
	(void)sha256;
	return -ENOTSUP;
}

void port_fw_abort(void)
{
}
