/**
 * @file hal_i2c.c
 * @brief I2C bus HAL — Zephyr TWIM wrapper for secure-element buses.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/i2c.h>
#include <zephyr/logging/log.h>

#include "hal/hal_i2c.h"

LOG_MODULE_REGISTER(hal_i2c, LOG_LEVEL_DBG);

static const struct device *const s_i2c0_dev = DEVICE_DT_GET(DT_NODELABEL(i2c0));
static const struct device *const s_i2c1_dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));

static const struct device *bus_dev(hal_i2c_bus_t bus)
{
	if (bus == HAL_I2C_BUS_SE050) {
		return s_i2c1_dev;
	}

	return s_i2c0_dev;
}

int hal_i2c_init(void)
{
	if (!device_is_ready(s_i2c0_dev)) {
		LOG_ERR("I2C0 (SE052F) not ready");
		return HAL_I2C_ERR_INIT;
	}

	if (!device_is_ready(s_i2c1_dev)) {
		LOG_ERR("I2C1 bus not ready");
		return HAL_I2C_ERR_INIT;
	}

	LOG_INF("I2C0 ready for SE052F (P0.27/P0.26)");
	LOG_INF("I2C1 ready for SE050 (P1.01/P1.02)");

	return HAL_I2C_OK;
}

bool hal_i2c_device_present(hal_i2c_bus_t bus, uint8_t addr)
{
	const struct device *dev = bus_dev(bus);
	uint8_t dummy = 0U;
	int ret;

	if (bus == HAL_I2C_BUS_SE050) {
		return false;
	}

	if (!device_is_ready(dev)) {
		return false;
	}

	/*
	 * Nordic TWIM cannot do a zero-length address probe. A 1-byte write of
	 * 0x00 is the same method as the lab I2C scanner; a 1-byte read NACKs
	 * on UM11225 when the SE has no pending T=1 response, which is the
	 * idle state.
	 */
	ret = i2c_write(dev, &dummy, 1U, addr);
	LOG_DBG("I2C probe bus=%u addr=0x%02X: %s",
		(unsigned int)bus, addr, (ret == 0) ? "ACK" : "NACK");
	return ret == 0;
}

int hal_i2c_scan(hal_i2c_bus_t bus)
{
	const struct device *dev = bus_dev(bus);
	int found = 0;

	if (!device_is_ready(dev)) {
		LOG_ERR("I2C scan bus=%u: device not ready", (unsigned int)bus);
		return 0;
	}

	for (uint8_t addr = 0x08U; addr <= 0x77U; addr++) {
		uint8_t dummy = 0U;

		if (i2c_write(dev, &dummy, 1U, addr) == 0) {
			LOG_INF("I2C scan bus=%u: ACK at 0x%02X", (unsigned int)bus, addr);
			found++;
		}
	}

	LOG_INF("I2C scan bus=%u: %d device(s) answered in 0x08-0x77",
		(unsigned int)bus, found);
	return found;
}

int hal_i2c_recover(hal_i2c_bus_t bus)
{
	const struct device *dev = bus_dev(bus);
	int ret;

	if (!device_is_ready(dev)) {
		return HAL_I2C_ERR_INIT;
	}
	
	if (bus == HAL_I2C_BUS_SE050) {
		return HAL_I2C_ERR_INIT;
	}

	ret = i2c_recover_bus(dev);
	if (ret != 0) {
		LOG_WRN("I2C bus=%u recover failed: %d", (unsigned int)bus, ret);
		return HAL_I2C_ERR_NACK;
	}

	LOG_INF("I2C bus=%u recovered", (unsigned int)bus);
	return HAL_I2C_OK;
}

int hal_i2c_write(uint8_t addr, const uint8_t *buf, uint16_t len)
{
	int ret = i2c_write(s_i2c0_dev, buf, len, addr);

	if (ret < 0) {
		LOG_ERR("I2C0 write 0x%02X failed: %d", addr, ret);
		return HAL_I2C_ERR_NACK;
	}

	return HAL_I2C_OK;
}

int hal_i2c_read(uint8_t addr, uint8_t *buf, uint16_t len)
{
	int ret = i2c_read(s_i2c0_dev, buf, len, addr);

	if (ret < 0) {
		LOG_ERR("I2C0 read 0x%02X failed: %d", addr, ret);
		return HAL_I2C_ERR_NACK;
	}

	return HAL_I2C_OK;
}

int hal_i2c_write_read(uint8_t addr,
		       const uint8_t *wr_buf, uint16_t wr_len,
		       uint8_t *rd_buf, uint16_t rd_len)
{
	int ret = i2c_write_read(s_i2c0_dev, addr, wr_buf, wr_len, rd_buf, rd_len);

	if (ret < 0) {
		LOG_ERR("I2C0 write_read 0x%02X failed: %d", addr, ret);
		return HAL_I2C_ERR_NACK;
	}

	return HAL_I2C_OK;
}
