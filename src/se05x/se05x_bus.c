/**
 * @file se05x_bus.c
 * @brief Shared Plug & Trust bus selector and cross-SE APDU lock.
 */

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>

#include "se05x/se05x_bus.h"

#if defined(CONFIG_PLUGANDTRUST)
/*
 * NXP nano-package lib/platform/zephyr/sm_i2c.c owns this global. Its
 * axI2CRead/Write functions use it for every T=1-over-I2C transfer.
 */
extern const struct device *i2c_dev;
#endif

static const struct device *const s_se052f_i2c =
	DEVICE_DT_GET(DT_NODELABEL(i2c0));
static const struct device *const s_se050_i2c =
	DEVICE_DT_GET(DT_NODELABEL(i2c1));

K_MUTEX_DEFINE(s_se05x_mutex);

int qdsd_se05x_bus_select_locked(qdsd_se05x_bus_t bus)
{
#if defined(CONFIG_PLUGANDTRUST)
	const struct device *dev =
		(bus == QDSD_SE05X_BUS_SE050) ? s_se050_i2c : s_se052f_i2c;

	if (!device_is_ready(dev)) {
		return -ENODEV;
	}

	i2c_dev = dev;
	return 0;
#else
	ARG_UNUSED(bus);
	return -ENOTSUP;
#endif
}

int qdsd_se05x_bus_lock(qdsd_se05x_bus_t bus)
{
	int ret;

	k_mutex_lock(&s_se05x_mutex, K_FOREVER);
	ret = qdsd_se05x_bus_select_locked(bus);
	if (ret != 0) {
		k_mutex_unlock(&s_se05x_mutex);
	}

	return ret;
}

void qdsd_se05x_bus_unlock(void)
{
	k_mutex_unlock(&s_se05x_mutex);
}
