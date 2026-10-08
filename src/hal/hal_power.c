/**
 * @file hal_power.c
 * @brief Boot-time safe defaults for power/enable-controlled signals.
 */

#include <zephyr/logging/log.h>

#include "hal/hal_power.h"
#include "hal/hal_gpio.h"

LOG_MODULE_REGISTER(hal_power, LOG_LEVEL_DBG);

int hal_power_init(void)
{
	int ret;

	/*
	 * USB data gate — highest priority safe default.
	 * TS3USB221 ~OE HIGH => switch disabled => document-hash path blocked.
	 */
	ret = hal_gpio_usb_gate_init();
	if (ret != HAL_GPIO_OK) {
		LOG_ERR("USB gate safe-default init failed: %d", ret);
		return HAL_POWER_ERR_INIT;
	}

	ret = hal_gpio_led_init();
	if (ret != HAL_GPIO_OK) {
		LOG_ERR("Status LED safe-default init failed: %d", ret);
		return HAL_POWER_ERR_INIT;
	}

	ret = hal_gpio_se050_ena_init();
	if (ret != HAL_GPIO_OK) {
		LOG_ERR("SE050 ENA init failed: %d", ret);
		return HAL_POWER_ERR_INIT;
	}

	LOG_INF("Power/enable safe defaults applied — USB gate closed, LEDs off");
	return HAL_POWER_OK;
}
