/**
 * @file main.c
 * @brief QDSD token firmware 0.6.2 — Ascert.en Flows v3.4, protocol v3.3 (nRF52840 / NCS 3.0).
 *
 * Boot order:
 *   1. Safe defaults: USB data gate CLOSED, LEDs, SE050 power.
 *   2. I2C, NVS (read once, to move 0.3-0.5 records), USB CCID descriptors.
 *   3. Self-test: crypto KATs, both secure elements answer, lifecycle record
 *      loads, interrupted BIND/REBIND/RESET finished, legacy records moved
 *      into the secure elements, cut-off signing receipts finished, required
 *      objects present.
 *   4. Pass    -> open the TS3USB221 gate and enumerate as a CCID reader.
 *      Service -> lifecycle record or objects inconsistent, or a factory reset
 *                 was cut off: enumerate, but answer only GET_INFO and
 *                 FACTORY_WIPE (DTI's repair path). Orange LED.
 *      Fail    -> crypto self-test or a secure element unreachable: gate
 *                 stays closed, orange LED, no USB.
 *
 * There is no Bluetooth: in the Ascert.en flows the phone talks only to DTI Cloud and
 * every authorisation reaches the token as a signed statement over USB.
 */
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "hal/hal_gpio.h"
#include "hal/hal_i2c.h"
#include "hal/hal_power.h"
#include "storage/nvs_store.h"
#include "token/token_engine.h"
#include "security/self_test.h"
#include "state_machine/state_record.h"
#include "se05x/se05x_link.h"
#include "usb/token_usb.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_INF);

static void halt_fault(const char *why, int rc)
{
	LOG_ERR("FAULT: %s (%d) — USB gate stays closed", why, rc);
	(void)hal_gpio_usb_gate_close();
	(void)hal_gpio_led_set_pattern(LED_PATTERN_FAULT);
	for (;;) {
		k_sleep(K_FOREVER);
	}
}

int main(void)
{
	int rc;

	LOG_INF("QDSD firmware %u.%u.%u (protocol v%u.%u)", QDSD_FW_MAJOR, QDSD_FW_MINOR,
		QDSD_FW_PATCH, QDSD_PROTOCOL_VERSION, QDSD_PROTOCOL_MINOR);

	rc = hal_power_init();
	if (rc != 0) {
		halt_fault("power/gate safe defaults", rc);
	}
	(void)hal_gpio_led_set_pattern(LED_PATTERN_BOOT);

	rc = hal_i2c_init();
	if (rc != 0) {
		halt_fault("I2C init", rc);
	}
	rc = qdsd_nvs_init();
	if (rc != 0) {
		halt_fault("NVS mount", rc);
	}
	rc = token_usb_init();
	if (rc != 0) {
		halt_fault("USB init", rc);
	}

	rc = qdsd_crypto_selftest();
	if (rc != 0) {
		halt_fault("crypto self-test", rc);
	}
	rc = se_link_init();
	if (rc != 0) {
		halt_fault("secure element sessions", rc);
	}
	rc = token_engine_init();
	if (rc == QDSD_INIT_SERVICE) {
		LOG_ERR("Service mode: only GET_INFO and FACTORY_WIPE are answered");
		(void)hal_gpio_led_set_pattern(LED_PATTERN_FAULT);
	} else if (rc != 0) {
		halt_fault("token engine init", rc);
	} else {
		LOG_INF("Self-test passed — state %s", state_lc_name(token_engine_lifecycle()));
	}

	rc = hal_gpio_usb_gate_open();
	if (rc != 0) {
		halt_fault("USB gate open", rc);
	}
	rc = token_usb_enable();
	if (rc != 0) {
		halt_fault("USB enable", rc);
	}
	return 0;
}
