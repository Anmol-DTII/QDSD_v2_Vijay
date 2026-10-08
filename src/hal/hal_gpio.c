/**
 * @file hal_gpio.c
 * @brief GPIO HAL — QDSD custom PCBA discrete I/O.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#include "hal/hal_gpio.h"

LOG_MODULE_REGISTER(hal_gpio, LOG_LEVEL_DBG);

/* ── Device-tree GPIO specs ──────────────────────────────────────────── */

static const struct gpio_dt_spec s_usb_oe =
	GPIO_DT_SPEC_GET(DT_ALIAS(usb_oe), gpios);
static const struct gpio_dt_spec s_usb_s =
	GPIO_DT_SPEC_GET(DT_ALIAS(usb_s), gpios);
static const struct gpio_dt_spec s_led_green =
	GPIO_DT_SPEC_GET(DT_ALIAS(status_led_green), gpios);
static const struct gpio_dt_spec s_led_orange =
	GPIO_DT_SPEC_GET(DT_ALIAS(status_led_orange), gpios);
static const struct gpio_dt_spec s_led_blue =
	GPIO_DT_SPEC_GET(DT_ALIAS(status_led_blue), gpios);
static const struct gpio_dt_spec s_se2_en =
	GPIO_DT_SPEC_GET(DT_ALIAS(se2_en), gpios);

/* ── RGB LED blink engine ────────────────────────────────────────────── */

/* 16 slots × tick: 0x5555 => 8 on + 8 off => 3 s per phase at 500 ms/slot */
#define BLINK_TICK_MS  500U
#define BLINK_SLOTS    16U

typedef struct {
	uint16_t bitmask;
	uint8_t  on_g;
	uint8_t  on_o;
	uint8_t  on_b;
} led_pattern_def_t;

/*
 * Bitmask: 16 slots × BLINK_TICK_MS (500 ms) — 1 = LED on for that slot.
 * RGB: orange channel = red indicator on LED4 (common-anode).
 */
static const uint16_t s_patterns[] = {
	[LED_PATTERN_OFF]           = 0x0000U,
	[LED_PATTERN_BOOT]          = 0x5555U,
	[LED_PATTERN_FAULT]         = 0xFFFFU,
	[LED_PATTERN_MANUFACTURING] = 0x0F0FU,
	[LED_PATTERN_UNASSIGNED]    = 0x5555U,
	[LED_PATTERN_BOUND]         = 0x5555U,
	[LED_PATTERN_READY]         = 0xFFFFU,
	[LED_PATTERN_SIGNING]       = 0xFFFFU,
	[LED_PATTERN_UPDATE]        = 0x3333U,
};

/* { bitmask, green, orange, blue } */
static const led_pattern_def_t s_pattern_colors[] = {
	[LED_PATTERN_OFF]           = { 0x0000U, 0U, 0U, 0U },
	[LED_PATTERN_BOOT]          = { 0x5555U, 0U, 1U, 0U },
	[LED_PATTERN_FAULT]         = { 0xFFFFU, 0U, 1U, 0U },
	[LED_PATTERN_MANUFACTURING] = { 0x0F0FU, 0U, 0U, 1U },
	[LED_PATTERN_UNASSIGNED]    = { 0x5555U, 1U, 0U, 0U },
	[LED_PATTERN_BOUND]         = { 0x5555U, 0U, 0U, 1U },
	[LED_PATTERN_READY]         = { 0xFFFFU, 1U, 0U, 0U },
	[LED_PATTERN_SIGNING]       = { 0xFFFFU, 0U, 0U, 1U },
	[LED_PATTERN_UPDATE]        = { 0x3333U, 0U, 0U, 1U },
};

static struct k_timer s_blink_timer;
static led_pattern_t  s_pattern = LED_PATTERN_OFF;
static uint8_t        s_slot  = 0U;

static void led_apply_rgb(uint8_t g, uint8_t o, uint8_t b)
{
	gpio_pin_set_dt(&s_led_green,  g);
	gpio_pin_set_dt(&s_led_orange, o);
	gpio_pin_set_dt(&s_led_blue,   b);
}

static void blink_tick(struct k_timer *t)
{
	const led_pattern_def_t *def;
	bool on;

	ARG_UNUSED(t);

	if (s_pattern >= ARRAY_SIZE(s_patterns)) {
		return;
	}

	def = &s_pattern_colors[s_pattern];
	on = ((s_patterns[s_pattern] >> (s_slot % BLINK_SLOTS)) & 0x01U) != 0U;

	if (on) {
		led_apply_rgb(def->on_g, def->on_o, def->on_b);
	} else {
		led_apply_rgb(0U, 0U, 0U);
	}

	s_slot = (uint8_t)((s_slot + 1U) % BLINK_SLOTS);
}

/* ── Status LED4 RGB ─────────────────────────────────────────────────── */

int hal_gpio_led_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&s_led_green) ||
	    !gpio_is_ready_dt(&s_led_orange) ||
	    !gpio_is_ready_dt(&s_led_blue)) {
		LOG_ERR("Status LED GPIO not ready");
		return HAL_GPIO_ERR_INIT;
	}

	ret = gpio_pin_configure_dt(&s_led_green, GPIO_OUTPUT_INACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	ret = gpio_pin_configure_dt(&s_led_orange, GPIO_OUTPUT_INACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	ret = gpio_pin_configure_dt(&s_led_blue, GPIO_OUTPUT_INACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	led_apply_rgb(0U, 0U, 0U);

	k_timer_init(&s_blink_timer, blink_tick, NULL);
	k_timer_start(&s_blink_timer, K_MSEC(BLINK_TICK_MS), K_MSEC(BLINK_TICK_MS));

	LOG_INF("Status LED4 RGB init: G=P0.14 O=P0.15 B=P0.16 (all off)");
	return HAL_GPIO_OK;
}

int hal_gpio_led_set_pattern(led_pattern_t pattern)
{
	const led_pattern_def_t *def;

	if (pattern >= ARRAY_SIZE(s_patterns)) {
		return HAL_GPIO_ERR_IO;
	}

	s_pattern = pattern;
	s_slot = 0U;
	def = &s_pattern_colors[pattern];

	if ((s_patterns[pattern] & 0x01U) != 0U) {
		led_apply_rgb(def->on_g, def->on_o, def->on_b);
	} else {
		led_apply_rgb(0U, 0U, 0U);
	}

	return HAL_GPIO_OK;
}

/* ── TS3USB221A USB data gate ────────────────────────────────────────── */

static bool s_gate_open = false;

int hal_gpio_usb_gate_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&s_usb_oe)) {
		LOG_ERR("USB switch OE GPIO (P0.08) not ready");
		return HAL_GPIO_ERR_INIT;
	}

	/* ~OE active-LOW: OUTPUT_INACTIVE => pin HIGH => gate CLOSED (safe). */
	ret = gpio_pin_configure_dt(&s_usb_oe, GPIO_OUTPUT_INACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	if (!gpio_is_ready_dt(&s_usb_s)) {
		LOG_ERR("USB switch S GPIO (P0.06) not ready");
		return HAL_GPIO_ERR_INIT;
	}

	ret = gpio_pin_configure_dt(&s_usb_s, GPIO_OUTPUT_INACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	/* Fixed routing: S=LOW selects B-port (DSC side per schematic). */
	gpio_pin_set_dt(&s_usb_s, 0);

	s_gate_open = false;
	LOG_INF("USB gate init: CLOSED (~OE HIGH), S=P0.06 LOW (B-port)");
	return HAL_GPIO_OK;
}

int hal_gpio_usb_gate_open(void)
{
	/* Active-LOW ~OE: logical 1 => physical LOW => path enabled. */
	gpio_pin_set_dt(&s_usb_oe, 1);
	s_gate_open = true;
	LOG_INF("USB gate => OPEN (data path enabled)");
	return HAL_GPIO_OK;
}

int hal_gpio_usb_gate_close(void)
{
	/* Active-LOW ~OE: logical 0 => physical HIGH => path blocked. */
	gpio_pin_set_dt(&s_usb_oe, 0);
	s_gate_open = false;
	LOG_INF("USB gate => CLOSED (data path blocked)");
	return HAL_GPIO_OK;
}

bool hal_gpio_usb_gate_is_open(void)
{
	return s_gate_open;
}

bool hal_gpio_usb_gate_is_closed(void)
{
	return !s_gate_open;
}

/* ── SE050 ENA (SE2_EN / P0.13) ──────────────────────────────────────── */

static bool s_se050_ena_on;

int hal_gpio_se050_ena_init(void)
{
	int ret;

	if (!gpio_is_ready_dt(&s_se2_en)) {
		LOG_ERR("SE2_EN GPIO (P0.13) not ready");
		return HAL_GPIO_ERR_INIT;
	}

	/* ACTIVE_HIGH: OUTPUT_ACTIVE => pin HIGH => IC2 powered. */
	ret = gpio_pin_configure_dt(&s_se2_en, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return HAL_GPIO_ERR_INIT;
	}

	s_se050_ena_on = true;
	k_sleep(K_MSEC(100));
	LOG_INF("SE2_EN (P0.13) HIGH — SE050 powered, 100 ms settle");

	return HAL_GPIO_OK;
}

bool hal_gpio_se050_ena_is_on(void)
{
	return s_se050_ena_on;
}
