#ifndef HAL_GPIO_H
#define HAL_GPIO_H

/**
 * @file hal_gpio.h
 * @brief GPIO HAL — QDSD custom PCBA discrete I/O.
 *
 * Pin map (from boards/arm/qdsd/qdsd.dts):
 *
 *   Component              nRF GPIO   Direction   Notes
 *   TS3USB221A ~OE          P0.08      Output      Active-LOW; HIGH = gate closed
 *   TS3USB221A S            P0.06      Output      Fixed routing select at boot
 *   Status LED4 green       P0.14      Output      RGB channel
 *   Status LED4 orange      P0.15      Output      RGB channel
 *   Status LED4 blue        P0.16      Output      RGB channel
 *   SE050 ENA (SE2_EN)      P0.13      Output      IC2 pin 11; HIGH = powered
 *
 * USB gate terminology (Spec v4.0):
 *   Gate OPEN   = document-hash USB path enabled (~OE LOW).
 *   Gate CLOSED = document-hash USB path blocked (~OE HIGH, safe default).
 */

#include <stdbool.h>
#include <stdint.h>

#define HAL_GPIO_OK       0
#define HAL_GPIO_ERR_INIT -1
#define HAL_GPIO_ERR_IO   -2

typedef enum {
	LED_PATTERN_OFF = 0,
	LED_PATTERN_BOOT,          /* orange blink: booting / self-test      */
	LED_PATTERN_FAULT,         /* orange solid: self-test failed          */
	LED_PATTERN_MANUFACTURING, /* blue slow blink: not yet personalised   */
	LED_PATTERN_UNASSIGNED,    /* green blink: waiting for pairing        */
	LED_PATTERN_BOUND,         /* blue blink: paired, no certified DSC    */
	LED_PATTERN_READY,         /* green solid: ready to sign              */
	LED_PATTERN_SIGNING,       /* blue solid: DSC signature in progress   */
	LED_PATTERN_UPDATE,        /* blue fast blink: entering bootloader    */
	LED_PATTERN_COUNT
} led_pattern_t;

/* ── Status LED4 (RGB) ───────────────────────────────────────────────── */

int  hal_gpio_led_init(void);
int  hal_gpio_led_set_pattern(led_pattern_t pattern);

/* ── TS3USB221A USB data gate ────────────────────────────────────────── */

/**
 * Gate OPEN   = TS3USB221 ~OE LOW  = USB D+/D− path enabled.
 * Gate CLOSED = TS3USB221 ~OE HIGH = USB D+/D− path blocked (safe default).
 */

int  hal_gpio_usb_gate_init(void);
int  hal_gpio_usb_gate_open(void);
int  hal_gpio_usb_gate_close(void);
bool hal_gpio_usb_gate_is_open(void);
bool hal_gpio_usb_gate_is_closed(void);

/* ── SE050 ENA (SE2_EN / P0.13) ──────────────────────────────────────── */

/**
 * Drive IC2 ENA. With CONFIG_QDSD_SE050 this asserts HIGH and waits for
 * the SE050 boot settle; otherwise the pin is held LOW (powered down).
 */
int  hal_gpio_se050_ena_init(void);
bool hal_gpio_se050_ena_is_on(void);

#endif /* HAL_GPIO_H */
