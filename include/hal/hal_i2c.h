#ifndef HAL_I2C_H
#define HAL_I2C_H

/**
 * @file hal_i2c.h
 * @brief I2C bus HAL — thin wrapper over Zephyr TWIM drivers.
 *
 * Bus assignment (qdsd board):
 *   i2c0 (P0.27/P0.26) — SE052F secure element (IC1), address 0x48
 *   i2c1 (P1.01/P1.02) — SE050 device-trust SE (IC2)
 */

#include <stdint.h>
#include <stdbool.h>

#define HAL_I2C_OK           0
#define HAL_I2C_ERR_INIT    -1
#define HAL_I2C_ERR_NACK    -2
#define HAL_I2C_ERR_TIMEOUT -3

/** SE052F default 7-bit I2C address on i2c0. */
#define HAL_I2C_ADDR_SE052F  0x48U

/** SE050 default 7-bit I2C address on i2c1. */
#define HAL_I2C_ADDR_SE050   0x48U

typedef enum {
	HAL_I2C_BUS_SE052F = 0,
	HAL_I2C_BUS_SE050  = 1,
} hal_i2c_bus_t;

/** @brief Initialise I2C0 (SE052F) and I2C1 (SE050). */
int hal_i2c_init(void);

/** @brief Probe a device address on the selected bus. */
bool hal_i2c_device_present(hal_i2c_bus_t bus, uint8_t addr);

/**
 * @brief Scan 0x08–0x77 on a bus, logging every address that ACKs.
 *
 * Bring-up / PCBA diagnostics only. Do not call while a Plug & Trust T=1
 * session is open on that bus — an address read corrupts protocol state.
 *
 * @return Number of responding addresses.
 */
int hal_i2c_scan(hal_i2c_bus_t bus);

/** @brief Recover TWIM bus after a stuck transaction (SE052F / PnT safe fallback). */
int hal_i2c_recover(hal_i2c_bus_t bus);

/** @brief Write bytes on i2c0 (SE052F bus). */
int hal_i2c_write(uint8_t addr, const uint8_t *buf, uint16_t len);

/** @brief Read bytes on i2c0 (SE052F bus). */
int hal_i2c_read(uint8_t addr, uint8_t *buf, uint16_t len);

/** @brief Write-then-read on i2c0 (SE052F bus). */
int hal_i2c_write_read(uint8_t addr,
		       const uint8_t *wr_buf, uint16_t wr_len,
		       uint8_t *rd_buf, uint16_t rd_len);

#endif /* HAL_I2C_H */
