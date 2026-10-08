#ifndef HAL_POWER_H
#define HAL_POWER_H

/**
 * @file hal_power.h
 * @brief Boot-time power and enable-line safe defaults.
 *
 * Applies safe GPIO states before other subsystems start:
 *   - USB data gate closed (TS3USB221 ~OE deasserted)
 *   - RGB status LED off
 *   - SE050 powered (SE2_EN) for the device-trust element
 */

#define HAL_POWER_OK       0
#define HAL_POWER_ERR_INIT -1

/**
 * @brief Apply all safe-default power/enable/GPIO states at boot.
 *
 * Must be called before I2C transactions or USB session logic.
 *
 * @return HAL_POWER_OK on success, negative on failure.
 */
int hal_power_init(void);

#endif /* HAL_POWER_H */
