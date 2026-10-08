/**
 * @file se05x_bus.h
 * @brief Shared Plug & Trust bus selector and cross-SE APDU lock.
 */

#ifndef QDSD_SE05X_BUS_H
#define QDSD_SE05X_BUS_H

typedef enum {
	QDSD_SE05X_BUS_SE052F = 0,
	QDSD_SE05X_BUS_SE050,
} qdsd_se05x_bus_t;

/**
 * Lock all SE05x APDU traffic and select the requested physical I2C bus.
 *
 * The NXP Zephyr port has one global i2c_dev. Every Plug & Trust operation
 * must therefore be enclosed by this lock while two SE05x sessions exist.
 */
int qdsd_se05x_bus_lock(qdsd_se05x_bus_t bus);
void qdsd_se05x_bus_unlock(void);

/** Re-apply the selected bus while the caller owns the lock. */
int qdsd_se05x_bus_select_locked(qdsd_se05x_bus_t bus);

#endif /* QDSD_SE05X_BUS_H */
