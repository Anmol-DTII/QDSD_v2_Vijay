#ifndef SE05X_SMLOG_SHIM_H
#define SE05X_SMLOG_SHIM_H

/**
 * @file se052f_pnt_smport_shim.h
 * @brief PlugNTrust SMLOG shims for application TU only.
 *
 * Include AFTER exactly one LOG_MODULE_REGISTER() in the same .c file.
 * Do NOT include sm_port.h here — it adds a second LOG_MODULE_* and breaks
 * the build on NCS v3 / Zephyr 4.x.
 */

#include <zephyr/logging/log.h>

#define SMLOG_I(...) LOG_INF(__VA_ARGS__)
#define SMLOG_E(...) LOG_ERR(__VA_ARGS__)
#define SMLOG_W(...) LOG_WRN(__VA_ARGS__)
#define SMLOG_D(...) LOG_DBG(__VA_ARGS__)
#define SMLOG_AU8_D(BUF, LEN) LOG_HEXDUMP_DBG(BUF, LEN, "")
#define SMLOG_MAU8_D(MSG, BUF, LEN) LOG_HEXDUMP_DBG(BUF, LEN, MSG)

#endif /* SE05X_SMLOG_SHIM_H */
