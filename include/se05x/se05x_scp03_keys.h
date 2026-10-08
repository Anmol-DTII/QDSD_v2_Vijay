/**
 * @file se05x_scp03_keys.h
 * @brief Bind Platform SCP03 keys to a session before it is opened.
 */
#ifndef QDSD_SE05X_SCP03_KEYS_H
#define QDSD_SE05X_SCP03_KEYS_H

#if defined(CONFIG_PLUGANDTRUST) && defined(CONFIG_PLUGANDTRUST_SCP03)
#include "se05x_types.h"

/** which: 0 = SE050 (device trust), 1 = SE052F (DSC). */
void se05x_scp03_bind(int which, Se05xSession_t *s);
#endif

#endif /* QDSD_SE05X_SCP03_KEYS_H */
