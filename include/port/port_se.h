/**
 * @file port_se.h
 * @brief Helper shared by the device port files (src/port): run one
 *        secure-element operation with the bus held.
 */
#ifndef QDSD_PORT_SE_H
#define QDSD_PORT_SE_H

#include <errno.h>

#include "se05x/se05x_link.h"

/*
 * Run expr with an acquired session. Answers from the element (0, -ENOENT,
 * -EPERM, -EACCES) keep the session; anything else drops it so the next call
 * re-opens it.
 */
#define WITH_SE(which, h, expr)                                                       \
	({                                                                            \
		se_handle_t *h = se_acquire(which);                                   \
		int _rc = -EIO;                                                       \
		if (h != NULL) {                                                      \
			_rc = (expr);                                                 \
			se_release(h, (_rc == 0) || (_rc == -ENOENT) || (_rc == -EPERM) || \
					      (_rc == -EACCES));                      \
		}                                                                     \
		_rc;                                                                  \
	})

#endif /* QDSD_PORT_SE_H */
