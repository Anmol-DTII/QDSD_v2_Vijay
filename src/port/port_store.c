/**
 * @file port_store.c
 * @brief port.h records inside the secure elements, and their factory reset.
 *
 * Certificates, slot records and signing receipts are SE05x binary objects
 * (docs/OBJECT_IDS.md). A write of up to SE_BINARY_CHUNK bytes is one
 * WriteBinary APDU, which the applet applies all or nothing; longer writes are
 * split and the core orders them so a power cut never leaves a record that
 * looks valid but is not (PROTOCOL.md §5).
 *
 * Factory reset: each element holds a FACTORY_RESET UserID object (NXP
 * reserved id 0x7FFF0205) whose 16-byte secret only DTI holds. DeleteAll is
 * only accepted inside a session authenticated with it, so the element itself
 * enforces the gate, not this firmware.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "port/port.h"
#include "port/port_se.h"
#include "qdsd/qdsd_config.h"
#include "qdsd/qdsd_objids.h"
#include "se05x/se05x_link.h"

LOG_MODULE_REGISTER(port_store, LOG_LEVEL_INF);

BUILD_ASSERT(PORT_OBJ_ATOMIC_MAX == SE_BINARY_CHUNK,
	     "core and link must agree on the atomic write size");

static int where(port_obj_t o, uint8_t idx, qdsd_se_t *se, uint32_t *id)
{
	switch (o) {
	case PORT_OBJ_DEVICE_CERT:
		if (idx != 0U) {
			return -EINVAL;
		}
		*se = QDSD_SE_DEV;
		*id = OID_DEVICE_CERT;
		return 0;
	case PORT_OBJ_RECEIPT:
		if (idx >= QDSD_RECEIPT_RING) {
			return -EINVAL;
		}
		*se = QDSD_SE_DEV;
		*id = OID_RECEIPT_BASE + idx;
		return 0;
	case PORT_OBJ_SLOT_REC:
		if (idx >= QDSD_DSC_SLOTS) {
			return -EINVAL;
		}
		*se = QDSD_SE_DSC;
		*id = OID_SLOT_REC_BASE + idx;
		return 0;
	case PORT_OBJ_SLOT_CERT:
		if (idx >= (2U * QDSD_DSC_SLOTS)) { /* two banks per slot */
			return -EINVAL;
		}
		*se = QDSD_SE_DSC;
		*id = OID_SLOT_CRT_BASE + idx;
		return 0;
	default:
		return -EINVAL;
	}
}

static int write_chunks(se_handle_t *h, uint32_t id, size_t off, const uint8_t *buf, size_t len)
{
	size_t done = 0U;
	int rc;

	while (done < len) {
		size_t n = MIN(len - done, (size_t)SE_BINARY_CHUNK);

		rc = se_binary_write_at(h, id, off + done, &buf[done], n);
		if (rc != 0) {
			return rc;
		}
		done += n;
	}
	return 0;
}

static int read_locked(se_handle_t *h, uint32_t id, uint8_t *buf, size_t cap, size_t *len)
{
	size_t size = 0U;
	size_t done = 0U;
	int rc = se_binary_size(h, id, &size);

	if (rc != 0) {
		return rc;
	}
	*len = size;
	if (buf == NULL) {
		return 0;
	}
	if (cap < size) {
		return -ENOSPC;
	}
	while (done < size) {
		size_t n = MIN(size - done, (size_t)SE_BINARY_CHUNK);

		rc = se_binary_read_at(h, id, done, &buf[done], n);
		if (rc != 0) {
			return rc;
		}
		done += n;
	}
	return 0;
}

static int write_locked(se_handle_t *h, uint32_t id, const uint8_t *buf, size_t len)
{
	size_t size = 0U;
	size_t first;
	int rc = se_binary_size(h, id, &size);

	if ((rc == 0) && (size == len)) {
		return write_chunks(h, id, 0U, buf, len); /* in place */
	}
	if (rc == 0) {
		rc = se_delete(h, id);
		if ((rc != 0) && (rc != -ENOENT)) {
			return rc;
		}
	} else if (rc != -ENOENT) {
		return rc;
	}
	first = MIN(len, (size_t)SE_BINARY_CHUNK);
	rc = se_binary_create(h, id, len, buf, first);
	if (rc != 0) {
		return rc;
	}
	return write_chunks(h, id, first, &buf[first], len - first);
}

static int patch_locked(se_handle_t *h, uint32_t id, size_t off, const uint8_t *buf, size_t len)
{
	size_t size = 0U;
	int rc = se_binary_size(h, id, &size);

	if (rc != 0) {
		return rc;
	}
	if ((off > size) || (len > (size - off))) {
		return -EINVAL;
	}
	return write_chunks(h, id, off, buf, len);
}

int port_obj_read(port_obj_t o, uint8_t idx, uint8_t *buf, size_t cap, size_t *len)
{
	qdsd_se_t se;
	uint32_t id;

	if (where(o, idx, &se, &id) != 0) {
		return -EINVAL;
	}
	return WITH_SE(se, h, read_locked(h, id, buf, cap, len));
}

int port_obj_write(port_obj_t o, uint8_t idx, const uint8_t *buf, size_t len)
{
	qdsd_se_t se;
	uint32_t id;

	if ((where(o, idx, &se, &id) != 0) || (len == 0U) || (len > 0x7FFFU)) {
		return -EINVAL;
	}
	return WITH_SE(se, h, write_locked(h, id, buf, len));
}

int port_obj_patch(port_obj_t o, uint8_t idx, size_t off, const uint8_t *buf, size_t len)
{
	qdsd_se_t se;
	uint32_t id;

	if ((where(o, idx, &se, &id) != 0) || (len == 0U)) {
		return -EINVAL;
	}
	return WITH_SE(se, h, patch_locked(h, id, off, buf, len));
}

int port_obj_delete(port_obj_t o, uint8_t idx)
{
	qdsd_se_t se;
	uint32_t id;

	if (where(o, idx, &se, &id) != 0) {
		return -EINVAL;
	}
	return WITH_SE(se, h, se_delete(h, id));
}

/* ── Factory reset ──────────────────────────────────────────────────── */

static qdsd_se_t link_se(port_se_t se)
{
	return (se == PORT_SE_DEV) ? QDSD_SE_DEV : QDSD_SE_DSC;
}

int port_wipe_auth_set(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	return WITH_SE(link_se(se), h,
		       se_userid_write(h, OID_FACTORY_RESET, secret, QDSD_WIPE_SECRET_LEN));
}

static int check_locked(se_handle_t *h, const uint8_t *secret)
{
	int rc = se_user_session_open(h, OID_FACTORY_RESET, secret, QDSD_WIPE_SECRET_LEN);

	if (rc == 0) {
		se_user_session_close(h);
	}
	return rc;
}

int port_wipe_auth_check(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	return WITH_SE(link_se(se), h, check_locked(h, secret));
}

int port_se_wipe(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	se_handle_t *h = se_acquire(link_se(se));
	int rc;

	if (h == NULL) {
		return -EIO;
	}
	rc = se_user_session_open(h, OID_FACTORY_RESET, secret, QDSD_WIPE_SECRET_LEN);
	if (rc == -ENOENT) {
		rc = -EACCES;
	}
	if (rc == 0) {
		LOG_WRN("Factory reset of %s", (se == PORT_SE_DEV) ? "SE050" : "SE052F");
		rc = se_user_delete_all(h);
	}
	se_user_session_close(h);
	/* Start the next command from a fresh Platform SCP03 session. */
	se_release(h, false);
	return rc;
}

int port_se_prepare(port_se_t se)
{
	return WITH_SE(link_se(se), h, se_create_p256_curve(h));
}
