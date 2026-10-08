/**
 * @file port_trust.c
 * @brief port.h SE050 functions: device key, stored public keys, counters, state.
 *
 * Phone and cloud signatures are checked inside the SE050 against the stored
 * key (ECDSAVerify), so the comparison happens in the element that holds the
 * keys. CONFIG_QDSD_VERIFY_IN_SE=n falls back to mbedTLS on the MCU (bring-up
 * aid only).
 */
#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "port/port.h"
#include "port/port_se.h"
#include "qdsd/qdsd_config.h"
#include "qdsd/qdsd_objids.h"
#include "se05x/se05x_link.h"

LOG_MODULE_REGISTER(port_trust, LOG_LEVEL_INF);

static uint32_t pub_obj(port_pubkey_t which)
{
	return (which == PORT_PUBKEY_CMD) ? OID_CMD_PUB : OID_ACT_PUB;
}

/* ── SE050 ──────────────────────────────────────────────────────────── */

static int devkey_ensure_locked(se_handle_t *h)
{
	bool ex = false;
	int rc = se_exists(h, OID_DEVKEY, &ex);

	if (rc != 0) {
		return rc;
	}
	if (ex) {
		return 0;
	}
	LOG_INF("Generating device key in SE050");
	return se_gen_p256(h, OID_DEVKEY);
}

int port_devkey_ensure(void)
{
	return WITH_SE(QDSD_SE_DEV, h, devkey_ensure_locked(h));
}

int port_devkey_pubkey(uint8_t pub[QDSD_P256_PUB_LEN])
{
	return WITH_SE(QDSD_SE_DEV, h, se_read_p256_pub(h, OID_DEVKEY, pub));
}

int port_devkey_sign(const uint8_t hash[QDSD_SHA256_LEN], uint8_t sig[QDSD_P256_SIG_LEN])
{
	return WITH_SE(QDSD_SE_DEV, h, se_sign_sha256(h, OID_DEVKEY, hash, sig));
}

int port_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN])
{
	return WITH_SE(QDSD_SE_DEV, h, se_read_uid(h, uid));
}

int port_devkey_vendor_attest(const uint8_t *fresh, size_t fresh_len, uint8_t *out,
			      size_t *out_len)
{
	if (fresh_len < 16U) {
		return -EINVAL;
	}
	/* SE05x freshness is 16 bytes: the first 16 bytes of the challenge. */
	return WITH_SE(QDSD_SE_DEV, h, se_read_attested(h, OID_DEVKEY, fresh, out, out_len));
}

int port_pubkey_write(port_pubkey_t which, const uint8_t pub[QDSD_P256_PUB_LEN])
{
	return WITH_SE(QDSD_SE_DEV, h, se_write_p256_pub(h, pub_obj(which), pub));
}

int port_pubkey_read(port_pubkey_t which, uint8_t pub[QDSD_P256_PUB_LEN])
{
	return WITH_SE(QDSD_SE_DEV, h, se_read_p256_pub(h, pub_obj(which), pub));
}

int port_pubkey_delete(port_pubkey_t which)
{
	return WITH_SE(QDSD_SE_DEV, h, se_delete(h, pub_obj(which)));
}

int port_pubkey_verify(port_pubkey_t which, const uint8_t hash[QDSD_SHA256_LEN],
		       const uint8_t sig[QDSD_P256_SIG_LEN])
{
#if defined(CONFIG_QDSD_VERIFY_IN_SE)
	int rc = WITH_SE(QDSD_SE_DEV, h, se_verify_sha256(h, pub_obj(which), hash, sig));

	/* -EPERM (bad signature) is an answer, not a link failure. */
	return rc;
#else
	uint8_t pub[QDSD_P256_PUB_LEN];
	int rc = port_pubkey_read(which, pub);

	if (rc != 0) {
		return rc;
	}
	return (port_ecdsa_p256_verify(pub, hash, sig) == 0) ? 0 : -EPERM;
#endif
}

int port_counter_ensure(port_counter_t c)
{
	return WITH_SE(QDSD_SE_DEV, h, se_counter_create(h, OID_CTR_BASE + (uint32_t)c));
}

int port_counter_read(port_counter_t c, uint32_t *value)
{
	return WITH_SE(QDSD_SE_DEV, h, se_counter_read(h, OID_CTR_BASE + (uint32_t)c, value));
}

int port_counter_inc(port_counter_t c)
{
	return WITH_SE(QDSD_SE_DEV, h, se_counter_inc(h, OID_CTR_BASE + (uint32_t)c));
}

int port_state_read(uint8_t *buf, size_t cap, size_t *len)
{
	return WITH_SE(QDSD_SE_DEV, h, se_binary_read(h, OID_STATE, buf, cap, len));
}

int port_state_write(const uint8_t *buf, size_t len)
{
	return WITH_SE(QDSD_SE_DEV, h, se_binary_write(h, OID_STATE, buf, len));
}
