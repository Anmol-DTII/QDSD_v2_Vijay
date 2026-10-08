/**
 * @file port_dsc.c
 * @brief port.h SE052F functions: DSC keys (generated or imported),
 *        their public parts, the SE052F's own attestation and unique id.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "port/port.h"
#include "port/port_se.h"
#include "qdsd/qdsd_config.h"
#include "qdsd/qdsd_objids.h"
#include "se05x/se05x_link.h"

LOG_MODULE_REGISTER(port_dsc, LOG_LEVEL_INF);

static uint32_t key_id(uint8_t slot)
{
	return OID_DSC_KEY_BASE + slot;
}

static bool alg_ok(uint8_t alg)
{
	return (alg == QDSD_ALG_P256) || (alg == QDSD_ALG_RSA2048);
}

static int pub_locked(se_handle_t *h, uint8_t slot, uint8_t alg, uint8_t *pub, size_t *len)
{
	int rc;

	if (alg == QDSD_ALG_RSA2048) {
		rc = se_read_rsa2048_mod(h, key_id(slot), pub);
		*len = QDSD_RSA_MOD_LEN;
		return rc;
	}
	rc = se_read_p256_pub(h, key_id(slot), pub);
	*len = QDSD_P256_PUB_LEN;
	return rc;
}

static int generate_locked(se_handle_t *h, uint8_t slot, uint8_t alg, uint8_t *pub, size_t *len)
{
	int rc = (alg == QDSD_ALG_RSA2048) ? se_gen_rsa2048(h, key_id(slot)) :
					      se_gen_p256(h, key_id(slot));

	return (rc == 0) ? pub_locked(h, slot, alg, pub, len) : rc;
}

int port_dsc_generate(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len)
{
	size_t need = (alg == QDSD_ALG_RSA2048) ? QDSD_RSA_MOD_LEN : QDSD_P256_PUB_LEN;

	if ((slot >= QDSD_DSC_SLOTS) || (cap < need) || !alg_ok(alg)) {
		return -EINVAL;
	}
	return WITH_SE(QDSD_SE_DSC, h, generate_locked(h, slot, alg, pub, len));
}

int port_dsc_pubkey(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len)
{
	size_t need = (alg == QDSD_ALG_RSA2048) ? QDSD_RSA_MOD_LEN : QDSD_P256_PUB_LEN;

	if ((slot >= QDSD_DSC_SLOTS) || !alg_ok(alg)) {
		return -EINVAL;
	}
	if (cap < need) {
		return -ENOSPC;
	}
	return WITH_SE(QDSD_SE_DSC, h, pub_locked(h, slot, alg, pub, len));
}

int port_dsc_sign(uint8_t slot, uint8_t alg, const uint8_t hash[QDSD_SHA256_LEN],
		  uint8_t *sig, size_t cap, size_t *len)
{
	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	if (alg == QDSD_ALG_RSA2048) {
		if (cap < QDSD_RSA_MOD_LEN) {
			return -ENOSPC;
		}
		*len = QDSD_RSA_MOD_LEN;
		return WITH_SE(QDSD_SE_DSC, h, se_sign_rsa2048_sha256(h, key_id(slot), hash, sig));
	}
	if (cap < QDSD_P256_SIG_LEN) {
		return -ENOSPC;
	}
	*len = QDSD_P256_SIG_LEN;
	return WITH_SE(QDSD_SE_DSC, h, se_sign_sha256(h, key_id(slot), hash, sig));
}

int port_dsc_delete(uint8_t slot)
{
	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	return WITH_SE(QDSD_SE_DSC, h, se_delete(h, key_id(slot)));
}

int port_dsc_import(uint8_t slot, uint8_t alg, const uint8_t *priv, size_t priv_len,
		    const uint8_t *pub, size_t pub_len)
{
	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	if (alg == QDSD_ALG_P256) {
		if ((priv_len != 32U) || (pub_len != QDSD_P256_PUB_LEN)) {
			return -EINVAL;
		}
		return WITH_SE(QDSD_SE_DSC, h, se_write_p256_pair(h, key_id(slot), priv, pub));
	}
	if ((alg == QDSD_ALG_RSA2048) && (priv_len == 640U) && (pub_len == QDSD_RSA_MOD_LEN)) {
		return WITH_SE(QDSD_SE_DSC, h, se_write_rsa2048_crt(h, key_id(slot), priv, pub));
	}
	return -EINVAL;
}

int port_dsc_vendor_attest(uint8_t slot, uint8_t alg, const uint8_t fresh[16],
			   uint8_t *out, size_t *out_len)
{
	int rc;

	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	/*
	 * The SE052F's own NXP attestation key signs the key object's public
	 * part and attributes (origin: generated inside or written from outside).
	 * BRINGUP: attested read of an RSA key object; if the applet refuses it,
	 * the core omits the vendor proof for RSA keys (KEY_STATUS still says
	 * everything, signed by the device key).
	 */
	(void)alg;
	rc = WITH_SE(QDSD_SE_DSC, h, se_read_attested(h, key_id(slot), fresh, out, out_len));
	if ((rc != 0) && (alg == QDSD_ALG_RSA2048)) {
		LOG_WRN("SE052F attested read of RSA key refused (%d)", rc);
		return -ENOTSUP;
	}
	return rc;
}

int port_dsc_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN])
{
	return WITH_SE(QDSD_SE_DSC, h, se_read_uid(h, uid));
}
