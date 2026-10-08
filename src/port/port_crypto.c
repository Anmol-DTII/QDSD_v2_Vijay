/**
 * @file port_crypto.c
 * @brief port.h MCU-side cryptography on the PSA Crypto API.
 *
 * 0.6.4: moved from the mbedTLS legacy API (mbedtls_ecp_*, mbedtls_rsa_*,
 * mbedtls_gcm_*) to PSA Crypto. NCS 2.8 deprecated the legacy API and its
 * CONFIG_NORDIC_SECURITY_BACKEND / CONFIG_MBEDTLS_*_C options; NCS 3.0 builds
 * this file with CONFIG_NRF_SECURITY and the CONFIG_PSA_WANT_* options in
 * prj.conf (Oberon in software, CryptoCell CC310 where it accelerates).
 *
 * Plain C, no RTOS dependency: the same file is built into the firmware and
 * into the host test model (mbedTLS 3.6 PSA core).
 *
 * Every entry point calls crypto_ready() first: PSA refuses key operations
 * (PSA_ERROR_BAD_STATE) until psa_crypto_init() has run, while hashing may
 * work without it — a missing init shows up as self-test -2 with SHA-256
 * passing.
 *
 * What runs here and why:
 *   - SHA-256 and P-256 point checks: plain computation, nothing secret.
 *   - port_ecdsa_p256_verify: self-test and statements carrying a key that
 *     is not stored yet. Stored phone and cloud keys are checked inside the
 *     SE050 (port_pubkey_verify).
 *   - port_sig_verify: proves an imported key matches its certificate.
 *   - Ephemeral ECDH + AES-256-GCM: unwrap an institutional key (.pfx) on
 *     its way into the SE052F. The ephemeral key lives in a volatile PSA key
 *     slot and is destroyed after one use; the GCM key slot is destroyed
 *     straight after decryption.
 */
#include <errno.h>
#include <string.h>

#include <psa/crypto.h>

#include "port/port.h"

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0U) {
		*v++ = 0U;
	}
}

static int crypto_ready(void)
{
	/* Idempotent: returns PSA_SUCCESS again once initialised. */
	return (psa_crypto_init() == PSA_SUCCESS) ? 0 : -EIO;
}

/* ── Hash and P-256 ─────────────────────────────────────────────────── */

int port_sha256(const uint8_t *data, size_t len, uint8_t out[QDSD_SHA256_LEN])
{
	size_t olen = 0U;

	if (crypto_ready() != 0) {
		return -EIO;
	}
	if ((psa_hash_compute(PSA_ALG_SHA_256, data, len, out, QDSD_SHA256_LEN, &olen) !=
	     PSA_SUCCESS) || (olen != QDSD_SHA256_LEN)) {
		return -EIO;
	}
	return 0;
}

static psa_hash_operation_t s_hash = PSA_HASH_OPERATION_INIT;

int port_sha256_begin(void)
{
	(void)psa_hash_abort(&s_hash);
	s_hash = psa_hash_operation_init();
	if (crypto_ready() != 0) {
		return -EIO;
	}
	return (psa_hash_setup(&s_hash, PSA_ALG_SHA_256) == PSA_SUCCESS) ? 0 : -EIO;
}

int port_sha256_update(const uint8_t *data, size_t len)
{
	return (psa_hash_update(&s_hash, data, len) == PSA_SUCCESS) ? 0 : -EIO;
}

int port_sha256_finish(uint8_t out[QDSD_SHA256_LEN])
{
	size_t olen = 0U;

	if ((psa_hash_finish(&s_hash, out, QDSD_SHA256_LEN, &olen) != PSA_SUCCESS) ||
	    (olen != QDSD_SHA256_LEN)) {
		(void)psa_hash_abort(&s_hash);
		return -EIO;
	}
	return 0;
}

/* Imports an uncompressed P-256 public key; PSA checks the point is on the curve. */
static int p256_import(const uint8_t pub[QDSD_P256_PUB_LEN], psa_key_id_t *id)
{
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st;

	if (pub[0] != 0x04U) {
		return -EINVAL;
	}
	psa_set_key_type(&at, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&at, 256U);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&at, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	st = psa_import_key(&at, pub, QDSD_P256_PUB_LEN, id);
	psa_reset_key_attributes(&at);
	if (st == PSA_SUCCESS) {
		return 0;
	}
	return (st == PSA_ERROR_INVALID_ARGUMENT) ? -EINVAL : -EIO;
}

int port_ecdsa_p256_verify(const uint8_t pub[QDSD_P256_PUB_LEN],
			   const uint8_t hash[QDSD_SHA256_LEN],
			   const uint8_t sig[QDSD_P256_SIG_LEN])
{
	psa_key_id_t id = PSA_KEY_ID_NULL;
	int rc = -EPERM;

	if ((crypto_ready() != 0) || (p256_import(pub, &id) != 0)) {
		return -EPERM;
	}
	if (psa_verify_hash(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, QDSD_SHA256_LEN, sig,
			    QDSD_P256_SIG_LEN) == PSA_SUCCESS) {
		rc = 0;
	}
	(void)psa_destroy_key(id);
	return rc;
}

int port_p256_pubkey_check(const uint8_t pub[QDSD_P256_PUB_LEN])
{
	psa_key_id_t id = PSA_KEY_ID_NULL;
	int rc;

	if (crypto_ready() != 0) {
		return -EIO;
	}
	rc = p256_import(pub, &id);
	if (rc == 0) {
		(void)psa_destroy_key(id);
	}
	return rc;
}

/* ── DSC signature check (imported keys) ────────────────────────────── */

/*
 * PSA imports RSA public keys as DER RSAPublicKey:
 *   SEQUENCE { INTEGER n, INTEGER e }   with e = 65537.
 * A 2048-bit modulus has its top bit set, so n needs a 00 pad byte.
 */
#define RSA_DER_LEN (4U + 4U + 1U + QDSD_RSA_MOD_LEN + 5U)

static int rsa2048_verify(const uint8_t mod[QDSD_RSA_MOD_LEN], const uint8_t hash[32],
			  const uint8_t *sig, size_t sig_len)
{
	static const uint8_t k_seq[4] = { 0x30, 0x82, 0x01, 0x0A };
	static const uint8_t k_int_n[5] = { 0x02, 0x82, 0x01, 0x01, 0x00 };
	static const uint8_t k_int_e[5] = { 0x02, 0x03, 0x01, 0x00, 0x01 };
	uint8_t der[RSA_DER_LEN];
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	psa_status_t st;
	int rc = -EPERM;

	if ((sig_len != QDSD_RSA_MOD_LEN) || ((mod[0] & 0x80U) == 0U) ||
	    ((mod[QDSD_RSA_MOD_LEN - 1U] & 0x01U) == 0U) || (crypto_ready() != 0)) {
		return -EPERM; /* not a 2048-bit odd modulus */
	}
	memcpy(der, k_seq, sizeof(k_seq));
	memcpy(&der[4], k_int_n, sizeof(k_int_n));
	memcpy(&der[9], mod, QDSD_RSA_MOD_LEN);
	memcpy(&der[9U + QDSD_RSA_MOD_LEN], k_int_e, sizeof(k_int_e));

	psa_set_key_type(&at, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
	psa_set_key_bits(&at, 2048U);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&at, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));
	st = psa_import_key(&at, der, sizeof(der), &id);
	psa_reset_key_attributes(&at);
	if (st != PSA_SUCCESS) {
		return -EPERM;
	}
	if (psa_verify_hash(id, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256), hash, 32U, sig,
			    sig_len) == PSA_SUCCESS) {
		rc = 0;
	}
	(void)psa_destroy_key(id);
	return rc;
}

int port_sig_verify(uint8_t alg, const uint8_t *pub, size_t pub_len,
		    const uint8_t hash[QDSD_SHA256_LEN], const uint8_t *sig, size_t sig_len)
{
	if ((pub == NULL) || (hash == NULL) || (sig == NULL)) {
		return -EINVAL;
	}
	if (alg == QDSD_ALG_P256) {
		if ((pub_len != QDSD_P256_PUB_LEN) || (sig_len != QDSD_P256_SIG_LEN)) {
			return -EPERM;
		}
		return port_ecdsa_p256_verify(pub, hash, sig);
	}
	if ((alg == QDSD_ALG_RSA2048) && (pub_len == QDSD_RSA_MOD_LEN)) {
		return rsa2048_verify(pub, hash, sig, sig_len);
	}
	return -EINVAL;
}

/* ── Key transport for .pfx import ──────────────────────────────────── */

static psa_key_id_t s_eph = PSA_KEY_ID_NULL;

void port_ecdh_clear(void)
{
	if (s_eph != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(s_eph); /* PSA wipes the key material */
		s_eph = PSA_KEY_ID_NULL;
	}
}

int port_ecdh_begin(uint8_t pub[QDSD_P256_PUB_LEN])
{
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	size_t olen = 0U;
	psa_status_t st;

	port_ecdh_clear();
	if (crypto_ready() != 0) {
		return -EIO;
	}
	psa_set_key_type(&at, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&at, 256U);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&at, PSA_ALG_ECDH);
	st = psa_generate_key(&at, &s_eph);
	psa_reset_key_attributes(&at);
	if (st != PSA_SUCCESS) {
		s_eph = PSA_KEY_ID_NULL;
		return -EIO;
	}
	if ((psa_export_public_key(s_eph, pub, QDSD_P256_PUB_LEN, &olen) != PSA_SUCCESS) ||
	    (olen != QDSD_P256_PUB_LEN)) {
		port_ecdh_clear();
		return -EIO;
	}
	return 0;
}

int port_ecdh_finish(const uint8_t peer[QDSD_P256_PUB_LEN], uint8_t z[32])
{
	size_t olen = 0U;
	psa_status_t st;
	int rc;

	if (s_eph == PSA_KEY_ID_NULL) {
		return -ENOENT;
	}
	if (peer[0] != 0x04U) {
		port_ecdh_clear(); /* one use only */
		return -EINVAL;
	}
	/* Shared secret = X coordinate; PSA rejects points not on the curve. */
	st = psa_raw_key_agreement(PSA_ALG_ECDH, s_eph, peer, QDSD_P256_PUB_LEN, z, 32U, &olen);
	if ((st == PSA_SUCCESS) && (olen == 32U)) {
		rc = 0;
	} else {
		wipe(z, 32U);
		rc = (st == PSA_ERROR_INVALID_ARGUMENT) ? -EINVAL : -EIO;
	}
	port_ecdh_clear(); /* one use only */
	return rc;
}

/*
 * The tag must follow the ciphertext in memory (ct ‖ tag), as it does in
 * IMPORT_DATA's wrapped-key TLV: PSA's one-shot AEAD takes them as one input.
 */
int port_aes256gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
	psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	size_t olen = 0U;
	psa_status_t st;

	if ((tag != &ct[len]) || (crypto_ready() != 0)) {
		return -EIO;
	}
	psa_set_key_type(&at, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&at, 256U);
	psa_set_key_usage_flags(&at, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&at, PSA_ALG_GCM);
	st = psa_import_key(&at, key, 32U, &id);
	psa_reset_key_attributes(&at);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}
	st = psa_aead_decrypt(id, PSA_ALG_GCM, iv, 12U, aad, aad_len, ct, len + 16U, pt, len,
			      &olen);
	(void)psa_destroy_key(id);
	if ((st == PSA_SUCCESS) && (olen == len)) {
		return 0;
	}
	wipe(pt, len);
	return (st == PSA_ERROR_INVALID_SIGNATURE) ? -EBADMSG : -EIO;
}
