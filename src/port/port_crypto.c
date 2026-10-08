/**
 * @file port_crypto.c
 * @brief port.h MCU-side cryptography on mbedTLS.
 *
 * Plain C over the mbedTLS legacy API, with no RTOS dependency, so the same
 * file is built into the firmware and into the host test model. Randomness
 * comes from port_random() (CSPRNG on the nRF52840, seeded DRBG on host).
 *
 * What runs here and why:
 *   - SHA-256 and P-256 point checks: plain computation, nothing secret.
 *   - port_ecdsa_p256_verify: self-test and statements carrying a key that
 *     is not stored yet. Stored phone and cloud keys are checked inside the
 *     SE050 (port_pubkey_verify).
 *   - port_sig_verify: proves an imported key matches its certificate.
 *   - Ephemeral ECDH + AES-256-GCM: unwrap an institutional key (.pfx) on
 *     its way into the SE052F. The ephemeral private key and the shared
 *     secret are wiped as soon as they are used.
 */
#include <errno.h>
#include <string.h>

#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

#include <psa/crypto.h>

#include "port/port.h"

static int rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return (port_random(out, len) == 0) ? 0 : -1;
}

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0U) {
		*v++ = 0U;
	}
}

/* ── Hash and P-256 ─────────────────────────────────────────────────── */

int port_sha256(const uint8_t *data, size_t len, uint8_t out[QDSD_SHA256_LEN])
{
	return (mbedtls_sha256(data, len, out, 0) == 0) ? 0 : -EIO;
}

static int load_point(mbedtls_ecp_group *grp, mbedtls_ecp_point *q, const uint8_t pub[65])
{
	if (pub[0] != 0x04U) {
		return -EINVAL;
	}
	if (mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
		return -EIO;
	}
	if (mbedtls_ecp_point_read_binary(grp, q, pub, QDSD_P256_PUB_LEN) != 0) {
		return -EINVAL;
	}
	return (mbedtls_ecp_check_pubkey(grp, q) == 0) ? 0 : -EINVAL;
}

int port_ecdsa_p256_verify(const uint8_t pub[QDSD_P256_PUB_LEN],
			   const uint8_t hash[QDSD_SHA256_LEN],
			   const uint8_t sig[QDSD_P256_SIG_LEN])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	mbedtls_mpi r;
	mbedtls_mpi s;
	int rc = -EPERM;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	if ((load_point(&grp, &q, pub) == 0) && (mbedtls_mpi_read_binary(&r, sig, 32) == 0) &&
	    (mbedtls_mpi_read_binary(&s, sig + 32, 32) == 0) &&
	    (mbedtls_ecdsa_verify(&grp, hash, QDSD_SHA256_LEN, &q, &r, &s) == 0)) {
		rc = 0;
	}
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int port_p256_pubkey_check(const uint8_t pub[QDSD_P256_PUB_LEN])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	int rc;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	rc = load_point(&grp, &q, pub);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

/* ── DSC signature check (imported keys) ────────────────────────────── */

static int rsa2048_verify(const uint8_t mod[QDSD_RSA_MOD_LEN], const uint8_t hash[32],
			  const uint8_t *sig, size_t sig_len)
{
	static const uint8_t e[3] = { 0x01, 0x00, 0x01 };
	mbedtls_rsa_context rsa;
	int rc = -EPERM;

	if (sig_len != QDSD_RSA_MOD_LEN) {
		return -EPERM;
	}
	mbedtls_rsa_init(&rsa);
	if ((mbedtls_rsa_import_raw(&rsa, mod, QDSD_RSA_MOD_LEN, NULL, 0, NULL, 0, NULL, 0, e,
				    sizeof(e)) == 0) &&
	    (mbedtls_rsa_complete(&rsa) == 0) && (mbedtls_rsa_check_pubkey(&rsa) == 0) &&
	    (mbedtls_rsa_pkcs1_verify(&rsa, MBEDTLS_MD_SHA256, 32, hash, sig) == 0)) {
		rc = 0;
	}
	mbedtls_rsa_free(&rsa);
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

static struct {
	bool    live;
	uint8_t d[32];
} s_eph;

void port_ecdh_clear(void)
{
	wipe(&s_eph, sizeof(s_eph));
}

int port_ecdh_begin(uint8_t pub[QDSD_P256_PUB_LEN])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	mbedtls_mpi d;
	size_t olen = 0U;
	int rc = -EIO;

	port_ecdh_clear();
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	mbedtls_mpi_init(&d);
	if ((mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0) &&
	    (mbedtls_ecp_gen_keypair(&grp, &d, &q, rng, NULL) == 0) &&
	    (mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub,
					    QDSD_P256_PUB_LEN) == 0) &&
	    (olen == QDSD_P256_PUB_LEN) && (mbedtls_mpi_write_binary(&d, s_eph.d, 32) == 0)) {
		s_eph.live = true;
		rc = 0;
	}
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	if (rc != 0) {
		port_ecdh_clear();
	}
	return rc;
}

int port_ecdh_finish(const uint8_t peer[QDSD_P256_PUB_LEN], uint8_t z[32])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point q;
	mbedtls_ecp_point s;
	mbedtls_mpi d;
	uint8_t pt[QDSD_P256_PUB_LEN];
	size_t olen = 0U;
	int rc = -EIO;

	if (!s_eph.live) {
		return -ENOENT;
	}
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&q);
	mbedtls_ecp_point_init(&s);
	mbedtls_mpi_init(&d);
	if (load_point(&grp, &q, peer) != 0) {
		rc = -EINVAL;
	} else if ((mbedtls_mpi_read_binary(&d, s_eph.d, 32) == 0) &&
		   (mbedtls_ecp_mul(&grp, &s, &d, &q, rng, NULL) == 0) &&
		   (mbedtls_ecp_is_zero(&s) == 0) &&
		   (mbedtls_ecp_point_write_binary(&grp, &s, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pt,
						   sizeof(pt)) == 0) &&
		   (olen == sizeof(pt))) {
		memcpy(z, &pt[1], 32U); /* shared secret = X coordinate */
		rc = 0;
	}
	wipe(pt, sizeof(pt));
	mbedtls_mpi_free(&d);
	mbedtls_ecp_point_free(&s);
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_group_free(&grp);
	port_ecdh_clear(); /* one use only */
	return rc;
}

int port_aes256gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	size_t n = 0U;
	size_t m = 0U;
	psa_status_t st;

	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_GCM);

	st = psa_import_key(&attr, key, 32, &id);
	if (st == PSA_SUCCESS) {
		st = psa_aead_decrypt_setup(&op, id, PSA_ALG_GCM);
	}
	if (st == PSA_SUCCESS) {
		st = psa_aead_set_nonce(&op, iv, 12);
	}
	if ((st == PSA_SUCCESS) && (aad_len > 0U)) {
		st = psa_aead_update_ad(&op, aad, aad_len);
	}
	if ((st == PSA_SUCCESS) && (len > 0U)) {
		st = psa_aead_update(&op, ct, len, pt, len, &n);
	}
	if (st == PSA_SUCCESS) {
		/* Checks the tag; releases any remaining plaintext. */
		st = psa_aead_verify(&op, pt + n, len - n, &m, tag, 16);
	}
	psa_aead_abort(&op);
	if (id != PSA_KEY_ID_NULL) {
		(void)psa_destroy_key(id);
	}
	if (st == PSA_SUCCESS) {
		return 0;
	}
	wipe(pt, len); /* PSA may have released plaintext before the tag check */
	return (st == PSA_ERROR_INVALID_SIGNATURE) ? -EBADMSG : -EIO;
}
