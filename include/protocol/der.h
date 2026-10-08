/**
 * @file der.h
 * @brief Strict, minimal DER helpers: ECDSA signatures and P-256 SPKI extraction.
 */
#ifndef QDSD_DER_H
#define QDSD_DER_H

#include <stddef.h>
#include <stdint.h>

/** ECDSA-Sig-Value DER -> raw r||s (64 bytes). */
int der_sig_to_raw(const uint8_t *der, size_t len, uint8_t raw[64]);
/** raw r||s -> ECDSA-Sig-Value DER (at most 72 bytes). */
int der_sig_from_raw(const uint8_t raw[64], uint8_t *der, size_t cap, size_t *len);
/** Accept raw (64) or DER signature, output raw. */
int der_sig_any_to_raw(const uint8_t *sig, size_t len, uint8_t raw[64]);

#include <stdbool.h>

#define DER_ALG_P256    0x00U
#define DER_ALG_RSA2048 0x01U

/** A public key found inside DER: P-256 point (65) or RSA-2048 modulus (256, e = 65537). */
typedef struct {
	uint8_t        alg;
	const uint8_t *key;
	size_t         key_len;
} der_key_t;

/** Parse a SubjectPublicKeyInfo (whole buffer). -ENOTSUP for other key types. */
int der_spki_key(const uint8_t *spki, size_t len, der_key_t *k);
/** Build the canonical SubjectPublicKeyInfo for a P-256 point or RSA-2048 modulus. */
int der_spki_build(uint8_t alg, const uint8_t *key, size_t key_len, uint8_t *out, size_t cap,
		   size_t *out_len);
/** Constant-time comparison of two parsed keys. */
bool der_key_equal(const der_key_t *a, const der_key_t *b);
/** Subject public key of an X.509 certificate. */
int der_cert_key(const uint8_t *cert, size_t len, der_key_t *k);
/** Subject public key of a PKCS#10 CertificationRequestInfo. */
int der_cri_key(const uint8_t *cri, size_t len, der_key_t *k);

/** SubjectPublicKeyInfo DER (whole buffer) -> uncompressed P-256 point. */
int der_spki_p256_pubkey(const uint8_t *spki, size_t len, uint8_t pub[65]);
/** X.509 Certificate -> uncompressed P-256 subject public key. */
int der_cert_p256_pubkey(const uint8_t *cert, size_t len, uint8_t pub[65]);
/** PKCS#10 CertificationRequestInfo -> uncompressed P-256 public key. */
int der_cri_p256_pubkey(const uint8_t *cri, size_t len, uint8_t pub[65]);

#endif /* QDSD_DER_H */
