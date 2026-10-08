/**
 * @file se05x_link.h
 * @brief Session management and object operations for the two SE05x parts.
 *
 * SE050 (I2C1) holds device trust: device key, DTI command key, activation
 * key, lifecycle object and monotonic counters. SE052F (I2C0) holds DSC keys.
 *
 * Both parts share one Plug & Trust T=1 context, so only one session can be
 * open at a time. se_acquire() locks the bus mutex and switches the open
 * session when needed; se_release() unlocks but keeps the session open.
 */
#ifndef QDSD_SE05X_LINK_H
#define QDSD_SE05X_LINK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
	QDSD_SE_DEV = 0, /* SE050  — device trust */
	QDSD_SE_DSC = 1, /* SE052F — DSC keys     */
} qdsd_se_t;

/* Object ids: include/qdsd/qdsd_objids.h */

/** Largest binary-object write sent as one APDU (all or nothing in the SE). */
#define SE_BINARY_CHUNK 208U

/** Open both elements once at boot (also proves they answer). */
int se_link_init(void);

/** Opaque session handle (Se05xSession_t inside). */
typedef struct se_handle se_handle_t;

se_handle_t *se_acquire(qdsd_se_t which);
/** ok=false drops the session so the next acquire re-opens it. */
void se_release(se_handle_t *h, bool ok);

int se_exists(se_handle_t *h, uint32_t id, bool *exists);
int se_delete(se_handle_t *h, uint32_t id);                       /* -ENOENT if absent */
int se_gen_p256(se_handle_t *h, uint32_t id);
int se_write_p256_pub(se_handle_t *h, uint32_t id, const uint8_t pub[65]);
int se_read_p256_pub(se_handle_t *h, uint32_t id, uint8_t pub[65]);
int se_sign_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], uint8_t sig[64]);
/* RSA-2048 (public exponent 65537), PKCS#1 v1.5 with SHA-256 */
int se_gen_rsa2048(se_handle_t *h, uint32_t id);
int se_read_rsa2048_mod(se_handle_t *h, uint32_t id, uint8_t mod[256]);
int se_sign_rsa2048_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], uint8_t sig[256]);
int se_counter_create(se_handle_t *h, uint32_t id);
int se_counter_inc(se_handle_t *h, uint32_t id);
int se_counter_read(se_handle_t *h, uint32_t id, uint32_t *v);
int se_binary_read(se_handle_t *h, uint32_t id, uint8_t *buf, size_t cap, size_t *len);
int se_binary_write(se_handle_t *h, uint32_t id, const uint8_t *buf, size_t len);
/* v3.2 binary objects of any size (certificates, receipts) */
int se_binary_size(se_handle_t *h, uint32_t id, size_t *size);            /* -ENOENT */
int se_binary_read_at(se_handle_t *h, uint32_t id, size_t off, uint8_t *buf, size_t n);
/** Create a binary object of total bytes holding first (n <= SE_BINARY_CHUNK). */
int se_binary_create(se_handle_t *h, uint32_t id, size_t total, const uint8_t *first, size_t n);
/** Overwrite n <= SE_BINARY_CHUNK bytes at off of an existing object. */
int se_binary_write_at(se_handle_t *h, uint32_t id, size_t off, const uint8_t *buf, size_t n);
int se_read_uid(se_handle_t *h, uint8_t uid[18]);
/** NXP-attested read of a key object; out = TLV 01 command APDU, 02 attested response. */
int se_read_attested(se_handle_t *h, uint32_t id, const uint8_t fresh[16],
		     uint8_t *out, size_t *out_len);

/* v3.2 */
/** ECDSAVerify with a stored P-256 key. 0 valid, -EPERM invalid. */
int se_verify_sha256(se_handle_t *h, uint32_t id, const uint8_t hash[32], const uint8_t sig[64]);
/** Write a P-256 key pair from outside (imported key). */
int se_write_p256_pair(se_handle_t *h, uint32_t id, const uint8_t d[32], const uint8_t pub[65]);
/** Write an RSA-2048 CRT key pair from outside: p, q, dp, dq, qinv (128 each), n (256). */
int se_write_rsa2048_crt(se_handle_t *h, uint32_t id, const uint8_t comp[640],
			 const uint8_t mod[256]);
/** Create and parameterise the NIST P-256 curve; 0 if it already exists. */
int se_create_p256_curve(se_handle_t *h);
/** Create (or replace) a UserID authentication object. */
int se_userid_write(se_handle_t *h, uint32_t id, const uint8_t *secret, size_t len);
/**
 * Open a session authenticated with UserID object id. -ENOENT if there is no
 * such object, -EACCES if the secret is wrong (the element decides).
 */
int se_user_session_open(se_handle_t *h, uint32_t id, const uint8_t *secret, size_t len);
/** DeleteAll inside the open UserID session (FACTORY_RESET object only). */
int se_user_delete_all(se_handle_t *h);
void se_user_session_close(se_handle_t *h);

#endif /* QDSD_SE05X_LINK_H */
