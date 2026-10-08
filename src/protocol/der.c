/**
 * @file der.c
 * @brief Strict, minimal DER helpers (no heap, no ASN.1 library).
 */
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "protocol/der.h"

#define DER_SEQ      0x30U
#define DER_INT      0x02U
#define DER_BITSTR   0x03U
#define DER_OID      0x06U
#define DER_CTX0     0xA0U

typedef struct {
	const uint8_t *p;
	size_t left;
} der_cur_t;

typedef struct {
	uint8_t tag;
	const uint8_t *val;
	size_t len;
} der_el_t;

/* Read one element with definite, minimal length (max 2 length bytes). */
static int der_next(der_cur_t *c, der_el_t *e)
{
	size_t len;
	size_t hlen;

	if (c->left < 2U) {
		return -EBADMSG;
	}
	e->tag = c->p[0];
	if (c->p[1] < 0x80U) {
		len = c->p[1];
		hlen = 2U;
	} else if (c->p[1] == 0x81U) {
		if ((c->left < 3U) || (c->p[2] < 0x80U)) {
			return -EBADMSG;
		}
		len = c->p[2];
		hlen = 3U;
	} else if (c->p[1] == 0x82U) {
		if (c->left < 4U) {
			return -EBADMSG;
		}
		len = ((size_t)c->p[2] << 8) | c->p[3];
		if (len < 0x100U) {
			return -EBADMSG;
		}
		hlen = 4U;
	} else {
		return -EBADMSG;
	}
	if (len > (c->left - hlen)) {
		return -EBADMSG;
	}
	e->val = c->p + hlen;
	e->len = len;
	c->p += hlen + len;
	c->left -= hlen + len;
	return 0;
}

static int der_expect(der_cur_t *c, uint8_t tag, der_el_t *e)
{
	int rc = der_next(c, e);

	if (rc != 0) {
		return rc;
	}
	return (e->tag == tag) ? 0 : -EBADMSG;
}

static void der_enter(der_cur_t *c, const der_el_t *e)
{
	c->p = e->val;
	c->left = e->len;
}

/* Copy a DER INTEGER (positive, minimal) into a 32-byte big-endian field. */
static int int_to_32(const der_el_t *e, uint8_t out[32])
{
	const uint8_t *v = e->val;
	size_t n = e->len;

	if ((n == 0U) || (v[0] & 0x80U)) {
		return -EBADMSG; /* empty or negative */
	}
	if ((n > 1U) && (v[0] == 0x00U) && !(v[1] & 0x80U)) {
		return -EBADMSG; /* non-minimal */
	}
	if (v[0] == 0x00U && n > 1U) {
		v++;
		n--;
	}
	if (n > 32U) {
		return -EBADMSG;
	}
	memset(out, 0, 32U);
	memcpy(out + (32U - n), v, n);
	return 0;
}

int der_sig_to_raw(const uint8_t *der, size_t len, uint8_t raw[64])
{
	der_cur_t c = { der, len };
	der_el_t seq;
	der_el_t r;
	der_el_t s;

	if ((der == NULL) || (raw == NULL)) {
		return -EINVAL;
	}
	if ((der_expect(&c, DER_SEQ, &seq) != 0) || (c.left != 0U)) {
		return -EBADMSG;
	}
	der_enter(&c, &seq);
	if ((der_expect(&c, DER_INT, &r) != 0) || (der_expect(&c, DER_INT, &s) != 0) ||
	    (c.left != 0U)) {
		return -EBADMSG;
	}
	if ((int_to_32(&r, raw) != 0) || (int_to_32(&s, raw + 32) != 0)) {
		return -EBADMSG;
	}
	return 0;
}

static size_t put_int32(const uint8_t v32[32], uint8_t *out)
{
	size_t skip = 0U;
	size_t n;
	size_t i = 0U;

	while ((skip < 31U) && (v32[skip] == 0x00U)) {
		skip++;
	}
	n = 32U - skip;
	out[i++] = DER_INT;
	if (v32[skip] & 0x80U) {
		out[i++] = (uint8_t)(n + 1U);
		out[i++] = 0x00U;
	} else {
		out[i++] = (uint8_t)n;
	}
	memcpy(&out[i], &v32[skip], n);
	return i + n;
}

int der_sig_from_raw(const uint8_t raw[64], uint8_t *der, size_t cap, size_t *len)
{
	uint8_t tmp[72];
	size_t body;

	if ((raw == NULL) || (der == NULL) || (len == NULL)) {
		return -EINVAL;
	}
	body = put_int32(raw, tmp);
	body += put_int32(raw + 32, tmp + body);
	if (cap < body + 2U) {
		return -ENOSPC;
	}
	der[0] = DER_SEQ;
	der[1] = (uint8_t)body;
	memcpy(der + 2, tmp, body);
	*len = body + 2U;
	return 0;
}

int der_sig_any_to_raw(const uint8_t *sig, size_t len, uint8_t raw[64])
{
	if ((sig == NULL) || (raw == NULL)) {
		return -EINVAL;
	}
	if (len == 64U) {
		memcpy(raw, sig, 64U);
		return 0;
	}
	return der_sig_to_raw(sig, len, raw);
}

/* id-ecPublicKey 1.2.840.10045.2.1, prime256v1 1.2.840.10045.3.1.7,
 * rsaEncryption 1.2.840.113549.1.1.1 */
static const uint8_t k_oid_ec_pub[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t k_oid_p256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t k_oid_rsa[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

/* Fixed DER prefixes for the two key types we produce. */
static const uint8_t k_spki_p256_prefix[] = {
	0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
	0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
};
static const uint8_t k_spki_rsa_prefix[] = {
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82,
	0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00,
};
static const uint8_t k_spki_rsa_suffix[] = { 0x02, 0x03, 0x01, 0x00, 0x01 };

static bool el_is(const der_el_t *e, const uint8_t *v, size_t n)
{
	return (e->len == n) && (memcmp(e->val, v, n) == 0);
}

/* Parse the body of a SubjectPublicKeyInfo SEQUENCE. */
static int spki_key(const der_el_t *spki, der_key_t *k)
{
	der_cur_t c;
	der_cur_t a;
	der_el_t alg;
	der_el_t oid1;
	der_el_t param;
	der_el_t bits;

	memset(k, 0, sizeof(*k));
	der_enter(&c, spki);
	if ((der_expect(&c, DER_SEQ, &alg) != 0) || (der_expect(&c, DER_BITSTR, &bits) != 0) ||
	    (c.left != 0U)) {
		return -EBADMSG;
	}
	der_enter(&a, &alg);
	if ((der_expect(&a, DER_OID, &oid1) != 0) || (der_next(&a, &param) != 0) ||
	    (a.left != 0U)) {
		return -EBADMSG;
	}
	if ((bits.len < 1U) || (bits.val[0] != 0x00U)) {
		return -EBADMSG; /* no unused bits allowed */
	}

	if (el_is(&oid1, k_oid_ec_pub, sizeof(k_oid_ec_pub))) {
		if ((param.tag != DER_OID) || !el_is(&param, k_oid_p256, sizeof(k_oid_p256))) {
			return -ENOTSUP;
		}
		if ((bits.len != 66U) || (bits.val[1] != 0x04U)) {
			return -EBADMSG;
		}
		k->alg = DER_ALG_P256;
		k->key = &bits.val[1];
		k->key_len = 65U;
		return 0;
	}

	if (el_is(&oid1, k_oid_rsa, sizeof(k_oid_rsa))) {
		der_cur_t r;
		der_el_t rsa;
		der_el_t n;
		der_el_t e;
		const uint8_t *nv;
		size_t nl;

		if ((param.tag != 0x05U) || (param.len != 0U)) {
			return -EBADMSG; /* parameters must be NULL */
		}
		r.p = &bits.val[1];
		r.left = bits.len - 1U;
		if ((der_expect(&r, DER_SEQ, &rsa) != 0) || (r.left != 0U)) {
			return -EBADMSG;
		}
		der_enter(&r, &rsa);
		if ((der_expect(&r, DER_INT, &n) != 0) || (der_expect(&r, DER_INT, &e) != 0) ||
		    (r.left != 0U)) {
			return -EBADMSG;
		}
		nv = n.val;
		nl = n.len;
		if ((nl > 1U) && (nv[0] == 0x00U)) {
			nv++;
			nl--;
		}
		if ((nl != 256U) || ((nv[0] & 0x80U) == 0U)) {
			return -ENOTSUP; /* RSA-2048 only */
		}
		if ((e.len != 3U) || (e.val[0] != 0x01U) || (e.val[1] != 0x00U) ||
		    (e.val[2] != 0x01U)) {
			return -ENOTSUP; /* public exponent 65537 only */
		}
		k->alg = DER_ALG_RSA2048;
		k->key = nv;
		k->key_len = 256U;
		return 0;
	}
	return -ENOTSUP;
}

int der_spki_key(const uint8_t *spki, size_t len, der_key_t *k)
{
	der_cur_t c = { spki, len };
	der_el_t e;

	if ((spki == NULL) || (k == NULL)) {
		return -EINVAL;
	}
	if ((der_expect(&c, DER_SEQ, &e) != 0) || (c.left != 0U)) {
		return -EBADMSG;
	}
	return spki_key(&e, k);
}

int der_spki_build(uint8_t alg, const uint8_t *key, size_t key_len, uint8_t *out, size_t cap,
		   size_t *out_len)
{
	size_t n;

	if ((key == NULL) || (out == NULL) || (out_len == NULL)) {
		return -EINVAL;
	}
	if ((alg == DER_ALG_P256) && (key_len == 65U) && (key[0] == 0x04U)) {
		n = sizeof(k_spki_p256_prefix) + 65U;
		if (cap < n) {
			return -ENOSPC;
		}
		memcpy(out, k_spki_p256_prefix, sizeof(k_spki_p256_prefix));
		memcpy(out + sizeof(k_spki_p256_prefix), key, 65U);
	} else if ((alg == DER_ALG_RSA2048) && (key_len == 256U) && ((key[0] & 0x80U) != 0U)) {
		n = sizeof(k_spki_rsa_prefix) + 256U + sizeof(k_spki_rsa_suffix);
		if (cap < n) {
			return -ENOSPC;
		}
		memcpy(out, k_spki_rsa_prefix, sizeof(k_spki_rsa_prefix));
		memcpy(out + sizeof(k_spki_rsa_prefix), key, 256U);
		memcpy(out + sizeof(k_spki_rsa_prefix) + 256U, k_spki_rsa_suffix,
		       sizeof(k_spki_rsa_suffix));
	} else {
		return -EINVAL;
	}
	*out_len = n;
	return 0;
}

bool der_key_equal(const der_key_t *a, const der_key_t *b)
{
	uint8_t d = 0U;
	size_t i;

	if ((a->alg != b->alg) || (a->key_len != b->key_len)) {
		return false;
	}
	for (i = 0U; i < a->key_len; i++) {
		d |= (uint8_t)(a->key[i] ^ b->key[i]);
	}
	return d == 0U;
}

int der_cert_key(const uint8_t *cert, size_t len, der_key_t *k)
{
	der_cur_t c = { cert, len };
	der_el_t outer;
	der_el_t tbs;
	der_el_t e;
	int i;

	if ((cert == NULL) || (k == NULL)) {
		return -EINVAL;
	}
	if ((der_expect(&c, DER_SEQ, &outer) != 0) || (c.left != 0U)) {
		return -EBADMSG;
	}
	der_enter(&c, &outer);
	if (der_expect(&c, DER_SEQ, &tbs) != 0) {
		return -EBADMSG;
	}
	der_enter(&c, &tbs);

	/* [0] version (optional) */
	if ((c.left > 0U) && (c.p[0] == DER_CTX0)) {
		if (der_next(&c, &e) != 0) {
			return -EBADMSG;
		}
	}
	/* serialNumber */
	if (der_expect(&c, DER_INT, &e) != 0) {
		return -EBADMSG;
	}
	/* signature, issuer, validity, subject */
	for (i = 0; i < 4; i++) {
		if (der_expect(&c, DER_SEQ, &e) != 0) {
			return -EBADMSG;
		}
	}
	/* subjectPublicKeyInfo */
	if (der_expect(&c, DER_SEQ, &e) != 0) {
		return -EBADMSG;
	}
	return spki_key(&e, k);
}

int der_cri_key(const uint8_t *cri, size_t len, der_key_t *k)
{
	der_cur_t c = { cri, len };
	der_el_t outer;
	der_el_t e;

	if ((cri == NULL) || (k == NULL)) {
		return -EINVAL;
	}
	if ((der_expect(&c, DER_SEQ, &outer) != 0) || (c.left != 0U)) {
		return -EBADMSG;
	}
	der_enter(&c, &outer);
	/* version INTEGER (must be 0) */
	if ((der_expect(&c, DER_INT, &e) != 0) || (e.len != 1U) || (e.val[0] != 0x00U)) {
		return -EBADMSG;
	}
	/* subject Name */
	if (der_expect(&c, DER_SEQ, &e) != 0) {
		return -EBADMSG;
	}
	/* subjectPKInfo */
	if (der_expect(&c, DER_SEQ, &e) != 0) {
		return -EBADMSG;
	}
	if (spki_key(&e, k) != 0) {
		return -EBADMSG;
	}
	/* attributes [0] IMPLICIT SET — required by PKCS#10, may be empty */
	if ((der_next(&c, &e) != 0) || (e.tag != DER_CTX0) || (c.left != 0U)) {
		return -EBADMSG;
	}
	return 0;
}

/* P-256-only wrappers (device certificate). */

static int p256_out(int rc, const der_key_t *k, uint8_t pub[65])
{
	if (rc != 0) {
		return rc;
	}
	if (k->alg != DER_ALG_P256) {
		return -ENOTSUP;
	}
	memcpy(pub, k->key, 65U);
	return 0;
}

int der_spki_p256_pubkey(const uint8_t *spki, size_t len, uint8_t pub[65])
{
	der_key_t k;

	return p256_out(der_spki_key(spki, len, &k), &k, pub);
}

int der_cert_p256_pubkey(const uint8_t *cert, size_t len, uint8_t pub[65])
{
	der_key_t k;

	return p256_out(der_cert_key(cert, len, &k), &k, pub);
}

int der_cri_p256_pubkey(const uint8_t *cri, size_t len, uint8_t pub[65])
{
	der_key_t k;

	return p256_out(der_cri_key(cri, len, &k), &k, pub);
}
