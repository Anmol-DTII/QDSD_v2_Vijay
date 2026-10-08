/**
 * @file token_store.c
 * @brief Slot records and certificates in the SE052F; boot checks and migration of 0.3-0.5 records.
 */
#include <errno.h>
#include <string.h>

#include "token/token_ctx.h"

/* ── Slot records and certificates (SE052F) ─────────────────────────── */

int slot_load(uint8_t slot, slot_meta_t *m)
{
	uint8_t b[SLOT_REC_LEN];
	size_t len = 0U;
	int rc;

	memset(m, 0, sizeof(*m));
	rc = port_obj_read(PORT_OBJ_SLOT_REC, slot, b, sizeof(b), &len);
	if (rc == -ENOENT) {
		return 0;
	}
	if (rc != 0) {
		return -EIO;
	}
	if ((len != SLOT_REC_LEN) || (b[0] != SLOT_REC_MAGIC) || (b[1] != SLOT_REC_VER) ||
	    (b[2] > SLOT_CERTIFIED) || !alg_ok(b[3]) || (b[4] > ORIGIN_IMPORTED) ||
	    (b[5] > CSR_DIGEST) || (b[SLOT_REC_BANK] > 1U)) {
		return -EIO;
	}
	m->cert_bank = b[SLOT_REC_BANK];
	m->status = b[2];
	m->alg = b[3];
	m->origin = b[4];
	m->csr_mode = b[5];
	m->seq = tlv_be32(&b[6]);
	m->cert_len = tlv_be16(&b[10]);
	memcpy(m->cert_hash, &b[12], sizeof(m->cert_hash));
	if (m->cert_len > QDSD_CERT_MAX) {
		return -EIO;
	}
	return 0;
}

int slot_save(uint8_t slot, const slot_meta_t *m)
{
	uint8_t b[SLOT_REC_LEN];

	memset(b, 0, sizeof(b));
	b[0] = SLOT_REC_MAGIC;
	b[1] = SLOT_REC_VER;
	b[2] = m->status;
	b[3] = m->alg;
	b[4] = m->origin;
	b[5] = m->csr_mode;
	tlv_wr_be32(&b[6], m->seq);
	tlv_wr_be16(&b[10], m->cert_len);
	memcpy(&b[12], m->cert_hash, sizeof(m->cert_hash));
	b[SLOT_REC_BANK] = m->cert_bank;
	return port_obj_write(PORT_OBJ_SLOT_REC, slot, b, sizeof(b));
}

int slot_save_empty(uint8_t slot)
{
	slot_meta_t m;

	memset(&m, 0, sizeof(m));
	return slot_save(slot, &m);
}

/* The slot key's SubjectPublicKeyInfo, read from the SE052F. */
int slot_spki(uint8_t slot, uint8_t alg, uint8_t *spki, size_t cap, size_t *len)
{
	uint8_t raw[QDSD_RSA_MOD_LEN];
	size_t n = 0U;
	int rc = port_dsc_pubkey(slot, alg, raw, sizeof(raw), &n);

	if (rc != 0) {
		return rc;
	}
	return der_spki_build(alg, raw, n, spki, cap, len);
}

/* Certificate of slot into buf; -ENOENT unless it matches the slot record. */
int slot_cert_read(uint8_t slot, const slot_meta_t *m, uint8_t *buf, size_t cap,
			  size_t *len)
{
	uint8_t h[32];
	int rc;

	if (m->cert_len == 0U) {
		return -ENOENT;
	}
	rc = port_obj_read(PORT_OBJ_SLOT_CERT, CERT_IDX(slot, m->cert_bank), buf, cap, len);
	if (rc != 0) {
		return (rc == -ENOENT) ? -ENOENT : -EIO;
	}
	if ((*len != m->cert_len) || (port_sha256(buf, *len, h) != 0) ||
	    !ct_equal(h, m->cert_hash, sizeof(h))) {
		return -ENOENT; /* torn or replaced write: not this record's certificate */
	}
	return 0;
}

/*
 * Store a certificate for slot, then point the record at it. Each slot has
 * two certificate objects (banks). A new certificate goes into the bank the
 * record does not point at; the record update (one atomic write) then
 * switches to it, and the old bank is deleted. The certificate write may take
 * several APDUs, but the record always names a complete certificate, so a
 * power cut leaves the old certificate or the new one (PROTOCOL.md §5).
 */
int slot_cert_store(uint8_t slot, slot_meta_t *m, const uint8_t *cert, size_t len)
{
	uint8_t old_bank = m->cert_bank;
	bool had_cert = (m->cert_len > 0U);
	uint8_t bank = had_cert ? (uint8_t)(1U - old_bank) : old_bank;

	if ((port_obj_write(PORT_OBJ_SLOT_CERT, CERT_IDX(slot, bank), cert, len) != 0) ||
	    (port_sha256(cert, len, m->cert_hash) != 0)) {
		return -EIO;
	}
	m->cert_len = (uint16_t)len;
	m->cert_bank = bank;
	m->status = SLOT_CERTIFIED;
	if (slot_save(slot, m) != 0) {
		return -EIO;
	}
	if (had_cert) {
		/* Best effort: a leftover is removed at the next boot. */
		(void)port_obj_delete(PORT_OBJ_SLOT_CERT, CERT_IDX(slot, old_bank));
	}
	return 0;
}

/* Both certificate objects of slot (absent is fine). */
int slot_certs_delete(uint8_t slot)
{
	if (!ok_or_absent(port_obj_delete(PORT_OBJ_SLOT_CERT, CERT_IDX(slot, 0U))) ||
	    !ok_or_absent(port_obj_delete(PORT_OBJ_SLOT_CERT, CERT_IDX(slot, 1U)))) {
		return -EIO;
	}
	return 0;
}

/* Remove key, certificate and record of slot (record first: unusable at once). */
int slot_erase(uint8_t slot)
{
	if (slot_save_empty(slot) != 0) {
		return -EIO;
	}
	if (!ok_or_absent(port_dsc_delete(slot)) || (slot_certs_delete(slot) != 0)) {
		return -EIO;
	}
	return 0;
}

bool any_certified(void)
{
	slot_meta_t m;
	uint8_t i;

	for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
		if ((slot_load(i, &m) == 0) && (m.status == SLOT_CERTIFIED)) {
			return true;
		}
	}
	return false;
}

/* ── Boot: migration from 0.3-0.5 and object checks ────────────────── */

/* Parse a 0.3-0.5 NVS slot record into m; spki is ignored (read from SE). */
static int legacy_slot_parse(const uint8_t *b, size_t len, slot_meta_t *m)
{
	memset(m, 0, sizeof(*m));
	if (len == SLOT_META_V1_LEN) {
		if (b[0] > SLOT_CERTIFIED) {
			return -EBADMSG;
		}
		m->status = b[0];
		m->alg = QDSD_ALG_P256;
		m->csr_mode = (b[0] == SLOT_EMPTY) ? (uint8_t)CSR_NONE : (uint8_t)CSR_FULL;
		m->seq = tlv_be32(&b[1]);
		return 0;
	}
	if ((len < SLOT_META_V05_HDR) || (b[0] != SLOT_META_V05_MAGIC) ||
	    (b[1] > SLOT_CERTIFIED) || !alg_ok(b[2]) || (b[3] > CSR_DIGEST)) {
		return -EBADMSG;
	}
	m->status = b[1];
	m->alg = b[2];
	m->csr_mode = b[3];
	m->seq = tlv_be32(&b[4]);
	return 0;
}

/*
 * Firmware 0.3-0.5 kept certificates and slot records in MCU flash. Copy
 * them into the secure elements, then delete the flash copy. Every step is
 * repeated from the start if power fails, because the flash copy is only
 * removed once the secure-element copy is complete.
 */
int migrate_legacy(void)
{
	uint8_t b[SLOT_META_V05_HDR + SPKI_MAX];
	slot_meta_t m;
	size_t len = 0U;
	size_t clen = 0U;
	uint8_t i;
	int rc;

	rc = port_nvs_read(NVS_DEVICE_CERT, g_tk.read_buf, sizeof(g_tk.read_buf), &len);
	if (rc == 0) {
		if ((port_obj_write(PORT_OBJ_DEVICE_CERT, 0U, g_tk.read_buf, len) != 0) ||
		    (port_nvs_delete(NVS_DEVICE_CERT) != 0)) {
			return -EIO;
		}
	} else if (rc != -ENOENT) {
		return -EIO;
	}

	for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
		rc = port_nvs_read(NVS_SLOT_META(i), b, sizeof(b), &len);
		if (rc == -ENOENT) {
			continue;
		}
		if ((rc != 0) || (legacy_slot_parse(b, len, &m) != 0)) {
			return -EIO;
		}
		m.origin = ORIGIN_GENERATED;
		rc = port_nvs_read(NVS_SLOT_CERT(i), g_tk.read_buf, sizeof(g_tk.read_buf), &clen);
		if ((rc == 0) && (m.status != SLOT_EMPTY)) {
			if ((port_obj_write(PORT_OBJ_SLOT_CERT, i, g_tk.read_buf, clen) != 0) ||
			    (port_sha256(g_tk.read_buf, clen, m.cert_hash) != 0)) {
				return -EIO;
			}
			m.cert_len = (uint16_t)clen;
		} else if ((rc != 0) && (rc != -ENOENT)) {
			return -EIO;
		}
		if ((slot_save(i, &m) != 0) ||
		    !ok_or_absent(port_nvs_delete(NVS_SLOT_CERT(i))) ||
		    !ok_or_absent(port_nvs_delete(NVS_SLOT_META(i)))) {
			return -EIO;
		}
	}
	return 0;
}

/*
 * Leftovers of a cut-off delete, keygen, import or certificate write: a key
 * or certificate in an empty slot, or a certificate in the bank the slot
 * record does not point at.
 */
static int sweep_orphans(void)
{
	slot_meta_t m;
	uint8_t i;

	for (i = 0U; i < QDSD_DSC_SLOTS; i++) {
		if (slot_load(i, &m) != 0) {
			return -EIO;
		}
		if (m.status == SLOT_EMPTY) {
			if (!ok_or_absent(port_dsc_delete(i)) || (slot_certs_delete(i) != 0)) {
				return -EIO;
			}
			continue;
		}
		if ((m.cert_len == 0U) && (slot_certs_delete(i) != 0)) {
			return -EIO;
		}
		if ((m.cert_len > 0U) &&
		    !ok_or_absent(port_obj_delete(PORT_OBJ_SLOT_CERT,
						  CERT_IDX(i, (uint8_t)(1U - m.cert_bank))))) {
			return -EIO;
		}
	}
	return 0;
}

int check_objects(void)
{
	uint8_t pub[QDSD_P256_PUB_LEN];
	uint32_t b;
	uint32_t k;
	uint32_t s;
	size_t clen = 0U;

	if (g_tk.st.lc == LC_MANUFACTURING) {
		return 0;
	}
	/* Tokens closed by firmware 0.3 have no policy counter yet. */
	if (port_counter_ensure(PORT_CTR_POLICY) != 0) {
		return -EIO;
	}
	if (!g_tk.st.has_device_id || (port_devkey_pubkey(pub) != 0) ||
	    (port_pubkey_read(PORT_PUBKEY_CMD, pub) != 0) ||
	    (port_obj_read(PORT_OBJ_DEVICE_CERT, 0U, NULL, 0U, &clen) != 0) ||
	    (read_counters(&b, &k, &s) != 0)) {
		return -EIO;
	}
	if (lc_is(LC_BOUND, LC_READY) && (port_pubkey_read(PORT_PUBKEY_ACTIVATION, pub) != 0)) {
		return -EIO;
	}
	/* Firmware <= 0.5 had no receipt ring. */
	if ((rcpt_ensure() != 0) || (sweep_orphans() != 0)) {
		return -EIO;
	}
	/*
	 * READY means "has a certified DSC". A power cut between a slot change
	 * (WRITE_CERT, import, DELETE_KEY) and the lifecycle write leaves the
	 * two out of step; the slot records are the truth.
	 */
	if (lc_is(LC_BOUND, LC_READY)) {
		uint8_t want = any_certified() ? (uint8_t)LC_READY : (uint8_t)LC_BOUND;

		if (set_lc(want) != 0) {
			return -EIO;
		}
	}
	return 0;
}

