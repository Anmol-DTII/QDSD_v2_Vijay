/**
 * @file port_host.c
 * @brief Software model of the QDSD hardware for host tests.
 *
 * Models in RAM, with mbedTLS for the cryptography:
 *   SE050  : device key, command/activation keys (verify inside), counters,
 *            state object, device certificate, receipt ring, FACTORY_RESET
 *            secret, NIST P-256 curve;
 *   SE052F : DSC keys (generated or imported, with origin), slot records,
 *            DSC certificates, FACTORY_RESET secret, curve, NXP attestation;
 *   MCU    : legacy NVS records (firmware 0.3-0.5) and the MCUboot slot.
 * Binary objects are written in PORT_OBJ_ATOMIC_MAX chunks exactly like the
 * device port, each chunk one unit of power budget, so a power cut can tear a
 * large write the way it would on hardware.
 * Test controls (sim_*) inject power loss, SE failures and time.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"

#include "port/port.h"
#include "qdsd/qdsd_config.h"
#include "token/token_engine.h"
#include "usb/ccid.h"
#include "usb/msc.h"

/* sim_* test controls are called from Python (ctypes), not from C. */
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define SIM_NVS_MAX 64
#define SIM_NVS_REC 2304
#define SIM_OBJ_IDX 32
#define SIM_OBJ_MAX 2112

typedef struct {
	bool    present;
	size_t  len;
	uint8_t data[SIM_OBJ_MAX];
} sim_obj_t;

typedef struct {
	bool present;
	mbedtls_ecp_keypair kp;
} sim_key_t;

static struct {
	bool inited;
	mbedtls_ctr_drbg_context drbg;
	uint32_t entropy_ctr;

	sim_key_t devkey;
	sim_key_t dsc[QDSD_DSC_SLOTS];
	struct {
		bool present;
		uint8_t alg;
		mbedtls_rsa_context rsa;
	} rsa[QDSD_DSC_SLOTS];
	uint8_t dsc_origin[QDSD_DSC_SLOTS]; /* 1 generated inside, 2 written from outside */
	sim_key_t att_dsc;                   /* stands in for the SE052F NXP attestation key */

	sim_obj_t obj[PORT_OBJ_KIND_COUNT][SIM_OBJ_IDX];
	struct {
		bool    present;
		uint8_t secret[QDSD_WIPE_SECRET_LEN];
	} wipe[2];
	bool curve[2];
	unsigned se_verifies;

	/* firmware update slot */
	uint8_t fw[600 * 1024];
	uint32_t fw_total;
	uint32_t fw_written;
	bool fw_open;
	bool fw_pending;
	bool pub_present[2];
	uint8_t pub[2][QDSD_P256_PUB_LEN];
	bool ctr_present[PORT_CTR_COUNT];
	uint32_t ctr[PORT_CTR_COUNT];
	bool state_present;
	uint8_t state[128];
	size_t state_len;

	struct {
		bool used;
		uint16_t id;
		size_t len;
		uint8_t data[SIM_NVS_REC];
	} nvs[SIM_NVS_MAX];

	uint8_t uid[QDSD_CHIP_UID_LEN];
	uint8_t uid_dsc[QDSD_CHIP_UID_LEN];

	/* fault injection */
	long power_budget;   /* -1 = unlimited */
	bool powered_off;
	bool fail_dsc_sign;
	uint64_t now_ms;
	unsigned events[8];
	unsigned writes;
} S;

static int det_entropy(void *ctx, unsigned char *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++) {
		out[i] = (unsigned char)(S.entropy_ctr * 131U + i * 7U + 0x5AU);
	}
	S.entropy_ctr++;
	return 0;
}

static int rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return mbedtls_ctr_drbg_random(&S.drbg, out, len);
}

static int key_gen(sim_key_t *k);
static int key_pub(const sim_key_t *k, uint8_t pub[65]);

static void key_free(sim_key_t *k)
{
	if (k->present) {
		mbedtls_ecp_keypair_free(&k->kp);
	}
	k->present = false;
}

/* ── install drive: 8 MB QSPI NOR + the read-only USB disk ────────── */

#define SIM_DRIVE_SIZE (8U * 1024U * 1024U)
static uint8_t s_drive[SIM_DRIVE_SIZE];
static bool s_drive_none;     /* models a board / build without the drive */
static msc_t s_msc;
static unsigned s_drive_erases;
static int pwr_write(void);
static int pwr_read(void);

static int msc_read_blocks(uint32_t lba, uint8_t *buf, uint32_t blocks)
{
	return port_drive_read(lba * MSC_BLOCK_SIZE, buf, (size_t)blocks * MSC_BLOCK_SIZE);
}

static void sim_drive_reset(void)
{
	memset(s_drive, 0xFF, sizeof(s_drive)); /* a new chip arrives erased */
	s_drive_none = false;
	s_drive_erases = 0U;
	msc_init(&s_msc, msc_read_blocks, 64U);
}

void sim_drive_none(int on) { s_drive_none = (on != 0); }
unsigned sim_drive_erases(void) { return s_drive_erases; }
uint8_t *sim_drive_mem(void) { return s_drive; }
int sim_msc_present(void) { return s_msc.present ? 1 : 0; }
uint32_t sim_msc_blocks(void) { return s_msc.blocks; }

uint32_t port_drive_size(void)
{
	return s_drive_none ? 0U : SIM_DRIVE_SIZE;
}

int port_drive_read(uint32_t off, void *buf, size_t len)
{
	if ((pwr_read() != 0) || (off > SIM_DRIVE_SIZE) || (len > SIM_DRIVE_SIZE - off)) {
		return -EIO;
	}
	memcpy(buf, &s_drive[off], len);
	return 0;
}

int port_drive_erase(uint32_t off, uint32_t len)
{
	if (((off % QDSD_DRIVE_ERASE_BLOCK) != 0U) || ((len % QDSD_DRIVE_ERASE_BLOCK) != 0U) ||
	    (off > SIM_DRIVE_SIZE) || (len > SIM_DRIVE_SIZE - off) || (pwr_write() != 0)) {
		return -EIO;
	}
	memset(&s_drive[off], 0xFF, len);
	s_drive_erases++;
	return 0;
}

int port_drive_write(uint32_t off, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;

	if ((off > SIM_DRIVE_SIZE) || (len > SIM_DRIVE_SIZE - off) || (pwr_write() != 0)) {
		return -EIO;
	}
	for (i = 0; i < len; i++) {
		s_drive[off + i] &= p[i]; /* NOR: programming only clears bits */
	}
	return 0;
}

void port_drive_medium(bool present, uint32_t blocks)
{
	msc_set_medium(&s_msc, present, blocks);
}

/*
 * One Bulk-Only command as src/usb/token_msc.c moves it: the CBW, then any
 * data-out in 64-byte packets, then every IN transfer until the status.
 * Returns the bytes read (data then the 13-byte CSW); *stalled = 1 if the
 * device stalled its endpoints (until sim_msc_reset()).
 */
size_t sim_msc(const uint8_t *cbw, size_t cbw_len, const uint8_t *dout, size_t dlen,
	       uint8_t *out, size_t cap, int *stalled)
{
	static uint8_t xfer[4096];
	msc_next_t next = msc_rx(&s_msc, cbw, cbw_len);
	size_t got = 0U;
	size_t pos = 0U;

	*stalled = 0;
	while ((next == MSC_ARM_OUT) && (pos < dlen)) {
		size_t n = (dlen - pos > 64U) ? 64U : (dlen - pos);

		next = msc_rx(&s_msc, &dout[pos], n);
		pos += n;
	}
	while (next == MSC_SEND_IN) {
		size_t n = msc_tx(&s_msc, xfer, sizeof(xfer), &next);

		if ((n > 0U) && (got + n <= cap)) {
			memcpy(&out[got], xfer, n);
		}
		got += n;
	}
	if (next == MSC_STALL) {
		*stalled = 1;
	}
	return got;
}

void sim_msc_reset(void) { msc_reset(&s_msc); }

/* ── test controls ─────────────────────────────────────────────────── */

void sim_reset_all(uint32_t seed)
{
	int i;

	if (S.inited) {
		key_free(&S.devkey);
		key_free(&S.att_dsc);
		for (i = 0; i < (int)QDSD_DSC_SLOTS; i++) {
			key_free(&S.dsc[i]);
			if (S.rsa[i].present) {
				mbedtls_rsa_free(&S.rsa[i].rsa);
			}
		}
		mbedtls_ctr_drbg_free(&S.drbg);
	}
	memset(&S, 0, sizeof(S));
	S.entropy_ctr = seed;
	mbedtls_ctr_drbg_init(&S.drbg);
	mbedtls_ctr_drbg_seed(&S.drbg, det_entropy, NULL, (const unsigned char *)"qdsd-sim", 8);
	for (i = 0; i < (int)QDSD_CHIP_UID_LEN; i++) {
		S.uid[i] = (uint8_t)(0xC0U + i + seed);
		S.uid_dsc[i] = (uint8_t)(0x50U + i + seed);
	}
	S.curve[0] = true;
	S.curve[1] = true;
	S.power_budget = -1;
	S.inited = true;
	(void)key_gen(&S.att_dsc);
	sim_drive_reset();
}

void sim_set_power_budget(long n) { S.power_budget = n; }
void sim_reboot(void) { S.powered_off = false; S.power_budget = -1; }
int  sim_powered_off(void) { return S.powered_off ? 1 : 0; }
void sim_fail_dsc_sign(int on) { S.fail_dsc_sign = (on != 0); }
void sim_advance_ms(uint64_t ms) { S.now_ms += ms; }
unsigned sim_event_count(int evt) { return (evt >= 0 && evt < 8) ? S.events[evt] : 0U; }
unsigned sim_write_count(void) { return S.writes; }
int sim_dsc_present(int slot)
{
	return (slot >= 0 && slot < (int)QDSD_DSC_SLOTS) ? (S.dsc[slot].present || S.rsa[slot].present) : 0;
}
int sim_nvs_put(uint16_t id, const uint8_t *buf, size_t len) { return port_nvs_write(id, buf, len); }
int sim_fw_pending(void) { return S.fw_pending ? 1 : 0; }
uint32_t sim_fw_written(void) { return S.fw_written; }
size_t sim_state_get(uint8_t *buf, size_t cap)
{
	if (!S.state_present || (cap < S.state_len)) {
		return 0;
	}
	memcpy(buf, S.state, S.state_len);
	return S.state_len;
}
void sim_state_set(const uint8_t *buf, size_t len)
{
	memcpy(S.state, buf, len);
	S.state_len = len;
	S.state_present = true;
}
void sim_counter_remove(int c) { if (c >= 0 && c < PORT_CTR_COUNT) { S.ctr_present[c] = false; S.ctr[c] = 0; } }
void sim_corrupt_state(void) { if (S.state_len) { S.state[10] ^= 0x01U; } }
void sim_state_remove(void) { S.state_present = false; S.state_len = 0U; }
int sim_counter(int c) { return (c >= 0 && c < PORT_CTR_COUNT) ? (int)S.ctr[c] : -1; }
int sim_counter_present(int c) { return (c >= 0 && c < PORT_CTR_COUNT) ? S.ctr_present[c] : 0; }
unsigned sim_se_verify_count(void) { return S.se_verifies; }
int sim_dsc_origin(int slot) { return (slot >= 0 && slot < (int)QDSD_DSC_SLOTS) ? S.dsc_origin[slot] : -1; }
int sim_curve_present(int se) { return (se == 0 || se == 1) ? S.curve[se] : 0; }
int sim_wipe_secret_present(int se) { return (se == 0 || se == 1) ? S.wipe[se].present : 0; }
int sim_nvs_count(void)
{
	int i;
	int n = 0;

	for (i = 0; i < SIM_NVS_MAX; i++) {
		n += S.nvs[i].used ? 1 : 0;
	}
	return n;
}
int sim_dsc_att_pub(uint8_t pub[65]) { return key_pub(&S.att_dsc, pub); }
/* Copy object (kind, idx) out; returns its length, or -1 if absent. */
long sim_obj_get(int kind, int idx, uint8_t *buf, size_t cap)
{
	const sim_obj_t *o;

	if ((kind < 0) || (kind >= PORT_OBJ_KIND_COUNT) || (idx < 0) || (idx >= SIM_OBJ_IDX)) {
		return -1;
	}
	o = &S.obj[kind][idx];
	if (!o->present || (cap < o->len)) {
		return -1;
	}
	memcpy(buf, o->data, o->len);
	return (long)o->len;
}
void sim_obj_put(int kind, int idx, const uint8_t *buf, size_t len)
{
	sim_obj_t *o = &S.obj[kind][idx];

	o->present = true;
	o->len = len;
	memcpy(o->data, buf, len);
}
void sim_obj_flip(int kind, int idx, size_t off) { S.obj[kind][idx].data[off] ^= 0x01U; }
void sim_obj_del(int kind, int idx) { S.obj[kind][idx].present = false; }

/* CCID reader in front of the token engine, as src/usb/token_usb.c wires it. */
static ccid_t s_ccid;
static bool s_ccid_init;

static void ccid_power(bool on)
{
	(void)on;
	token_engine_card_reset(); /* as src/usb/token_usb.c */
}

size_t sim_ccid(const uint8_t *msg, size_t len, uint8_t *out, size_t cap)
{
	if (!s_ccid_init) {
		ccid_init(&s_ccid, token_engine_process, ccid_power);
		s_ccid_init = true;
	}
	return ccid_handle(&s_ccid, msg, len, out, cap);
}
void sim_ccid_unplug(void) { s_ccid_init = false; }

/* Every persistent write consumes one unit of power budget. */
static int pwr_write(void)
{
	if (S.powered_off) {
		return -EIO;
	}
	if (S.power_budget == 0) {
		S.powered_off = true;
		return -EIO;
	}
	if (S.power_budget > 0) {
		S.power_budget--;
	}
	S.writes++;
	return 0;
}

static int pwr_read(void)
{
	return S.powered_off ? -EIO : 0;
}

/* ── crypto (hash, verify, ECDH, GCM: src/port/port_crypto.c) ──────── */

int port_random(uint8_t *buf, size_t len)
{
	return rng(NULL, buf, len) == 0 ? 0 : -EIO;
}

static int key_gen(sim_key_t *k)
{
	key_free(k);
	mbedtls_ecp_keypair_init(&k->kp);
	if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &k->kp, rng, NULL) != 0) {
		mbedtls_ecp_keypair_free(&k->kp);
		return -EIO;
	}
	k->present = true;
	return 0;
}

static int key_pub(const sim_key_t *k, uint8_t pub[65])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point Q;
	size_t olen = 0;
	int rc = -EIO;

	if (!k->present) {
		return -ENOENT;
	}
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&Q);
	if ((mbedtls_ecp_export(&k->kp, &grp, NULL, &Q) == 0) &&
	    (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub,
					    65) == 0) &&
	    (olen == 65)) {
		rc = 0;
	}
	mbedtls_ecp_point_free(&Q);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

static int key_sign(const sim_key_t *k, const uint8_t hash[32], uint8_t sig[64])
{
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;
	int rc = -EIO;

	if (!k->present) {
		return -ENOENT;
	}
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	if ((mbedtls_ecp_export(&k->kp, &grp, &d, NULL) == 0) &&
	    (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, rng, NULL) == 0) &&
	    (mbedtls_mpi_write_binary(&r, sig, 32) == 0) &&
	    (mbedtls_mpi_write_binary(&s, sig + 32, 32) == 0)) {
		rc = 0;
	}
	mbedtls_mpi_free(&d);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

/* ── SE050 model ────────────────────────────────────────────────────── */

int port_devkey_ensure(void)
{
	int rc;

	if (S.devkey.present) {
		return pwr_read();
	}
	if (!S.curve[0]) {
		return -EIO; /* 6A80 on a wiped element until the curve is created */
	}
	rc = pwr_write();
	return rc ? rc : key_gen(&S.devkey);
}

int port_devkey_pubkey(uint8_t pub[QDSD_P256_PUB_LEN])
{
	return pwr_read() ? -EIO : key_pub(&S.devkey, pub);
}

int port_devkey_sign(const uint8_t hash[QDSD_SHA256_LEN], uint8_t sig[QDSD_P256_SIG_LEN])
{
	return pwr_read() ? -EIO : key_sign(&S.devkey, hash, sig);
}

int port_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN])
{
	if (pwr_read()) {
		return -EIO;
	}
	memcpy(uid, S.uid, QDSD_CHIP_UID_LEN);
	return 0;
}

int port_devkey_vendor_attest(const uint8_t *fresh, size_t fresh_len, uint8_t *out,
			      size_t *out_len)
{
	/* Mock: "SIMATT" || fresh || pub — real SE050 returns an NXP-signed blob. */
	uint8_t pub[65];
	size_t n = 6 + fresh_len + 65;

	if (pwr_read() || key_pub(&S.devkey, pub) || (*out_len < n)) {
		return -EIO;
	}
	memcpy(out, "SIMATT", 6);
	memcpy(out + 6, fresh, fresh_len);
	memcpy(out + 6 + fresh_len, pub, 65);
	*out_len = n;
	return 0;
}

int port_pubkey_write(port_pubkey_t which, const uint8_t pub[QDSD_P256_PUB_LEN])
{
	int rc = S.curve[0] ? pwr_write() : -EIO;

	if (rc) {
		return rc;
	}
	memcpy(S.pub[which], pub, QDSD_P256_PUB_LEN);
	S.pub_present[which] = true;
	return 0;
}

int port_pubkey_read(port_pubkey_t which, uint8_t pub[QDSD_P256_PUB_LEN])
{
	if (pwr_read()) {
		return -EIO;
	}
	if (!S.pub_present[which]) {
		return -ENOENT;
	}
	memcpy(pub, S.pub[which], QDSD_P256_PUB_LEN);
	return 0;
}

int port_pubkey_delete(port_pubkey_t which)
{
	int rc;

	if (!S.pub_present[which]) {
		return pwr_read() ? -EIO : -ENOENT;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	S.pub_present[which] = false;
	memset(S.pub[which], 0, QDSD_P256_PUB_LEN);
	return 0;
}

int port_pubkey_verify(port_pubkey_t which, const uint8_t hash[QDSD_SHA256_LEN],
		       const uint8_t sig[QDSD_P256_SIG_LEN])
{
	if (pwr_read()) {
		return -EIO;
	}
	if (!S.pub_present[which]) {
		return -ENOENT;
	}
	S.se_verifies++;
	return (port_ecdsa_p256_verify(S.pub[which], hash, sig) == 0) ? 0 : -EPERM;
}

int port_counter_ensure(port_counter_t c)
{
	int rc;

	if (S.ctr_present[c]) {
		return pwr_read();
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	S.ctr_present[c] = true;
	S.ctr[c] = 0;
	return 0;
}

int port_counter_read(port_counter_t c, uint32_t *value)
{
	if (pwr_read()) {
		return -EIO;
	}
	if (!S.ctr_present[c]) {
		return -ENOENT;
	}
	*value = S.ctr[c];
	return 0;
}

int port_counter_inc(port_counter_t c)
{
	int rc;

	if (!S.ctr_present[c]) {
		return -ENOENT;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	S.ctr[c]++;
	return 0;
}

int port_state_read(uint8_t *buf, size_t cap, size_t *len)
{
	if (pwr_read()) {
		return -EIO;
	}
	if (!S.state_present) {
		return -ENOENT;
	}
	if (cap < S.state_len) {
		return -ENOSPC;
	}
	memcpy(buf, S.state, S.state_len);
	*len = S.state_len;
	return 0;
}

int port_state_write(const uint8_t *buf, size_t len)
{
	int rc = pwr_write();

	if (rc) {
		return rc;
	}
	if (len > sizeof(S.state)) {
		return -ENOSPC;
	}
	memcpy(S.state, buf, len);
	S.state_len = len;
	S.state_present = true;
	return 0;
}

/* ── SE052F model ───────────────────────────────────────────────────── */

static void rsa_drop(uint8_t slot)
{
	if (S.rsa[slot].present) {
		mbedtls_rsa_free(&S.rsa[slot].rsa);
		S.rsa[slot].present = false;
	}
}

int port_dsc_generate(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len)
{
	int rc;

	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	key_free(&S.dsc[slot]);
	rsa_drop(slot);
	S.dsc_origin[slot] = 1U;
	if (alg == QDSD_ALG_P256) {
		if ((cap < 65U) || !S.curve[1]) {
			return (cap < 65U) ? -ENOSPC : -EIO;
		}
		rc = key_gen(&S.dsc[slot]);
		if (rc == 0) {
			rc = key_pub(&S.dsc[slot], pub);
			*len = 65U;
		}
		return rc;
	}
	if (alg != QDSD_ALG_RSA2048 || cap < QDSD_RSA_MOD_LEN) {
		return -EINVAL;
	}
	mbedtls_rsa_init(&S.rsa[slot].rsa);
	if (mbedtls_rsa_gen_key(&S.rsa[slot].rsa, rng, NULL, 2048, 65537) != 0) {
		mbedtls_rsa_free(&S.rsa[slot].rsa);
		return -EIO;
	}
	S.rsa[slot].present = true;
	if (mbedtls_rsa_export_raw(&S.rsa[slot].rsa, pub, QDSD_RSA_MOD_LEN, NULL, 0, NULL, 0, NULL,
				   0, NULL, 0) != 0) {
		return -EIO;
	}
	*len = QDSD_RSA_MOD_LEN;
	return 0;
}

int port_dsc_sign(uint8_t slot, uint8_t alg, const uint8_t hash[QDSD_SHA256_LEN],
		  uint8_t *sig, size_t cap, size_t *len)
{
	if ((slot >= QDSD_DSC_SLOTS) || pwr_read()) {
		return -EIO;
	}
	if (S.fail_dsc_sign) {
		return -EIO;
	}
	if (alg == QDSD_ALG_P256) {
		if (cap < 64U || !S.dsc[slot].present) {
			return -EIO;
		}
		*len = 64U;
		return key_sign(&S.dsc[slot], hash, sig);
	}
	if (!S.rsa[slot].present || cap < QDSD_RSA_MOD_LEN) {
		return -EIO;
	}
	if (mbedtls_rsa_pkcs1_sign(&S.rsa[slot].rsa, rng, NULL, MBEDTLS_MD_SHA256, 32, hash, sig) !=
	    0) {
		return -EIO;
	}
	*len = QDSD_RSA_MOD_LEN;
	return 0;
}

int port_dsc_delete(uint8_t slot)
{
	int rc;

	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	if (!S.dsc[slot].present && !S.rsa[slot].present) {
		return pwr_read() ? -EIO : -ENOENT;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	key_free(&S.dsc[slot]);
	rsa_drop(slot);
	return 0;
}

int port_dsc_pubkey(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len)
{
	if ((slot >= QDSD_DSC_SLOTS) || pwr_read()) {
		return -EIO;
	}
	if (alg == QDSD_ALG_P256) {
		if (!S.dsc[slot].present) {
			return -ENOENT;
		}
		if (cap < 65U) {
			return -ENOSPC;
		}
		*len = 65U;
		return key_pub(&S.dsc[slot], pub);
	}
	if (!S.rsa[slot].present) {
		return -ENOENT;
	}
	if (cap < QDSD_RSA_MOD_LEN) {
		return -ENOSPC;
	}
	if (mbedtls_rsa_export_raw(&S.rsa[slot].rsa, pub, QDSD_RSA_MOD_LEN, NULL, 0, NULL, 0, NULL,
				   0, NULL, 0) != 0) {
		return -EIO;
	}
	*len = QDSD_RSA_MOD_LEN;
	return 0;
}

/*
 * Like the element, the model stores what it is given: it does not check
 * that the private key matches pub. The core proves that with a probe
 * signature before using an imported key.
 */
int port_dsc_import(uint8_t slot, uint8_t alg, const uint8_t *priv, size_t priv_len,
		    const uint8_t *pub, size_t pub_len)
{
	static const uint8_t e[3] = { 0x01, 0x00, 0x01 };
	int rc;

	(void)pub;
	if (slot >= QDSD_DSC_SLOTS) {
		return -EINVAL;
	}
	if ((alg == QDSD_ALG_P256) && ((priv_len != 32U) || (pub_len != 65U))) {
		return -EINVAL;
	}
	if ((alg == QDSD_ALG_RSA2048) && ((priv_len != 640U) || (pub_len != QDSD_RSA_MOD_LEN))) {
		return -EINVAL;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	key_free(&S.dsc[slot]);
	rsa_drop(slot);
	S.dsc_origin[slot] = 2U;
	if (alg == QDSD_ALG_P256) {
		if (!S.curve[1]) {
			return -EIO;
		}
		mbedtls_ecp_keypair_init(&S.dsc[slot].kp);
		if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &S.dsc[slot].kp, priv, 32) != 0) {
			mbedtls_ecp_keypair_free(&S.dsc[slot].kp);
			return -EINVAL;
		}
		/* derive the public point so signing works */
		if (mbedtls_ecp_keypair_calc_public(&S.dsc[slot].kp, rng, NULL) != 0) {
			mbedtls_ecp_keypair_free(&S.dsc[slot].kp);
			return -EINVAL;
		}
		S.dsc[slot].present = true;
		return 0;
	}
	mbedtls_rsa_init(&S.rsa[slot].rsa);
	if ((mbedtls_rsa_import_raw(&S.rsa[slot].rsa, NULL, 0, priv, 128, priv + 128, 128, NULL, 0,
				    e, sizeof(e)) != 0) ||
	    (mbedtls_rsa_complete(&S.rsa[slot].rsa) != 0)) {
		mbedtls_rsa_free(&S.rsa[slot].rsa);
		return -EINVAL;
	}
	S.rsa[slot].present = true;
	return 0;
}

/* Mock SE052F attestation: "SIMKATT" | origin | fresh | SHA-256(pub) | sig. */
int port_dsc_vendor_attest(uint8_t slot, uint8_t alg, const uint8_t fresh[16],
			   uint8_t *out, size_t *out_len)
{
	uint8_t pub[QDSD_RSA_MOD_LEN];
	uint8_t tbs[7 + 1 + 16 + 32];
	uint8_t h[32];
	size_t plen = 0U;
	int rc;

	if (*out_len < sizeof(tbs) + 64U) {
		return -ENOSPC;
	}
	rc = port_dsc_pubkey(slot, alg, pub, sizeof(pub), &plen);
	if (rc) {
		return rc;
	}
	memcpy(tbs, "SIMKATT", 7);
	tbs[7] = S.dsc_origin[slot];
	memcpy(&tbs[8], fresh, 16);
	if ((port_sha256(pub, plen, &tbs[24]) != 0) || (port_sha256(tbs, sizeof(tbs), h) != 0) ||
	    (key_sign(&S.att_dsc, h, &out[sizeof(tbs)]) != 0)) {
		return -EIO;
	}
	memcpy(out, tbs, sizeof(tbs));
	*out_len = sizeof(tbs) + 64U;
	return 0;
}

int port_dsc_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN])
{
	if (pwr_read()) {
		return -EIO;
	}
	memcpy(uid, S.uid_dsc, QDSD_CHIP_UID_LEN);
	return 0;
}

/* ── Binary objects in the secure elements ──────────────────────────── */

static int obj_ref(port_obj_t o, uint8_t idx, sim_obj_t **out)
{
	if (((int)o < 0) || (o >= PORT_OBJ_KIND_COUNT) || (idx >= SIM_OBJ_IDX)) {
		return -EINVAL;
	}
	*out = &S.obj[o][idx];
	return 0;
}

/* One WriteBinary APDU per PORT_OBJ_ATOMIC_MAX bytes, as on the device. */
static int obj_chunks(sim_obj_t *ob, size_t off, const uint8_t *buf, size_t len)
{
	size_t done = 0U;
	int rc;

	while (done < len) {
		size_t n = len - done;

		if (n > PORT_OBJ_ATOMIC_MAX) {
			n = PORT_OBJ_ATOMIC_MAX;
		}
		rc = pwr_write();
		if (rc) {
			return rc;
		}
		memcpy(&ob->data[off + done], &buf[done], n);
		done += n;
	}
	return 0;
}

int port_obj_read(port_obj_t o, uint8_t idx, uint8_t *buf, size_t cap, size_t *len)
{
	sim_obj_t *ob;

	if (obj_ref(o, idx, &ob) || pwr_read()) {
		return -EIO;
	}
	if (!ob->present) {
		return -ENOENT;
	}
	*len = ob->len;
	if (buf == NULL) {
		return 0;
	}
	if (cap < ob->len) {
		return -ENOSPC;
	}
	memcpy(buf, ob->data, ob->len);
	return 0;
}

int port_obj_write(port_obj_t o, uint8_t idx, const uint8_t *buf, size_t len)
{
	sim_obj_t *ob;
	int rc;

	if (obj_ref(o, idx, &ob) || (len == 0U) || (len > SIM_OBJ_MAX)) {
		return -EINVAL;
	}
	if (ob->present && (ob->len != len)) {
		rc = pwr_write(); /* DeleteSecureObject */
		if (rc) {
			return rc;
		}
		ob->present = false;
	}
	if (!ob->present) {
		/* WriteBinary with TAG_3 length creates a zero-filled file. */
		rc = pwr_write();
		if (rc) {
			return rc;
		}
		memset(ob->data, 0, sizeof(ob->data));
		ob->present = true;
		ob->len = len;
		{
			size_t n = (len > PORT_OBJ_ATOMIC_MAX) ? PORT_OBJ_ATOMIC_MAX : len;

			memcpy(ob->data, buf, n);
			return obj_chunks(ob, n, &buf[n], len - n);
		}
	}
	return obj_chunks(ob, 0U, buf, len);
}

int port_obj_patch(port_obj_t o, uint8_t idx, size_t off, const uint8_t *buf, size_t len)
{
	sim_obj_t *ob;

	if (obj_ref(o, idx, &ob) || pwr_read()) {
		return -EIO;
	}
	if (!ob->present) {
		return -ENOENT;
	}
	if ((off > ob->len) || (len > ob->len - off)) {
		return -EINVAL;
	}
	return obj_chunks(ob, off, buf, len);
}

int port_obj_delete(port_obj_t o, uint8_t idx)
{
	sim_obj_t *ob;
	int rc;

	if (obj_ref(o, idx, &ob)) {
		return -EINVAL;
	}
	if (!ob->present) {
		return pwr_read() ? -EIO : -ENOENT;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	ob->present = false;
	ob->len = 0U;
	return 0;
}

/* ── Factory reset (FACTORY_RESET UserID + DeleteAll) ───────────────── */

int port_wipe_auth_set(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	int rc = pwr_write();

	if (rc) {
		return rc;
	}
	S.wipe[se].present = true;
	memcpy(S.wipe[se].secret, secret, QDSD_WIPE_SECRET_LEN);
	return 0;
}

int port_wipe_auth_check(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	if (pwr_read()) {
		return -EIO;
	}
	if (!S.wipe[se].present) {
		return -ENOENT;
	}
	return (memcmp(S.wipe[se].secret, secret, QDSD_WIPE_SECRET_LEN) == 0) ? 0 : -EACCES;
}

int port_se_wipe(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN])
{
	int i;
	int rc = port_wipe_auth_check(se, secret);

	if (rc) {
		return (rc == -ENOENT) ? -EACCES : rc;
	}
	rc = pwr_write(); /* DeleteAll is one command */
	if (rc) {
		return rc;
	}
	if (se == PORT_SE_DEV) {
		key_free(&S.devkey);
		memset(S.pub_present, 0, sizeof(S.pub_present));
		memset(S.ctr_present, 0, sizeof(S.ctr_present));
		memset(S.ctr, 0, sizeof(S.ctr));
		S.state_present = false;
		S.state_len = 0U;
		for (i = 0; i < SIM_OBJ_IDX; i++) {
			S.obj[PORT_OBJ_DEVICE_CERT][i].present = false;
			S.obj[PORT_OBJ_RECEIPT][i].present = false;
		}
	} else {
		for (i = 0; i < (int)QDSD_DSC_SLOTS; i++) {
			key_free(&S.dsc[i]);
			rsa_drop((uint8_t)i);
			S.dsc_origin[i] = 0U;
		}
		for (i = 0; i < SIM_OBJ_IDX; i++) {
			S.obj[PORT_OBJ_SLOT_REC][i].present = false;
			S.obj[PORT_OBJ_SLOT_CERT][i].present = false;
		}
	}
	S.wipe[se].present = false;
	S.curve[se] = false;
	return 0;
}

int port_se_prepare(port_se_t se)
{
	int rc;

	if (S.curve[se]) {
		return pwr_read();
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	S.curve[se] = true;
	return 0;
}

/* ── NVS model ──────────────────────────────────────────────────────── */

static int nvs_find(uint16_t id)
{
	int i;

	for (i = 0; i < SIM_NVS_MAX; i++) {
		if (S.nvs[i].used && (S.nvs[i].id == id)) {
			return i;
		}
	}
	return -1;
}

int port_nvs_read(uint16_t id, void *buf, size_t cap, size_t *len)
{
	int i;

	if (pwr_read()) {
		return -EIO;
	}
	i = nvs_find(id);
	if (i < 0) {
		return -ENOENT;
	}
	*len = S.nvs[i].len;
	if (buf == NULL) {
		return 0;
	}
	if (cap < S.nvs[i].len) {
		return -ENOSPC;
	}
	memcpy(buf, S.nvs[i].data, S.nvs[i].len);
	return 0;
}

int port_nvs_write(uint16_t id, const void *buf, size_t len)
{
	int i;
	int rc;

	if (len > SIM_NVS_REC) {
		return -ENOSPC;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	i = nvs_find(id);
	if (i < 0) {
		for (i = 0; i < SIM_NVS_MAX && S.nvs[i].used; i++) {
		}
		if (i == SIM_NVS_MAX) {
			return -ENOSPC;
		}
	}
	S.nvs[i].used = true;
	S.nvs[i].id = id;
	S.nvs[i].len = len;
	memcpy(S.nvs[i].data, buf, len);
	return 0;
}

int port_nvs_delete(uint16_t id)
{
	int i = nvs_find(id);
	int rc;

	if (i < 0) {
		return pwr_read() ? -EIO : -ENOENT;
	}
	rc = pwr_write();
	if (rc) {
		return rc;
	}
	S.nvs[i].used = false;
	return 0;
}

/* ── firmware update slot ───────────────────────────────────────────── */

/* Models a build with CONFIG_QDSD_FW_UPDATE=n (src/port/port_fw_none.c). */
static bool fw_none;
void sim_fw_none(int on) { fw_none = (on != 0); }

uint32_t port_fw_slot_size(void)
{
	return fw_none ? 0U : (uint32_t)sizeof(S.fw);
}

int port_fw_begin(uint32_t total)
{
	if (total > sizeof(S.fw)) {
		return -ENOSPC;
	}
	memset(S.fw, 0xFF, sizeof(S.fw));
	S.fw_total = total;
	S.fw_written = 0;
	S.fw_open = true;
	S.fw_pending = false;
	return 0;
}

int port_fw_write(const uint8_t *data, size_t len)
{
	if (!S.fw_open || (len > (S.fw_total - S.fw_written))) {
		return -EINVAL;
	}
	memcpy(&S.fw[S.fw_written], data, len);
	S.fw_written += (uint32_t)len;
	return 0;
}

int port_fw_finish(const uint8_t sha256[QDSD_SHA256_LEN])
{
	uint8_t h[32];

	if (!S.fw_open || (S.fw_written != S.fw_total)) {
		return -EINVAL;
	}
	if (mbedtls_sha256(S.fw, S.fw_total, h, 0) != 0) {
		return -EIO;
	}
	if (memcmp(h, sha256, 32) != 0) {
		return -EBADMSG;
	}
	S.fw_open = false;
	S.fw_pending = true;
	return 0;
}

void port_fw_abort(void)
{
	S.fw_open = false;
	S.fw_written = 0;
}

/* ── system ─────────────────────────────────────────────────────────── */

uint64_t port_uptime_ms(void)
{
	return S.now_ms;
}

void port_event(port_event_t evt, uint32_t arg)
{
	(void)arg;
	if ((int)evt >= 0 && (int)evt < 8) {
		S.events[evt]++;
	}
}
