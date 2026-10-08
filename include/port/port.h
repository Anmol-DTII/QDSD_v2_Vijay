/**
 * @file port.h
 * @brief Hardware port interface for the portable QDSD core.
 *
 * The core (protocol, lifecycle, journal, policy) is plain C with no RTOS or
 * vendor dependency. Everything that touches hardware goes through this
 * interface. Two implementations exist:
 *   - src/port     : nRF52840 + SE050 (device trust) + SE052F (DSC keys)
 *   - tests/host   : software model used by the host test suite
 *
 * Since protocol v3.2 every persistent record lives inside a secure element:
 * certificates, slot records and signing receipts included. MCU flash (NVS)
 * is only read once, to move records written by firmware 0.3-0.5.
 *
 * All functions return 0 on success or a negative errno-style code.
 * -ENOENT means "object does not exist" and is part of normal control flow.
 */
#ifndef QDSD_PORT_H
#define QDSD_PORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QDSD_P256_PUB_LEN   65U  /* 04 || X || Y */
#define QDSD_P256_SIG_LEN   64U  /* r || s       */
#define QDSD_SHA256_LEN     32U
#define QDSD_CHIP_UID_LEN   18U

/* ── Randomness and MCU-side crypto ─────────────────────────────────── */

int port_random(uint8_t *buf, size_t len);
int port_sha256(const uint8_t *data, size_t len, uint8_t out[QDSD_SHA256_LEN]);
/** SHA-256 in pieces (one at a time): begin, any number of updates, finish. */
int port_sha256_begin(void);
int port_sha256_update(const uint8_t *data, size_t len);
int port_sha256_finish(uint8_t out[QDSD_SHA256_LEN]);
/** Returns 0 only if sig is a valid P-256 ECDSA signature of hash by pub. */
int port_ecdsa_p256_verify(const uint8_t pub[QDSD_P256_PUB_LEN],
			   const uint8_t hash[QDSD_SHA256_LEN],
			   const uint8_t sig[QDSD_P256_SIG_LEN]);
/** Returns 0 only if pub is a valid uncompressed point on P-256. */
int port_p256_pubkey_check(const uint8_t pub[QDSD_P256_PUB_LEN]);
/**
 * MCU-side check of a DSC signature over a SHA-256 digest: P-256 raw r||s
 * (pub = 65-byte point) or RSA-2048 PKCS#1 v1.5 (pub = 256-byte modulus,
 * e = 65537). Used to prove an imported key matches its certificate.
 */
int port_sig_verify(uint8_t alg, const uint8_t *pub, size_t pub_len,
		    const uint8_t hash[QDSD_SHA256_LEN], const uint8_t *sig, size_t sig_len);

/* Key transport for imported (.pfx) keys: ephemeral ECDH on the MCU. */
/** Make a fresh ephemeral P-256 key pair (replacing any previous one). */
int port_ecdh_begin(uint8_t pub[QDSD_P256_PUB_LEN]);
/** Shared secret X coordinate with peer; destroys the ephemeral key. */
int port_ecdh_finish(const uint8_t peer[QDSD_P256_PUB_LEN], uint8_t z[32]);
void port_ecdh_clear(void);
/** AES-256-GCM decrypt with a 16-byte tag, which must follow ct in memory
 *  (tag == ct + len). -EBADMSG if the tag is wrong; pt is wiped on failure. */
int port_aes256gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
			   const uint8_t *aad, size_t aad_len,
			   const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt);

/* ── Device trust element (SE050) ───────────────────────────────────── */

/** Create the device key inside the secure element if it does not exist. */
int port_devkey_ensure(void);
int port_devkey_pubkey(uint8_t pub[QDSD_P256_PUB_LEN]);
int port_devkey_sign(const uint8_t hash[QDSD_SHA256_LEN], uint8_t sig[QDSD_P256_SIG_LEN]);
int port_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN]);
/**
 * Chip-vendor attestation of the device public key (SE050 ReadObject_W_Attst).
 * Output is the raw attested-read response; opaque to the core.
 */
int port_devkey_vendor_attest(const uint8_t *fresh, size_t fresh_len,
			      uint8_t *out, size_t *out_len);

typedef enum {
	PORT_PUBKEY_CMD = 0,     /* DTI command key (trust anchor) */
	PORT_PUBKEY_ACTIVATION,  /* Subscriber phone activation key */
} port_pubkey_t;

int port_pubkey_write(port_pubkey_t which, const uint8_t pub[QDSD_P256_PUB_LEN]);
int port_pubkey_read(port_pubkey_t which, uint8_t pub[QDSD_P256_PUB_LEN]);
int port_pubkey_delete(port_pubkey_t which);
/**
 * Verify a P-256 signature (raw r||s) over hash with a stored key, inside the
 * SE050 (ECDSAVerify), so the phone and cloud keys never leave the element.
 * 0 = valid, -EPERM = invalid, -ENOENT = key absent.
 */
int port_pubkey_verify(port_pubkey_t which, const uint8_t hash[QDSD_SHA256_LEN],
		       const uint8_t sig[QDSD_P256_SIG_LEN]);

typedef enum {
	PORT_CTR_BINDING = 0,
	PORT_CTR_KEYGEN,
	PORT_CTR_SIGN,
	PORT_CTR_POLICY,
	PORT_CTR_COUNT
} port_counter_t;

/** Create counter at 0 if missing; existing counters are left as they are. */
int port_counter_ensure(port_counter_t c);
int port_counter_read(port_counter_t c, uint32_t *value);
/** Increment by exactly one. Must be monotonic and persistent. */
int port_counter_inc(port_counter_t c);

/** Lifecycle state record. Write must be atomic (all or nothing). */
int port_state_read(uint8_t *buf, size_t cap, size_t *len);
int port_state_write(const uint8_t *buf, size_t len);

/* ── DSC element (SE052F) ───────────────────────────────────────────── */

#define QDSD_ALG_P256     0x00U
#define QDSD_ALG_RSA2048  0x01U
#define QDSD_RSA_MOD_LEN  256U  /* RSA-2048 modulus, big-endian, no sign byte */
#define QDSD_DSC_SIG_MAX  256U  /* largest DSC signature (RSA-2048) */

/**
 * Generate a fresh key pair of alg in slot, replacing any key there.
 * pub receives the raw public key: the 65-byte P-256 point, or the 256-byte
 * RSA-2048 modulus (public exponent must be 65537).
 */
int port_dsc_generate(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len);
/**
 * Sign a SHA-256 digest with the slot key: raw r||s (64 bytes) for P-256,
 * RSASSA-PKCS1-v1_5 with SHA-256 DigestInfo (256 bytes) for RSA-2048.
 */
int port_dsc_sign(uint8_t slot, uint8_t alg, const uint8_t hash[QDSD_SHA256_LEN],
		  uint8_t *sig, size_t cap, size_t *len);
/** Delete slot key; -ENOENT if empty is acceptable to callers. */
int port_dsc_delete(uint8_t slot);
/** Read the slot key's public part (same format as port_dsc_generate). */
int port_dsc_pubkey(uint8_t slot, uint8_t alg, uint8_t *pub, size_t cap, size_t *len);
/**
 * Write an externally created key pair into slot (institutional .pfx import),
 * replacing any key there. P-256: priv = d (32), pub = 65-byte point.
 * RSA-2048: priv = p||q||dp||dq||qinv (5 x 128), pub = 256-byte modulus.
 * The element records the key's origin as external.
 */
int port_dsc_import(uint8_t slot, uint8_t alg, const uint8_t *priv, size_t priv_len,
		    const uint8_t *pub, size_t pub_len);
/**
 * SE052F chip-vendor attestation of the slot key (ReadObject_W_Attst with the
 * SE052F's own NXP attestation key): proves the key is inside that element and
 * reports its origin (generated inside or imported). Opaque to the core.
 * -ENOTSUP if the element cannot attest this key type.
 */
int port_dsc_vendor_attest(uint8_t slot, uint8_t alg, const uint8_t fresh[16],
			   uint8_t *out, size_t *out_len);
/** SE052F unique id (0x7FFF0206). */
int port_dsc_chip_uid(uint8_t uid[QDSD_CHIP_UID_LEN]);

/* ── Records stored inside the secure elements (binary objects) ─────── */

typedef enum {
	PORT_OBJ_DEVICE_CERT = 0, /* SE050:  device X.509 certificate          */
	PORT_OBJ_RECEIPT,         /* SE050:  signing receipt ring, idx = entry  */
	PORT_OBJ_SLOT_REC,        /* SE052F: slot record, idx = slot            */
	PORT_OBJ_SLOT_CERT,       /* SE052F: DSC certificate, idx = slot + bank * QDSD_DSC_SLOTS */
	PORT_OBJ_KIND_COUNT
} port_obj_t;

/**
 * Largest write the element applies all-or-nothing (one WriteBinary APDU
 * under Platform SCP03 without extended length). Longer writes are split and
 * the core orders them so a power cut never leaves a record half-valid.
 */
#define PORT_OBJ_ATOMIC_MAX 208U

/**
 * Read a whole object. buf may be NULL with cap 0 to get the size only.
 * -ENOENT if absent, -ENOSPC if cap is too small.
 */
int port_obj_read(port_obj_t o, uint8_t idx, uint8_t *buf, size_t cap, size_t *len);
/**
 * Replace a whole object. An object of the same size is overwritten in place
 * (atomic if len <= PORT_OBJ_ATOMIC_MAX); otherwise it is deleted and created.
 */
int port_obj_write(port_obj_t o, uint8_t idx, const uint8_t *buf, size_t len);
/** Overwrite bytes [off, off+len) of an existing object (atomic if len <= MAX). */
int port_obj_patch(port_obj_t o, uint8_t idx, size_t off, const uint8_t *buf, size_t len);
/** -ENOENT if absent. */
int port_obj_delete(port_obj_t o, uint8_t idx);

/* ── Factory reset of the secure elements ───────────────────────────── */

typedef enum {
	PORT_SE_DEV = 0, /* SE050  */
	PORT_SE_DSC = 1, /* SE052F */
} port_se_t;

#define QDSD_WIPE_SECRET_LEN 16U

/**
 * Create (or replace) the element's FACTORY_RESET authentication object
 * (UserID at 0x7FFF0205) with a secret only DTI holds.
 */
int port_wipe_auth_set(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN]);
/**
 * Check secret against the FACTORY_RESET object without erasing anything.
 * 0 = correct, -EACCES = wrong, -ENOENT = no FACTORY_RESET object yet.
 */
int port_wipe_auth_check(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN]);
/**
 * Open a session authenticated with the FACTORY_RESET object and run
 * DeleteAll: every key, record and counter is erased (NXP trust-provisioned
 * objects stay). -EACCES if the secret is wrong; the element enforces this.
 */
int port_se_wipe(port_se_t se, const uint8_t secret[QDSD_WIPE_SECRET_LEN]);

/**
 * Make an element ready for key objects: create the NIST P-256 curve if it is
 * missing (a wiped element has no curves). Called by FACTORY_INIT.
 */
int port_se_prepare(port_se_t se);

/* ── MCU flash: legacy records only (firmware 0.3-0.5), read to migrate ── */

int port_nvs_read(uint16_t id, void *buf, size_t cap, size_t *len);
int port_nvs_write(uint16_t id, const void *buf, size_t len);
int port_nvs_delete(uint16_t id);

/* ── Firmware update (MCUboot secondary slot) ───────────────────────── */

/** Size of the secondary image slot in bytes. */
uint32_t port_fw_slot_size(void);
/** Start writing a new image of total bytes into the secondary slot. */
int port_fw_begin(uint32_t total);
/** Append bytes sequentially. */
int port_fw_write(const uint8_t *data, size_t len);
/**
 * Flush, check that SHA-256 of the written image equals sha256, then mark
 * the image for installation at next boot (MCUboot verifies the signature).
 */
int port_fw_finish(const uint8_t sha256[QDSD_SHA256_LEN]);
/** Abandon a partial write (nothing is installed). */
void port_fw_abort(void);

/* ── Install drive (external QSPI NOR flash, docs/INSTALL_DRIVE.md) ──── */

/** Erase granularity of the drive flash (64 KB blocks). */
#define QDSD_DRIVE_ERASE_BLOCK 0x10000U

/** Bytes of drive flash; 0 when the board has none (build without the drive). */
uint32_t port_drive_size(void);
int port_drive_read(uint32_t off, void *buf, size_t len);
/** Erase [off, off + len); both multiples of QDSD_DRIVE_ERASE_BLOCK. */
int port_drive_erase(uint32_t off, uint32_t len);
/** Program erased flash (NOR: bits only go from 1 to 0). */
int port_drive_write(uint32_t off, const void *buf, size_t len);
/**
 * Tell the USB drive whether a valid image is there (present) and how many
 * 512-byte blocks it shows. Called at boot and by FACTORY_DRIVE.
 */
void port_drive_medium(bool present, uint32_t blocks);

/* ── System ─────────────────────────────────────────────────────────── */

uint64_t port_uptime_ms(void);

typedef enum {
	PORT_EVT_SIGNING_START = 0,
	PORT_EVT_SIGNING_DONE,
	PORT_EVT_STATE_CHANGED,
	PORT_EVT_UPDATE_REBOOT,  /* image staged: reboot so MCUboot installs it */
} port_event_t;

/** Notification hook for LEDs, update mode and logging. May be a no-op. */
void port_event(port_event_t evt, uint32_t arg);

#ifdef __cplusplus
}
#endif

#endif /* QDSD_PORT_H */
