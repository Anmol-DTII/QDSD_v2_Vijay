/**
 * @file token_ctx.h
 * @brief Shared context of the token subsystem (files in src/token only).
 *
 * The token subsystem is the command processor: one file per flow, all
 * sharing one context (g_tk) and the helpers declared here. Nothing outside
 * src/token includes this header; the transport uses token_engine.h.
 */
#ifndef TOKEN_CTX_H
#define TOKEN_CTX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "port/port.h"
#include "protocol/der.h"
#include "protocol/stmt.h"
#include "protocol/tlv.h"
#include "qdsd/qdsd_config.h"
#include "state_machine/state_record.h"
#include "token/token_engine.h"

/* ── Legacy MCU NVS records (firmware 0.3-0.5), migrated at boot ────── */

#define NVS_DEVICE_CERT     0x0100U
#define NVS_SLOT_META(s)    ((uint16_t)(0x0110U + (s)))
#define NVS_SLOT_CERT(s)    ((uint16_t)(0x0120U + (s)))
#define NVS_LEGACY_SLOTS    8U    /* ids reserved for up to 8 slots */
#define SLOT_META_V1_LEN    70U   /* 0.3/0.4: status, seq, P-256 point */
#define SLOT_META_V05_MAGIC 0x53U /* 'S': 0.5 layout */
#define SLOT_META_V05_HDR   10U
#define SPKI_MAX            294U  /* RSA-2048 SubjectPublicKeyInfo */

/* ── Slot record in SE052F: fixed size, so every update is one atomic write ── */

#define SLOT_REC_LEN   48U
#define SLOT_REC_MAGIC 0x53U /* 'S' */
#define SLOT_REC_VER   0x02U
#define SLOT_REC_BANK  44U   /* byte holding the current certificate bank (0/1) */

/* Certificate object of slot s in bank b: PORT_OBJ_SLOT_CERT index. */
#define CERT_IDX(s, b) ((uint8_t)((s) + ((b) * QDSD_DSC_SLOTS)))

/* ── Signing-receipt ring entry in SE050 ─────────────────────────────── */
/*
 *   0   'R'
 *   1   kind: 0 empty, 1 pending (signature in progress), 2 final
 *   2   stmt_len u16
 *   4   dsc_sig_len u16
 *   6   reserved
 *   8   receipt statement (<= RCPT_STMT_CAP)          } head: one atomic write
 * 208   device signature r||s (64)                     } tail: written before
 * 272   DSC signature (<= 256)                         }       the final head
 */
#define RCPT_HDR        8U
#define RCPT_STMT_CAP   200U
#define RCPT_HEAD_LEN   (RCPT_HDR + RCPT_STMT_CAP)
#define RCPT_DEVSIG_OFF RCPT_HEAD_LEN
#define RCPT_DSCSIG_OFF (RCPT_DEVSIG_OFF + QDSD_P256_SIG_LEN)
#define RCPT_LEN        (RCPT_DSCSIG_OFF + QDSD_DSC_SIG_MAX)
#define RCPT_TAIL_LEN   (RCPT_LEN - RCPT_HEAD_LEN)
#define RCPT_EMPTY      0U
#define RCPT_PENDING    1U
#define RCPT_FINAL      2U

#if RCPT_HEAD_LEN > PORT_OBJ_ATOMIC_MAX
#error "receipt head must fit one atomic secure-element write"
#endif
#if SLOT_REC_LEN > PORT_OBJ_ATOMIC_MAX
#error "slot record must fit one atomic secure-element write"
#endif

/* SIGN_RECEIPT status (PROTOCOL.md §2.7) */
#define RCPT_STATUS_OK          0x00U
#define RCPT_STATUS_SE_FAILED   0x01U
#define RCPT_STATUS_INTERRUPTED 0x02U

/* Response-only tags (PROTOCOL.md §2.3) */
#define T_CHIP_UID        0x1BU
#define T_VENDOR_ATT      0x1CU
#define T_DEVICE_CERT     0x1DU
#define T_CMD_PUB         0x1EU
#define T_SLOT_ENTRY      0x20U
#define T_PROTO_VER       0x21U
#define T_SLOT_COUNT      0x22U
#define T_OFFSET          0x23U
#define T_TOTAL           0x24U
#define T_CHUNK           0x25U
#define T_IMAGE_SIZE      0x28U
#define T_IMAGE_SHA256    0x29U
#define T_IMAGE_OFFSET    0x2AU
#define T_PROTO_MINOR     0x2BU
#define T_WIPE_SECRET_DEV 0x31U
#define T_WIPE_SECRET_DSC 0x32U
#define T_AGENT_PUB       0x34U
#define T_IMPORT_CT       0x35U
#define T_IMPORT_CERT     0x36U
#define T_DSC_UID         0x37U
#define T_KEY_VENDOR_ATT  0x38U
#define T_SESSION_EPOCH   0x39U /* u32, random per session (v3.3) */
#define T_NONCE_STATUS    0x3AU /* u8 reason with 6984 (v3.3) */

/* Why a SIGN / LOGIN nonce is not usable (T_NONCE_STATUS, PROTOCOL.md §4.8). */
#define NONCE_WHY_EXPIRED     0x01U
#define NONCE_WHY_REPLACED    0x02U /* evicted by a newer GET_SESSION_NONCE */
#define NONCE_WHY_DISCARDED   0x03U /* REBIND, RESET, wipe, USB reset */
#define NONCE_WHY_UNKNOWN     0x04U /* never issued here (or token restarted) */
#define NONCE_WHY_USED        0x05U /* already consumed by a SIGN or LOGIN */
#define NONCE_WHY_FAILS       0x06U /* too many failed signature checks */
#define NONCE_WHY_KEY_CHANGED 0x07U /* approval names an earlier key in that slot */
#define NONCE_GRAVE           8U    /* dropped nonces remembered, with the reason */
#define NONCE_PFX             8U

/* ISO 7816 command chaining / GET RESPONSE (v3.3) */
#define CLA_CHAIN             0x10U
#define INS_GET_RESPONSE      0xC0U
#define SW_CHAIN_LAST_EXPECTED 0x6883U
#define SHORT_RSP_MAX         256U
#define T_STMT            0x70U
#define T_STMT_SIG        0x71U
#define T_DSC_SIG_RAW     0x72U
#define T_DSC_SIG_DER     0x73U
#define T_CRI             0x74U
#define T_CSR_DIGEST      0x75U

/* MCUboot image header (bootutil/image.h) */
#define MCUBOOT_MAGIC       0x96F3B83DU
#define MCUBOOT_HDR_MIN     32U

#define DEVID_PREFIX     "QDSD-DEVID"
#define DEVID_PREFIX_LEN 10U

/* .pfx import key transport (PROTOCOL.md §4.6) */
#define IMPORT_KDF_LABEL     "QDSD-IMPORT-V1"
#define IMPORT_KDF_LABEL_LEN 14U
#define IMPORT_CHECK_LABEL   "QDSD-IMPORT-CHECK"
#define IMPORT_IV_LEN        12U
#define IMPORT_TAG_LEN       16U
#define IMPORT_PT_P256       32U
#define IMPORT_PT_RSA        (5U * 128U)

typedef enum {
	SLOT_EMPTY     = 0,
	SLOT_PENDING   = 1,
	SLOT_CERTIFIED = 2,
} slot_status_t;

typedef enum {
	CSR_NONE   = 0, /* no certificate-request signature yet               */
	CSR_FULL   = 1, /* signed full CertificationRequestInfo (repeatable)  */
	CSR_DIGEST = 2, /* signed a bare digest: the key's one allowed signature */
} csr_mode_t;

typedef struct {
	uint8_t  status;
	uint8_t  alg;       /* QDSD_ALG_* */
	uint8_t  origin;    /* ORIGIN_* */
	uint8_t  csr_mode;  /* csr_mode_t */
	uint32_t seq;       /* keygen counter value that created the key */
	uint16_t cert_len;  /* 0 = no certificate */
	uint8_t  cert_hash[32];
	uint8_t  cert_bank; /* which of the slot's two certificate objects is current */
} slot_meta_t;

typedef struct {
	uint8_t        cla;
	uint8_t        ins;
	uint8_t        p1;
	uint8_t        p2;
	const uint8_t *data;
	size_t         lc;
	size_t         le;   /* 0 = absent; 256 / 65536 for "00" */
	bool           ext;  /* extended-length form (whole response in one go) */
} apdu_t;

typedef struct {
	qdsd_state_t st;
	bool         fault;
	bool         wipe_pending; /* journal says a factory wipe was cut off */
	bool         state_lost;   /* lifecycle record corrupt, or gone on a personalised token */
	bool         selected;
	bool         keep_data_on_error;

	/* Session (Flow 2b): RAM only, recomputed at SELECT. */
	struct {
		bool     started;     /* first SELECT of this USB connection seen */
		bool     card_auth;   /* LOGIN or BIND since the last card power cycle */
		bool     logged_in;
		bool     pairing;     /* opened by BIND, lasts until unplug */
		uint64_t last_ms;     /* last accepted command, for idle timeout */
	} sess;

	/* Outstanding nonces (several, so approvals don't evict each other). */
	struct {
		bool     valid;
		uint8_t  v[32];
		uint64_t issued_ms;
		uint32_t order;
		uint8_t  fails;
	} nonce[QDSD_NONCE_SLOTS];
	uint32_t nonce_order;
	struct {
		uint8_t pfx[NONCE_PFX];
		uint8_t why;
	} grave[NONCE_GRAVE];
	uint8_t  grave_next;
	uint32_t epoch;           /* random per session (GET_INFO 39) */

	/* ISO 7816 command chaining and GET RESPONSE */
	struct {
		bool     active;
		uint8_t  cla, ins, p1, p2;
		uint16_t len;
	} chain;
	struct {
		uint16_t len;     /* data + SW held for GET RESPONSE */
		uint16_t off;
	} gr;

	/* In-app firmware update, RAM only. */
	struct {
		bool     active;
		bool     header_ok;
		uint32_t total;
		uint32_t written;
		uint8_t  sha256[32];
	} fw;

	struct {
		bool     active;
		uint8_t  slot;
		uint16_t total;
		uint16_t got;
	} certw;

	/* .pfx import (v3.2), RAM only. */
	struct {
		bool     active;
		uint8_t  alg;
		uint32_t seq;
		uint8_t  cert_hash[32];
		uint8_t  pub[QDSD_P256_PUB_LEN]; /* token's ephemeral key */
		uint16_t total;
		uint16_t got;
	} imp;

	uint8_t chain_buf[QDSD_APDU_MAX];
	uint8_t gr_buf[QDSD_RSP_MAX];
	uint8_t certw_buf[QDSD_CERT_MAX];
	uint8_t imp_buf[QDSD_IMPORT_MAX];
	uint8_t read_buf[QDSD_CERT_MAX];
	uint8_t stmt_buf[512];
	uint8_t spki[SPKI_MAX];
	uint8_t rcpt_head[RCPT_HEAD_LEN];
	uint8_t rcpt_tail[RCPT_TAIL_LEN];
} token_ctx_t;

/** The one token context (RAM only; persistent state lives in the SEs). */
extern token_ctx_t g_tk;

/* token_engine.c */
void secure_zero(void *p, size_t n);
bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n);
bool lc_is(uint8_t a, uint8_t b);
bool alg_ok(uint8_t alg);
void fw_version(uint8_t v[4]);
int pubkey_hash(port_pubkey_t which, uint8_t h[32]);
int read_counters(uint32_t *binding, uint32_t *keygen, uint32_t *sign);
int counter_to(port_counter_t c, uint32_t target);
bool ok_or_absent(int rc);
int set_lc(uint8_t lc);
void nonce_drop_at(size_t i, uint8_t why);
void nonce_drop_all(uint8_t why);
int nonce_find(const uint8_t *v);
uint16_t nonce_stale(tlv_writer_t *rsp, const uint8_t *v, uint8_t why);
void new_epoch(void);
void nonce_fail(int i);
void certw_abort(void);
void import_abort(void);
bool login_required(void);
bool session_exists(void);
void session_recompute(void);
bool session_logged_in(void);
uint8_t session_byte(void);
bool method_ok(const stmt_t *st);
bool policy_flags_ok(uint8_t flags);
int device_sign(const tlv_writer_t *w, uint8_t sig[QDSD_P256_SIG_LEN]);
uint16_t emit_device_signed(tlv_writer_t *rsp, const tlv_writer_t *w);
uint16_t get_signed(const apdu_t *a, uint8_t purpose_a, uint8_t purpose_b,
		stmt_t *st, tlv_item_t *sig);
uint16_t verify_with(port_pubkey_t which, const stmt_t *st, const tlv_item_t *sig);

/* token_store.c */
int slot_load(uint8_t slot, slot_meta_t *m);
int slot_save(uint8_t slot, const slot_meta_t *m);
int slot_save_empty(uint8_t slot);
int slot_spki(uint8_t slot, uint8_t alg, uint8_t *spki, size_t cap, size_t *len);
int slot_cert_read(uint8_t slot, const slot_meta_t *m, uint8_t *buf, size_t cap,
		size_t *len);
int slot_cert_store(uint8_t slot, slot_meta_t *m, const uint8_t *cert, size_t len);
int slot_erase(uint8_t slot);
int slot_certs_delete(uint8_t slot);
bool any_certified(void);
int migrate_legacy(void);
int check_objects(void);

/* token_receipt.c */
int rcpt_put_head(uint32_t ctr, uint8_t kind, const uint8_t *stmt, size_t len,
		size_t dsc_len);
int rcpt_put_final(uint32_t ctr, const uint8_t *stmt, size_t len,
		const uint8_t devsig[QDSD_P256_SIG_LEN], const uint8_t *dsc, size_t dsc_len);
int rcpt_ensure(void);
int rcpt_clear_all(void);
int rcpt_recover(void);
uint16_t h_get_receipt(const apdu_t *a, tlv_writer_t *rsp);

/* token_journal.c */
int journal_apply(void);
uint16_t journal_run(uint8_t op, uint32_t target, const uint8_t *key, uint8_t flags,
		uint8_t next_lc);

/* token_factory.c */
uint16_t h_factory_init(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_factory_personalise(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_factory_close(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_factory_wipe(const apdu_t *a, tlv_writer_t *rsp);

/* token_pairing.c */
uint16_t h_attest(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_bind(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_rebind(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_reset(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_policy(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_login(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_logout(const apdu_t *a, tlv_writer_t *rsp);

/* token_dsc.c */
int pick_slot(uint8_t *out);
uint16_t emit_key_attest(tlv_writer_t *rsp, uint32_t seq, uint8_t slot,
		const uint8_t *spki, size_t spki_len, uint8_t origin);
uint16_t h_keygen(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_sign_csr(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_write_cert(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_delete_key(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_get_key_attestation(const apdu_t *a, tlv_writer_t *rsp);

/* token_import.c */
uint16_t h_import_begin(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_import_data(const apdu_t *a, tlv_writer_t *rsp);

/* token_sign.c */
uint16_t h_get_nonce(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_sign(const apdu_t *a, tlv_writer_t *rsp);

/* token_update.c */
void fw_abort(void);
uint16_t h_update_begin(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_update_write(const apdu_t *a, tlv_writer_t *rsp);
uint16_t h_update_finish(const apdu_t *a, tlv_writer_t *rsp);

#endif /* TOKEN_CTX_H */
