/**
 * @file state_record.h
 * @brief Persistent lifecycle record + intent journal (stored in SE050).
 */
#ifndef QDSD_STATE_H
#define QDSD_STATE_H

#include <stdbool.h>
#include <stdint.h>

#define QDSD_DEVICE_ID_LEN 16U

typedef enum {
	LC_MANUFACTURING = 0x00,
	LC_UNASSIGNED    = 0x01,
	LC_BOUND         = 0x02,
	LC_READY         = 0x03,
	LC_FAULT         = 0xFF,
} qdsd_lc_t;

typedef enum {
	J_NONE   = 0,
	J_BIND   = 1,
	J_REBIND = 2,
	J_RESET  = 3,
	J_POLICY = 4,
	J_WIPE   = 5, /* v3.2: factory reset of both SEs in progress */
} qdsd_journal_op_t;

typedef struct {
	uint8_t  lc;
	bool     has_device_id;
	uint8_t  device_id[QDSD_DEVICE_ID_LEN];
	uint8_t  policy_flags;   /* token-enforced Subscriber settings */
	/* Intent journal: set before a multi-step change, cleared after it. */
	uint8_t  j_op;
	uint8_t  j_next_lc;
	uint8_t  j_flags;        /* policy flags to apply (BIND, POLICY) */
	uint32_t j_target;       /* binding_no (BIND/REBIND/RESET) or policy_no (POLICY) */
	uint8_t  j_key[65];
	/* Set when the record was read in the v1 (protocol v2) layout. */
	bool     migrated;
} qdsd_state_t;

/** Fresh MANUFACTURING record. */
void state_defaults(qdsd_state_t *s);
/**
 * 0 = loaded, -ENOENT = no record (fresh chip), -EBADMSG = corrupt.
 * Reads both the v1 layout (firmware 0.3) and v2; sets s->migrated for v1.
 */
int state_load(qdsd_state_t *s);
int state_save(const qdsd_state_t *s);

const char *state_lc_name(uint8_t lc);

#endif /* QDSD_STATE_H */
