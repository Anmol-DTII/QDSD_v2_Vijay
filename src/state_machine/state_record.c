/**
 * @file state_record.c
 * @brief Lifecycle record serialisation with CRC-32 (atomic SE050 object).
 *
 * The SE050 binary object keeps the size it was created with, so every layout
 * is exactly 96 bytes.
 *
 * Layout v2 (firmware 0.4, protocol v3), big-endian:
 *   0  'Q'
 *   1  0x02          version
 *   2  lc
 *   3  flags         bit0 = has_device_id
 *   4  device_id[16]
 *  20  policy_flags
 *  21  j_op
 *  22  j_next_lc
 *  23  j_flags
 *  24  j_target u32
 *  28  j_key X||Y (64; the 0x04 prefix of the uncompressed point is implied)
 *  92  crc32 over bytes 0..91
 *
 * Layout v1 (firmware 0.3) is read for migration:
 *   'Q' 'S' 0x01 lc flags device_id[16] j_op j_next_lc j_binding[4] j_key[65] crc
 */
#include <errno.h>
#include <string.h>

#include "port/port.h"
#include "state_machine/state_record.h"
#include "protocol/stmt.h"
#include "protocol/tlv.h"

#define ST_LEN     96U
#define ST_CRC_OFF 92U

static uint32_t crc32(const uint8_t *p, size_t n)
{
	uint32_t c = 0xFFFFFFFFU;
	size_t i;
	int k;

	for (i = 0U; i < n; i++) {
		c ^= p[i];
		for (k = 0; k < 8; k++) {
			c = (c >> 1) ^ (0xEDB88320U & (0U - (c & 1U)));
		}
	}
	return ~c;
}

static bool lc_valid(uint8_t lc)
{
	return (lc == LC_MANUFACTURING) || (lc == LC_UNASSIGNED) || (lc == LC_BOUND) ||
	       (lc == LC_READY);
}

void state_defaults(qdsd_state_t *s)
{
	memset(s, 0, sizeof(*s));
	s->lc = LC_MANUFACTURING;
	s->j_op = J_NONE;
}

static int load_v1(const uint8_t *b, qdsd_state_t *s)
{
	if (!lc_valid(b[3]) || (b[21] > J_RESET)) {
		return -EBADMSG;
	}
	s->lc = b[3];
	s->has_device_id = (b[4] & 0x01U) != 0U;
	memcpy(s->device_id, &b[5], QDSD_DEVICE_ID_LEN);
	s->j_op = b[21];
	s->j_next_lc = b[22];
	s->j_target = tlv_be32(&b[23]);
	memcpy(s->j_key, &b[27], sizeof(s->j_key));
	/* Flows v3.2 default: a paired token requires login approval. */
	s->policy_flags = ((s->lc == LC_BOUND) || (s->lc == LC_READY)) ?
			  (uint8_t)POLICY_LOGIN_REQUIRED : 0U;
	s->j_flags = s->policy_flags;
	if (s->j_op == J_BIND) {
		s->j_flags = POLICY_LOGIN_REQUIRED;
	}
	s->migrated = true;
	return 0;
}

static int load_v2(const uint8_t *b, qdsd_state_t *s)
{
	if (!lc_valid(b[2]) || (b[21] > J_WIPE) || ((b[20] & ~POLICY_DEFINED_BITS) != 0U) ||
	    ((b[23] & ~POLICY_DEFINED_BITS) != 0U)) {
		return -EBADMSG;
	}
	s->lc = b[2];
	s->has_device_id = (b[3] & 0x01U) != 0U;
	memcpy(s->device_id, &b[4], QDSD_DEVICE_ID_LEN);
	s->policy_flags = b[20];
	s->j_op = b[21];
	s->j_next_lc = b[22];
	s->j_flags = b[23];
	s->j_target = tlv_be32(&b[24]);
	if ((s->j_op == J_BIND) || (s->j_op == J_REBIND)) {
		s->j_key[0] = 0x04U;
		memcpy(&s->j_key[1], &b[28], 64U);
	}
	return 0;
}

int state_load(qdsd_state_t *s)
{
	uint8_t b[ST_LEN];
	size_t len = 0U;
	int rc;

	state_defaults(s);
	rc = port_state_read(b, sizeof(b), &len);
	if (rc != 0) {
		return rc;
	}
	if ((len != ST_LEN) || (crc32(b, ST_CRC_OFF) != tlv_be32(&b[ST_CRC_OFF]))) {
		return -EBADMSG;
	}
	if ((b[0] == 'Q') && (b[1] == 'S') && (b[2] == 0x01U)) {
		return load_v1(b, s);
	}
	if ((b[0] == 'Q') && (b[1] == 0x02U)) {
		return load_v2(b, s);
	}
	return -EBADMSG;
}

int state_save(const qdsd_state_t *s)
{
	uint8_t b[ST_LEN];

	memset(b, 0, sizeof(b));
	b[0] = 'Q';
	b[1] = 0x02U;
	b[2] = s->lc;
	b[3] = s->has_device_id ? 0x01U : 0x00U;
	memcpy(&b[4], s->device_id, QDSD_DEVICE_ID_LEN);
	b[20] = s->policy_flags;
	b[21] = s->j_op;
	b[22] = s->j_next_lc;
	b[23] = s->j_flags;
	tlv_wr_be32(&b[24], s->j_target);
	if ((s->j_op == J_BIND) || (s->j_op == J_REBIND)) {
		if (s->j_key[0] != 0x04U) {
			return -EINVAL; /* only uncompressed points are journalled */
		}
		memcpy(&b[28], &s->j_key[1], 64U);
	}
	tlv_wr_be32(&b[ST_CRC_OFF], crc32(b, ST_CRC_OFF));
	return port_state_write(b, sizeof(b));
}

const char *state_lc_name(uint8_t lc)
{
	switch (lc) {
	case LC_MANUFACTURING: return "MANUFACTURING";
	case LC_UNASSIGNED:    return "UNASSIGNED";
	case LC_BOUND:         return "BOUND";
	case LC_READY:         return "READY";
	case LC_FAULT:         return "FAULT";
	default:               return "?";
	}
}
