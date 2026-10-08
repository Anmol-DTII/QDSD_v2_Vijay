/**
 * @file ccid.c
 * @brief USB CCID message layer: one slot, card always present, extended APDU.
 *
 * The reader presents a card that is always inserted (the QDSD applet). Power
 * on/off map to a token session reset, like a smart card being re-inserted.
 * Only the messages an APDU-level reader must support are implemented; the
 * rest answer "command not supported" as the CCID specification requires.
 */
#include <string.h>

#include "usb/ccid.h"

/* bStatus: bmICCStatus (bits 0-1) | bmCommandStatus (bits 6-7) */
#define ICC_ACTIVE      0x00U
#define ICC_INACTIVE    0x01U
#define ICC_ABSENT      0x02U
#define CMD_OK          0x00U
#define CMD_FAILED      0x40U
#define CMD_TIME_EXT    0x80U

/* bError values (CCID rev 1.1 §6.2.6) */
#define ERR_CMD_NOT_SUPPORTED 0x00U
#define ERR_BAD_LENGTH        0x01U
#define ERR_BAD_SLOT          0x05U
#define ERR_BAD_LEVEL_PARAM   0x08U
#define ERR_ICC_MUTE          0xFEU

/*
 * ATR: TS 3B, T0 8C (TD1 follows, 12 historical bytes), TD1 80 (TD2 follows,
 * T=0), TD2 01 (T=1), historical "QDSDAscertEN", TCK. Windows derives the
 * card's Plug-and-Play id from the historical bytes (see docs/USB_CCID.md).
 */
static uint8_t s_atr[] = {
	0x3B, 0x8C, 0x80, 0x01,
	'Q', 'D', 'S', 'D', 'A', 's', 'c', 'e', 'r', 't', 'E', 'N',
	0x00, /* TCK, computed */
};

#define LE16(v) (uint8_t)((v) & 0xFFU), (uint8_t)(((v) >> 8) & 0xFFU)
#define LE32(v) (uint8_t)((v) & 0xFFU), (uint8_t)(((v) >> 8) & 0xFFU), \
		(uint8_t)(((v) >> 16) & 0xFFU), (uint8_t)(((v) >> 24) & 0xFFU)

/*
 * dwFeatures 0x000400BE:
 *   0x02 automatic parameters from ATR, 0x04 automatic activation,
 *   0x08 automatic voltage, 0x10 automatic clock, 0x20 automatic baud rate,
 *   0x80 automatic PPS, 0x00040000 extended APDU level exchange.
 */
static const uint8_t s_class_desc[CCID_CLASS_DESC_LEN] = {
	CCID_CLASS_DESC_LEN, 0x21,
	LE16(0x0110),             /* bcdCCID 1.10 */
	0x00,                     /* bMaxSlotIndex: one slot */
	0x07,                     /* bVoltageSupport: 5 V, 3 V, 1.8 V */
	LE32(0x00000002UL),       /* dwProtocols: T=1 */
	LE32(4000UL),             /* dwDefaultClock (kHz) */
	LE32(4000UL),             /* dwMaximumClock */
	0x00,                     /* bNumClockSupported */
	LE32(9600UL),             /* dwDataRate (bps) */
	LE32(9600UL),             /* dwMaxDataRate */
	0x00,                     /* bNumDataRatesSupported */
	LE32(254UL),              /* dwMaxIFSD */
	LE32(0UL),                /* dwSynchProtocols */
	LE32(0UL),                /* dwMechanical */
	LE32(0x000400BEUL),       /* dwFeatures */
	LE32((uint32_t)CCID_MAX_MSG), /* dwMaxCCIDMessageLength */
	0xFF,                     /* bClassGetResponse: echo */
	0xFF,                     /* bClassEnvelope: echo */
	LE16(0x0000),             /* wLcdLayout: none */
	0x00,                     /* bPINSupport: none */
	0x01,                     /* bMaxCCIDBusySlots */
};

static uint32_t rd_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static void wr_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

const uint8_t *ccid_atr(size_t *len)
{
	uint8_t tck = 0U;
	size_t i;

	for (i = 1U; i < sizeof(s_atr) - 1U; i++) {
		tck ^= s_atr[i];
	}
	s_atr[sizeof(s_atr) - 1U] = tck;
	*len = sizeof(s_atr);
	return s_atr;
}

const uint8_t *ccid_class_descriptor(void)
{
	return s_class_desc;
}

void ccid_init(ccid_t *c, ccid_exec_t exec, ccid_power_t power)
{
	memset(c, 0, sizeof(*c));
	c->exec = exec;
	c->power = power;
}

size_t ccid_msg_len(const uint8_t *buf, size_t have)
{
	uint32_t dl;

	if (have < CCID_HDR_LEN) {
		return 0U;
	}
	dl = rd_le32(&buf[1]);
	if (dl > (uint32_t)(CCID_MAX_OUT_MSG - CCID_HDR_LEN)) {
		return CCID_MAX_OUT_MSG + 1U; /* too long: caller rejects */
	}
	return CCID_HDR_LEN + (size_t)dl;
}

/* Answer header: type, length, slot and sequence echoed, status, error, param. */
static size_t answer(const uint8_t *msg, uint8_t type, uint32_t dlen, uint8_t status,
		     uint8_t error, uint8_t param, uint8_t *out)
{
	out[0] = type;
	wr_le32(&out[1], dlen);
	out[5] = msg[5]; /* bSlot */
	out[6] = msg[6]; /* bSeq  */
	out[7] = status;
	out[8] = error;
	out[9] = param;
	return CCID_HDR_LEN + dlen;
}

/* Which answer type a request expects (CCID §6.2). */
static uint8_t answer_type(uint8_t req)
{
	switch (req) {
	case CCID_PC_ICC_POWER_ON:
	case CCID_PC_XFR_BLOCK:
	case CCID_PC_SECURE:
		return CCID_RDR_DATA_BLOCK;
	case CCID_PC_GET_PARAMETERS:
	case CCID_PC_RESET_PARAMETERS:
	case CCID_PC_SET_PARAMETERS:
		return CCID_RDR_PARAMETERS;
	case CCID_PC_ESCAPE:
		return CCID_RDR_ESCAPE;
	case CCID_PC_SET_DATA_RATE:
		return CCID_RDR_DATA_RATE;
	default:
		return CCID_RDR_SLOT_STATUS;
	}
}

static uint8_t icc(const ccid_t *c)
{
	return (uint8_t)(c->powered ? ICC_ACTIVE : ICC_INACTIVE);
}

/* T=1 protocol data for Get/Set/ResetParameters (CCID §6.2.3, Table 6.2-3). */
static size_t parameters(const ccid_t *c, const uint8_t *msg, uint8_t *out)
{
	static const uint8_t t1[7] = {
		0x11, /* bmFindexDindex: Fi=372, Di=1 */
		0x10, /* bmTCCKST1: LRC, direct convention */
		0x00, /* bGuardTimeT1 */
		0x4D, /* bmWaitingIntegersT1: BWI 4, CWI 13 */
		0x00, /* bClockStop: not allowed */
		0xFE, /* bIFSC */
		0x00, /* bNadValue */
	};

	memcpy(&out[CCID_HDR_LEN], t1, sizeof(t1));
	return answer(msg, CCID_RDR_PARAMETERS, sizeof(t1), (uint8_t)(CMD_OK | icc(c)), 0U,
		      0x01U /* bProtocolNum T=1 */, out);
}

size_t ccid_handle(ccid_t *c, const uint8_t *msg, size_t len, uint8_t *out, size_t cap)
{
	uint8_t type;
	uint32_t dlen;
	size_t rlen = 0U;

	if ((msg == NULL) || (out == NULL) || (len < CCID_HDR_LEN) || (cap < CCID_MAX_IN_MSG)) {
		return 0U;
	}
	type = msg[0];
	dlen = rd_le32(&msg[1]);
	if ((size_t)dlen != (len - CCID_HDR_LEN)) {
		return answer(msg, answer_type(type), 0U, (uint8_t)(CMD_FAILED | icc(c)),
			      ERR_BAD_LENGTH, 0U, out);
	}
	if (msg[5] != 0x00U) {
		return answer(msg, answer_type(type), 0U, (uint8_t)(CMD_FAILED | ICC_ABSENT),
			      ERR_BAD_SLOT, 0U, out);
	}

	switch (type) {
	case CCID_PC_ICC_POWER_ON: {
		size_t alen = 0U;
		const uint8_t *atr = ccid_atr(&alen);

		/* A power-on of a powered card is a warm reset (token: card reset). */
		if (c->power != NULL) {
			c->power(true);
		}
		c->powered = true;
		memcpy(&out[CCID_HDR_LEN], atr, alen);
		return answer(msg, CCID_RDR_DATA_BLOCK, (uint32_t)alen, (uint8_t)(CMD_OK | ICC_ACTIVE), 0U,
			      0U, out);
	}
	case CCID_PC_ICC_POWER_OFF:
		if (c->powered && (c->power != NULL)) {
			c->power(false);
		}
		c->powered = false;
		return answer(msg, CCID_RDR_SLOT_STATUS, 0U, (uint8_t)(CMD_OK | ICC_INACTIVE), 0U,
			      0x00U /* bClockStatus: running */, out);
	case CCID_PC_GET_SLOT_STATUS:
		return answer(msg, CCID_RDR_SLOT_STATUS, 0U, (uint8_t)(CMD_OK | icc(c)), 0U, 0x00U,
			      out);
	case CCID_PC_XFR_BLOCK:
		if (!c->powered) {
			return answer(msg, CCID_RDR_DATA_BLOCK, 0U, (uint8_t)(CMD_FAILED | ICC_INACTIVE),
				      ERR_ICC_MUTE, 0U, out);
		}
		/* wLevelParameter 0: the block is one whole APDU (no chaining needed,
		 * dwMaxCCIDMessageLength covers the largest APDU). */
		if ((msg[8] != 0x00U) || (msg[9] != 0x00U)) {
			return answer(msg, CCID_RDR_DATA_BLOCK, 0U, (uint8_t)(CMD_FAILED | ICC_ACTIVE),
				      ERR_BAD_LEVEL_PARAM, 0U, out);
		}
		if ((dlen == 0U) || (c->exec == NULL)) {
			return answer(msg, CCID_RDR_DATA_BLOCK, 0U, (uint8_t)(CMD_FAILED | ICC_ACTIVE),
				      ERR_BAD_LENGTH, 0U, out);
		}
		c->exec(&msg[CCID_HDR_LEN], dlen, &out[CCID_HDR_LEN], QDSD_RSP_MAX, &rlen);
		if ((rlen < 2U) || (rlen > QDSD_RSP_MAX)) {
			return answer(msg, CCID_RDR_DATA_BLOCK, 0U, (uint8_t)(CMD_FAILED | ICC_ACTIVE),
				      ERR_ICC_MUTE, 0U, out);
		}
		return answer(msg, CCID_RDR_DATA_BLOCK, (uint32_t)rlen, (uint8_t)(CMD_OK | ICC_ACTIVE), 0U,
			      0U, out);
	case CCID_PC_GET_PARAMETERS:
	case CCID_PC_RESET_PARAMETERS:
	case CCID_PC_SET_PARAMETERS:
		/* Parameters are fixed (APDU level); a SetParameters is acknowledged
		 * with the values in force, as the specification allows. */
		return parameters(c, msg, out);
	case CCID_PC_ABORT:
		return answer(msg, CCID_RDR_SLOT_STATUS, 0U, (uint8_t)(CMD_OK | icc(c)), 0U, 0U, out);
	default:
		/* Escape, IccClock, T0APDU, Secure, Mechanical, SetDataRate... */
		return answer(msg, answer_type(type), 0U, (uint8_t)(CMD_FAILED | icc(c)),
			      ERR_CMD_NOT_SUPPORTED, 0U, out);
	}
}

size_t ccid_time_extension(const uint8_t *msg, uint8_t mult, uint8_t out[CCID_HDR_LEN])
{
	return answer(msg, CCID_RDR_DATA_BLOCK, 0U, (uint8_t)(CMD_TIME_EXT | ICC_ACTIVE), mult, 0U, out);
}

size_t ccid_notify_slot(bool changed, uint8_t out[2])
{
	out[0] = CCID_RDR_NOTIFY_SLOT;
	out[1] = (uint8_t)(0x01U | (changed ? 0x02U : 0x00U)); /* slot 0: present (+changed) */
	return 2U;
}
