/**
 * @file msc.c
 * @brief Read-only USB mass storage: Bulk-Only Transport and the SCSI
 *        commands Windows, macOS and Linux send to a removable disk.
 *
 * See include/usb/msc.h. References: USB Mass Storage Class Bulk-Only
 * Transport 1.0; SCSI Primary Commands (SPC-2) and Block Commands (SBC).
 *
 * Data residue rule: when a command returns less data than the host asked
 * for, the transfer must end with a short packet. If the real length is a
 * whole number of packets (0, 64, …), one zero byte is added so the host
 * sees the end of the data; the residue in the status reports the rest.
 */
#include <string.h>

#include "usb/msc.h"

#define CBW_SIG 0x43425355UL /* "USBC" */
#define CSW_SIG 0x53425355UL /* "USBS" */

enum { PH_CBW = 0, PH_DATA_IN, PH_DATA_OUT, PH_CSW, PH_STALLED };

/* SCSI opcodes */
#define TEST_UNIT_READY        0x00U
#define REQUEST_SENSE          0x03U
#define READ6                  0x08U
#define WRITE6                 0x0AU
#define INQUIRY                0x12U
#define MODE_SELECT6           0x15U
#define MODE_SENSE6            0x1AU
#define START_STOP_UNIT        0x1BU
#define PREVENT_ALLOW          0x1EU
#define READ_FORMAT_CAPACITIES 0x23U
#define READ_CAPACITY10        0x25U
#define READ10                 0x28U
#define WRITE10                0x2AU
#define VERIFY10               0x2FU
#define SYNC_CACHE10           0x35U
#define MODE_SELECT10          0x55U
#define MODE_SENSE10           0x5AU
#define READ12                 0xA8U
#define WRITE12                0xAAU

/* sense keys / codes */
#define SK_NONE            0x00U
#define SK_NOT_READY       0x02U
#define SK_MEDIUM_ERROR    0x03U
#define SK_ILLEGAL_REQUEST 0x05U
#define SK_UNIT_ATTENTION  0x06U
#define SK_DATA_PROTECT    0x07U

#define CSW_PASS  0x00U
#define CSW_FAIL  0x01U
#define CSW_PHASE 0x02U

static const char k_vendor[8]   = { 'D', 'T', 'I', 'I', ' ', ' ', ' ', ' ' };
static const char k_product[16] = { 'A', 's', 'c', 'e', 'r', 't', '.', 'e',
				    'n', ' ', 'S', 'e', 't', 'u', 'p', ' ' };
static const char k_rev[4]      = { '1', '.', '0', '0' };

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint32_t be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
	       (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void sense(msc_t *m, uint8_t key, uint8_t asc, uint8_t ascq)
{
	m->key = key;
	m->asc = asc;
	m->ascq = ascq;
}

static void fail(msc_t *m, uint8_t key, uint8_t asc, uint8_t ascq)
{
	sense(m, key, asc, ascq);
	m->status = CSW_FAIL;
}

void msc_init(msc_t *m, msc_read_fn read, uint16_t mps)
{
	memset(m, 0, sizeof(*m));
	m->read = read;
	m->mps = (mps == 0U) ? 64U : mps;
	m->phase = PH_CBW;
}

void msc_set_medium(msc_t *m, bool present, uint32_t blocks)
{
	if ((present != m->present) || (blocks != m->blocks)) {
		m->attention = present; /* "not ready to ready" change, reported once */
	}
	m->present = present;
	m->blocks = present ? blocks : 0U;
}

void msc_reset(msc_t *m)
{
	m->phase = PH_CBW;
	m->rsp_len = 0U;
	m->left_blocks = 0U;
	m->out_left = 0U;
}

/* Small reply of n bytes; the host gets at most what it asked for. */
static void reply(msc_t *m, const uint8_t *p, uint32_t n)
{
	if (n > sizeof(m->rsp)) {
		n = sizeof(m->rsp);
	}
	memcpy(m->rsp, p, n);
	m->rsp_len = n;
	m->in_len = n;
}

static void cmd_inquiry(msc_t *m, const uint8_t *cb)
{
	uint8_t r[36];

	if ((cb[1] & 0x01U) != 0U) { /* EVPD pages: not supported */
		fail(m, SK_ILLEGAL_REQUEST, 0x24U, 0x00U);
		return;
	}
	memset(r, 0, sizeof(r));
	r[0] = 0x00U;          /* direct-access block device */
	r[1] = 0x80U;          /* removable medium */
	r[2] = 0x04U;          /* SPC-2 */
	r[3] = 0x02U;          /* response data format */
	r[4] = (uint8_t)(sizeof(r) - 5U);
	memcpy(&r[8], k_vendor, sizeof(k_vendor));
	memcpy(&r[16], k_product, sizeof(k_product));
	memcpy(&r[32], k_rev, sizeof(k_rev));
	reply(m, r, sizeof(r));
}

static void cmd_request_sense(msc_t *m)
{
	uint8_t r[18];

	memset(r, 0, sizeof(r));
	r[0] = 0x70U;          /* current error, fixed format */
	r[2] = m->key;
	r[7] = 10U;            /* additional length */
	r[12] = m->asc;
	r[13] = m->ascq;
	reply(m, r, sizeof(r));
	sense(m, SK_NONE, 0U, 0U);
}

static bool need_medium(msc_t *m)
{
	if (!m->present) {
		fail(m, SK_NOT_READY, 0x3AU, 0x00U); /* medium not present */
		return false;
	}
	return true;
}

static void cmd_read_capacity(msc_t *m)
{
	uint8_t r[8];

	if (!need_medium(m)) {
		return;
	}
	put_be32(&r[0], m->blocks - 1U);
	put_be32(&r[4], MSC_BLOCK_SIZE);
	reply(m, r, sizeof(r));
}

static void cmd_read_format_capacities(msc_t *m)
{
	uint8_t r[12];

	memset(r, 0, sizeof(r));
	r[3] = 8U;             /* capacity list length */
	put_be32(&r[4], m->present ? m->blocks : 0U);
	r[8] = m->present ? 0x02U : 0x03U; /* formatted media / no media */
	r[10] = (uint8_t)(MSC_BLOCK_SIZE >> 8);
	r[11] = (uint8_t)MSC_BLOCK_SIZE;
	reply(m, r, sizeof(r));
}

static void cmd_mode_sense(msc_t *m, bool ten)
{
	/* Header only, with the write-protect bit; no pages. */
	static const uint8_t r6[4]  = { 0x03U, 0x00U, 0x80U, 0x00U };
	static const uint8_t r10[8] = { 0x00U, 0x06U, 0x00U, 0x80U, 0U, 0U, 0U, 0U };

	if (ten) {
		reply(m, r10, sizeof(r10));
	} else {
		reply(m, r6, sizeof(r6));
	}
}

static void cmd_read(msc_t *m, uint32_t lba, uint32_t count)
{
	if (!need_medium(m)) {
		return;
	}
	if ((lba >= m->blocks) || (count > (m->blocks - lba))) {
		fail(m, SK_ILLEGAL_REQUEST, 0x21U, 0x00U); /* LBA out of range */
		return;
	}
	m->lba = lba;
	m->left_blocks = count;
	m->in_len = count * MSC_BLOCK_SIZE;
}

static void cmd_unit_ready(msc_t *m)
{
	if (m->attention) {
		m->attention = false;
		fail(m, SK_UNIT_ATTENTION, 0x28U, 0x00U); /* medium may have changed */
		return;
	}
	(void)need_medium(m);
}

static void run_scsi(msc_t *m, const uint8_t *cb)
{
	switch (cb[0]) {
	case TEST_UNIT_READY:
		cmd_unit_ready(m);
		break;
	case REQUEST_SENSE:
		cmd_request_sense(m);
		break;
	case INQUIRY:
		cmd_inquiry(m, cb);
		break;
	case MODE_SENSE6:
		cmd_mode_sense(m, false);
		break;
	case MODE_SENSE10:
		cmd_mode_sense(m, true);
		break;
	case READ_CAPACITY10:
		cmd_read_capacity(m);
		break;
	case READ_FORMAT_CAPACITIES:
		cmd_read_format_capacities(m);
		break;
	case READ6: {
		uint32_t lba = (((uint32_t)cb[1] & 0x1FU) << 16) | ((uint32_t)cb[2] << 8) | cb[3];
		uint32_t n = (cb[4] == 0U) ? 256U : cb[4];

		cmd_read(m, lba, n);
		break;
	}
	case READ10:
		cmd_read(m, be32(&cb[2]), ((uint32_t)cb[7] << 8) | cb[8]);
		break;
	case READ12:
		cmd_read(m, be32(&cb[2]), be32(&cb[6]));
		break;
	case PREVENT_ALLOW:
	case START_STOP_UNIT:
	case SYNC_CACHE10:
		break; /* nothing to do for a read-only flash disk */
	case VERIFY10:
		(void)need_medium(m);
		break;
	case WRITE6:
	case WRITE10:
	case WRITE12:
	case MODE_SELECT6:
	case MODE_SELECT10:
		fail(m, SK_DATA_PROTECT, 0x27U, 0x00U); /* write protected */
		break;
	default:
		fail(m, SK_ILLEGAL_REQUEST, 0x20U, 0x00U); /* invalid command */
		break;
	}
}

msc_next_t msc_rx(msc_t *m, const uint8_t *pkt, size_t len)
{
	if (m->phase == PH_STALLED) {
		return MSC_STALL;
	}
	if (m->phase == PH_DATA_OUT) {
		uint32_t n = (len > m->out_left) ? m->out_left : (uint32_t)len;

		m->out_left -= n; /* write data is discarded: the disk is read-only */
		m->done += n;
		if (m->out_left == 0U) {
			m->phase = PH_CSW;
			return MSC_SEND_IN;
		}
		return MSC_ARM_OUT;
	}
	if (m->phase != PH_CBW) {
		return MSC_SEND_IN; /* the host should be reading; keep answering */
	}

	/* A valid and meaningful CBW, or reset recovery (BOT §6.6.1). */
	if ((len != MSC_CBW_LEN) || (le32(pkt) != CBW_SIG) || (pkt[14] == 0U) ||
	    (pkt[14] > 16U)) {
		m->phase = PH_STALLED;
		return MSC_STALL;
	}
	m->tag = le32(&pkt[4]);
	m->host_len = le32(&pkt[8]);
	m->host_in = (pkt[12] & 0x80U) != 0U;
	m->done = 0U;
	m->status = CSW_PASS;
	m->rsp_len = 0U;
	m->left_blocks = 0U;
	m->in_len = 0U;
	m->pad = false;
	m->out_left = 0U;

	if ((pkt[13] & 0x0FU) != 0U) {
		fail(m, SK_ILLEGAL_REQUEST, 0x25U, 0x00U); /* logical unit not supported */
	} else {
		run_scsi(m, &pkt[15]);
	}

	if (m->host_len == 0U) {
		if (m->in_len != 0U) {
			m->status = CSW_PHASE; /* Hn < Di */
			m->in_len = 0U;
			m->left_blocks = 0U;
		}
		m->phase = PH_CSW;
		return MSC_SEND_IN;
	}
	if (!m->host_in) {
		/* Host sends data (a write, or a mismatch): take it and drop it. */
		if (m->in_len != 0U) {
			m->status = CSW_PHASE; /* Ho <> Di */
			m->in_len = 0U;
			m->left_blocks = 0U;
		}
		m->out_left = m->host_len;
		m->phase = PH_DATA_OUT;
		return MSC_ARM_OUT;
	}
	/* Host reads. */
	if (m->in_len > m->host_len) {
		if (m->left_blocks != 0U) {
			m->status = CSW_PHASE; /* Hi < Di for a READ: send what fits */
		}
		m->in_len = m->host_len;
	}
	if ((m->in_len < m->host_len) && ((m->in_len % m->mps) == 0U)) {
		m->in_len += 1U; /* end the data with a short packet (see file header) */
		m->pad = true;
		if (m->rsp_len < sizeof(m->rsp)) {
			m->rsp[m->rsp_len] = 0U;
		}
	}
	m->phase = PH_DATA_IN;
	return MSC_SEND_IN;
}

static size_t make_csw(msc_t *m, uint8_t *buf)
{
	uint32_t data = m->done - (m->pad ? 1U : 0U); /* the padding byte is not data */
	uint32_t residue = (m->host_len > data) ? (m->host_len - data) : 0U;

	put_le32(&buf[0], CSW_SIG);
	put_le32(&buf[4], m->tag);
	put_le32(&buf[8], residue);
	buf[12] = m->status;
	m->phase = PH_CBW;
	return MSC_CSW_LEN;
}

size_t msc_tx(msc_t *m, uint8_t *buf, size_t cap, msc_next_t *next)
{
	size_t n = 0U;

	if (m->phase == PH_DATA_IN) {
		uint32_t want = m->in_len - m->done;

		if (m->left_blocks != 0U) {
			/* Whole blocks, as many as fit. */
			uint32_t blocks = (uint32_t)(cap / MSC_BLOCK_SIZE);
			uint32_t max_blocks = (want + MSC_BLOCK_SIZE - 1U) / MSC_BLOCK_SIZE;

			if (blocks > m->left_blocks) {
				blocks = m->left_blocks;
			}
			if (blocks > max_blocks) {
				blocks = max_blocks;
			}
			if ((m->read == NULL) || (m->read(m->lba, buf, blocks) != 0)) {
				memset(buf, 0, (size_t)blocks * MSC_BLOCK_SIZE);
				fail(m, SK_MEDIUM_ERROR, 0x11U, 0x00U); /* unrecovered read error */
			}
			n = (size_t)blocks * MSC_BLOCK_SIZE;
			if (n > want) {
				n = want; /* host asked for less than whole blocks (phase error) */
			}
			m->lba += blocks;
			m->left_blocks -= blocks;
		} else {
			/* Small reply (plus the padding byte, if any). */
			uint32_t have = (m->rsp_len > m->done) ? (m->rsp_len - m->done) : 0U;

			n = (want < cap) ? want : cap;
			if (have > 0U) {
				memcpy(buf, &m->rsp[m->done], (n < have) ? n : have);
			}
			if (n > have) {
				memset(&buf[have], 0, n - have);
			}
		}
		m->done += (uint32_t)n;
		if (m->done >= m->in_len) {
			m->phase = PH_CSW;
		}
		*next = MSC_SEND_IN;
		if (n > 0U) {
			return n;
		}
	}
	if (m->phase == PH_CSW) {
		*next = MSC_ARM_OUT;
		return make_csw(m, buf);
	}
	*next = (m->phase == PH_STALLED) ? MSC_STALL : MSC_ARM_OUT;
	return 0U;
}
