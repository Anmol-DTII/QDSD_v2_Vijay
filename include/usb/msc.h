/**
 * @file msc.h
 * @brief Read-only USB mass storage (Bulk-Only Transport + SCSI subset).
 *
 * The install drive (docs/INSTALL_DRIVE.md): the Ascert.en installer on the
 * token's external QSPI flash, shown to the PC as a write-protected
 * removable disk. Plain C with no RTOS dependency, like ccid.c, so the same
 * code runs on the token and in the host tests; src/usb/token_msc.c only
 * moves packets.
 *
 * Read-only for real: MODE SENSE reports write protection, so Windows,
 * macOS and Linux mount the volume read-only and never try to write; a WRITE
 * that arrives anyway is refused with DATA PROTECT / WRITE PROTECTED, and
 * its data is discarded.
 *
 * Driving it (one command at a time):
 *   after every bulk-OUT packet:  next = msc_rx(m, pkt, len)
 *     MSC_ARM_OUT  -> receive the next OUT packet
 *     MSC_SEND_IN  -> call msc_tx() until it says MSC_ARM_OUT
 *     MSC_STALL    -> stall both bulk endpoints until a Bulk-Only reset
 *   msc_tx(m, buf, cap, &next): fills the next IN transfer (data, then the
 *     13-byte status); next = MSC_SEND_IN while more follows.
 */
#ifndef QDSD_USB_MSC_H
#define QDSD_USB_MSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MSC_BLOCK_SIZE   512U
#define MSC_CBW_LEN      31U
#define MSC_CSW_LEN      13U

/* Class requests (bRequest) */
#define MSC_REQ_GET_MAX_LUN 0xFEU
#define MSC_REQ_RESET       0xFFU

/* USB interface triple: mass storage, SCSI transparent, Bulk-Only */
#define MSC_IF_CLASS     0x08U
#define MSC_IF_SUBCLASS  0x06U
#define MSC_IF_PROTOCOL  0x50U

typedef enum {
	MSC_ARM_OUT = 0,
	MSC_SEND_IN = 1,
	MSC_STALL   = 2,
} msc_next_t;

/** Read whole 512-byte blocks; 0 on success. */
typedef int (*msc_read_fn)(uint32_t lba, uint8_t *buf, uint32_t blocks);

typedef struct {
	/* configuration */
	msc_read_fn read;
	uint16_t    mps;          /* bulk max packet size (64 at full speed) */

	/* medium */
	bool     present;
	uint32_t blocks;
	bool     attention;       /* report "medium may have changed" once */

	/* sense for REQUEST SENSE */
	uint8_t  key, asc, ascq;

	/* current command */
	int      phase;           /* internal */
	uint32_t tag;
	uint32_t host_len;        /* dCBWDataTransferLength */
	bool     host_in;         /* bmCBWFlags direction */
	uint32_t done;            /* bytes moved in the data phase */
	uint8_t  status;          /* CSW status */
	/* data-in source */
	uint8_t  rsp[64];         /* small replies (INQUIRY, sense, capacity…) */
	uint32_t rsp_len;
	uint32_t lba;             /* READ: next block */
	uint32_t left_blocks;     /* READ: blocks still to send */
	uint32_t in_len;          /* bytes the data phase will carry */
	bool     pad;             /* in_len includes one padding byte */
	uint32_t out_left;        /* data-out bytes still to discard */
} msc_t;

/** Set up; the medium starts absent. */
void msc_init(msc_t *m, msc_read_fn read, uint16_t mps);
/** The medium appeared (valid image) or went away; the host is told once. */
void msc_set_medium(msc_t *m, bool present, uint32_t blocks);
/** Bulk-Only Mass Storage Reset (class request 0xFF) and bus reset. */
void msc_reset(msc_t *m);
/** Feed one bulk-OUT packet. */
msc_next_t msc_rx(msc_t *m, const uint8_t *pkt, size_t len);
/** Next bulk-IN transfer, at most cap bytes (a multiple of MSC_BLOCK_SIZE, ≥ 512). */
size_t msc_tx(msc_t *m, uint8_t *buf, size_t cap, msc_next_t *next);

#ifdef __cplusplus
}
#endif

#endif /* QDSD_USB_MSC_H */
