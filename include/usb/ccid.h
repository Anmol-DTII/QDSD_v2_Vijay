/**
 * @file ccid.h
 * @brief USB CCID (smart-card reader class 0x0B) message layer.
 *
 * Plain C, no USB stack dependency, so the host tests exercise it. The
 * token presents itself as a CCID reader with one slot and a card that is
 * always inserted: the QDSD applet. Exchange level is extended APDU
 * (dwFeatures bit 0x00040000): every PC_to_RDR_XfrBlock carries one whole
 * command APDU and every RDR_to_PC_DataBlock one whole response, so the
 * standard drivers (Windows usbccid.sys, macOS CryptoTokenKit, pcsc-lite
 * libccid on Linux) talk to it with no QDSD driver installed.
 *
 * Reference: USB Device Class Specification for Integrated Circuit(s) Cards
 * Interface Devices, rev 1.1 (CCID).
 */
#ifndef QDSD_CCID_H
#define QDSD_CCID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qdsd/qdsd_config.h"

#define CCID_HDR_LEN 10U

/* PC_to_RDR message types */
#define CCID_PC_SET_PARAMETERS   0x61U
#define CCID_PC_ICC_POWER_ON     0x62U
#define CCID_PC_ICC_POWER_OFF    0x63U
#define CCID_PC_GET_SLOT_STATUS  0x65U
#define CCID_PC_SECURE           0x69U
#define CCID_PC_T0_APDU          0x6AU
#define CCID_PC_ESCAPE           0x6BU
#define CCID_PC_GET_PARAMETERS   0x6CU
#define CCID_PC_RESET_PARAMETERS 0x6DU
#define CCID_PC_ICC_CLOCK        0x6EU
#define CCID_PC_XFR_BLOCK        0x6FU
#define CCID_PC_MECHANICAL       0x71U
#define CCID_PC_ABORT            0x72U
#define CCID_PC_SET_DATA_RATE    0x73U

/* RDR_to_PC message types */
#define CCID_RDR_DATA_BLOCK      0x80U
#define CCID_RDR_SLOT_STATUS     0x81U
#define CCID_RDR_PARAMETERS      0x82U
#define CCID_RDR_ESCAPE          0x83U
#define CCID_RDR_DATA_RATE       0x84U
#define CCID_RDR_NOTIFY_SLOT     0x50U /* interrupt IN */

/* Class-specific control requests */
#define CCID_REQ_ABORT           0x01U
#define CCID_REQ_GET_CLOCKS      0x02U
#define CCID_REQ_GET_DATA_RATES  0x03U

/* Largest message either way: header + the largest APDU or response. */
#define CCID_MAX_OUT_MSG (CCID_HDR_LEN + QDSD_APDU_MAX)
#define CCID_MAX_IN_MSG  (CCID_HDR_LEN + QDSD_RSP_MAX)
#define CCID_MAX_MSG     ((CCID_MAX_OUT_MSG > CCID_MAX_IN_MSG) ? CCID_MAX_OUT_MSG : CCID_MAX_IN_MSG)

/** Length of the CCID functional descriptor (type 0x21). */
#define CCID_CLASS_DESC_LEN 54U

/** Executes one command APDU (the token engine). */
typedef void (*ccid_exec_t)(const uint8_t *apdu, size_t len, uint8_t *rsp, size_t cap,
			    size_t *rsp_len);
/** Called when the card is powered on or off (token card reset, not session reset). */
typedef void (*ccid_power_t)(bool on);

typedef struct {
	bool         powered;
	ccid_exec_t  exec;
	ccid_power_t power;
} ccid_t;

void ccid_init(ccid_t *c, ccid_exec_t exec, ccid_power_t power);

/**
 * Total length of the PC_to_RDR message whose first bytes are in buf, or 0
 * if fewer than CCID_HDR_LEN bytes have arrived. A value above
 * CCID_MAX_OUT_MSG means the message is too long to accept.
 */
size_t ccid_msg_len(const uint8_t *buf, size_t have);

/**
 * Handle one complete PC_to_RDR message and build the RDR_to_PC answer in
 * out (cap >= CCID_MAX_IN_MSG). Returns the answer length (always >= 10).
 * An XfrBlock runs the APDU through exec, which may take seconds.
 */
size_t ccid_handle(ccid_t *c, const uint8_t *msg, size_t len, uint8_t *out, size_t cap);

/**
 * Time-extension answer (bmCommandStatus = 2) for the message being
 * processed, so the host keeps waiting during long operations such as
 * RSA-2048 key generation. mult = multiple of the block waiting time.
 */
size_t ccid_time_extension(const uint8_t *msg, uint8_t mult, uint8_t out[CCID_HDR_LEN]);

/** RDR_to_PC_NotifySlotChange for the interrupt endpoint. */
size_t ccid_notify_slot(bool changed, uint8_t out[2]);

/** The answer-to-reset presented at IccPowerOn. */
const uint8_t *ccid_atr(size_t *len);

/** The CCID class descriptor (bLength = 54, bDescriptorType = 0x21). */
const uint8_t *ccid_class_descriptor(void);

#endif /* QDSD_CCID_H */
