/**
 * @file token_usb.c
 * @brief USB CCID transport (protocol v3.2, PROTOCOL.md §1, docs/USB_CCID.md).
 *
 * One interface of class 0x0B (smart-card reader) with bulk OUT, bulk IN and
 * interrupt IN, so every desktop OS binds its own CCID driver: Windows
 * usbccid.sys, macOS CryptoTokenKit, Linux pcsc-lite libccid. No QDSD
 * driver, INF or vendor descriptor is needed for the transport; the Ascert.en
 * agent talks to the token through PC/SC (SCardTransmit).
 *
 * The CCID messages are handled by src/usb/ccid.c (shared with the host
 * tests); this file only moves bytes. One message at a time: OUT is re-armed
 * after the answer has gone. APDUs run on a dedicated work queue because
 * secure-element operations take from milliseconds (ECDSA) to seconds
 * (RSA-2048 key generation); while one runs, a CCID time extension goes out
 * every TOKEN_USB_WTX_MS so the host driver keeps waiting.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/usb/usb_device.h>

#include <usb_descriptor.h>

#include "token/token_engine.h"
#include "usb/ccid.h"
#include "usb/token_usb.h"
#include "usb/token_usb_desc.h"

LOG_MODULE_REGISTER(token_usb, LOG_LEVEL_INF);

#define EP_OUT_IDX 0
#define EP_IN_IDX  1
#define EP_INT_IDX 2

/* ── Descriptors ────────────────────────────────────────────────────── */

USBD_CLASS_DESCR_DEFINE(primary, 0) struct {
	struct usb_if_descriptor if0;
	uint8_t ccid[CCID_CLASS_DESC_LEN]; /* filled from ccid_class_descriptor() */
	struct usb_ep_descriptor out_ep;
	struct usb_ep_descriptor in_ep;
	struct usb_ep_descriptor int_ep;
} __packed token_usb_desc = {
	.if0 = {
		.bLength = sizeof(struct usb_if_descriptor),
		.bDescriptorType = USB_DESC_INTERFACE,
		.bInterfaceNumber = TOKEN_USB_INTERFACE_NUM,
		.bAlternateSetting = 0,
		.bNumEndpoints = 3,
		.bInterfaceClass = TOKEN_USB_INTERFACE_CLASS,
		.bInterfaceSubClass = 0,
		.bInterfaceProtocol = 0,
		.iInterface = 0,
	},
	.out_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = TOKEN_USB_EP_BULK_OUT,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = sys_cpu_to_le16(TOKEN_USB_BULK_MPS),
		.bInterval = 0,
	},
	.in_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = TOKEN_USB_EP_BULK_IN,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = sys_cpu_to_le16(TOKEN_USB_BULK_MPS),
		.bInterval = 0,
	},
	.int_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = TOKEN_USB_EP_INT_IN,
		.bmAttributes = USB_DC_EP_INTERRUPT,
		.wMaxPacketSize = sys_cpu_to_le16(TOKEN_USB_INT_MPS),
		.bInterval = TOKEN_USB_INT_INTERVAL,
	},
};

/* ── State ──────────────────────────────────────────────────────────── */

#define TOKEN_USB_WQ_STACK 8192
#define TOKEN_USB_WQ_PRIO  5

K_THREAD_STACK_DEFINE(s_wq_stack, TOKEN_USB_WQ_STACK);
static struct k_work_q s_wq;
static struct k_work s_rx_work;
static struct k_work s_reset_work;
static struct k_work_delayable s_wtx_work;

static K_SEM_DEFINE(s_in_free, 1, 1);  /* bulk IN transfer slot */
static K_MUTEX_DEFINE(s_busy_lock);

/* Set by the USB status callback, read by the work queues: read it once. */
static struct usb_cfg_data *volatile s_cfg;
/* Bumped on every bus reset / disconnect: answers to older commands are dropped. */
static atomic_t s_gen;
static ccid_t s_ccid;
static bool s_enabled;
static bool s_busy;         /* an APDU is running */
static bool s_discard;      /* skipping an oversized message */

static uint8_t s_pkt[TOKEN_USB_BULK_MPS];
static size_t  s_pkt_len;
static uint8_t s_rx[CCID_MAX_OUT_MSG];
static size_t  s_rx_len;
static uint8_t s_tx[CCID_MAX_IN_MSG];
static uint8_t s_wtx[CCID_HDR_LEN];
static uint8_t s_notify[2];

static void read_cb(uint8_t ep, int size, void *priv);

/*
 * IccPowerOn / IccPowerOff (SCardReconnect with reset, Windows recovering
 * from a crashed process, pcsc-lite idle power-down): SELECT again and abort
 * uploads, but keep the login and outstanding nonces. Only a USB reset or
 * unplug ends the session (reset_work_fn).
 */
static void ccid_power(bool on)
{
	ARG_UNUSED(on);
	token_engine_card_reset();
}

static void arm_out(void)
{
	struct usb_cfg_data *cfg = s_cfg;

	if (cfg == NULL) {
		return;
	}
	if (usb_transfer(cfg->endpoint[EP_OUT_IDX].ep_addr, s_pkt, sizeof(s_pkt),
			 USB_TRANS_READ, read_cb, cfg) != 0) {
		LOG_ERR("OUT arm failed");
	}
}

static void answer_done(uint8_t ep, int size, void *priv)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(size);
	ARG_UNUSED(priv);
	k_sem_give(&s_in_free);
	arm_out(); /* ready for the next command */
}

static void wtx_done(uint8_t ep, int size, void *priv)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(size);
	ARG_UNUSED(priv);
	k_sem_give(&s_in_free);
}

static void send_answer(size_t len)
{
	struct usb_cfg_data *cfg;

	(void)k_sem_take(&s_in_free, K_FOREVER); /* a time extension may be in flight */
	cfg = s_cfg;
	if ((cfg == NULL) ||
	    (usb_transfer(cfg->endpoint[EP_IN_IDX].ep_addr, s_tx, len, USB_TRANS_WRITE,
			  answer_done, cfg) != 0)) {
		LOG_ERR("IN start failed");
		k_sem_give(&s_in_free);
		arm_out();
	}
}

/* System work queue: keep the host waiting while an APDU runs. */
static void wtx_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	struct usb_cfg_data *cfg;

	k_mutex_lock(&s_busy_lock, K_FOREVER);
	cfg = s_cfg;
	if (s_busy && (cfg != NULL) && (k_sem_take(&s_in_free, K_NO_WAIT) == 0)) {
		(void)ccid_time_extension(s_rx, 1U, s_wtx);
		if (usb_transfer(cfg->endpoint[EP_IN_IDX].ep_addr, s_wtx, sizeof(s_wtx),
				 USB_TRANS_WRITE, wtx_done, cfg) != 0) {
			k_sem_give(&s_in_free);
		}
	}
	if (s_busy) {
		k_work_schedule(&s_wtx_work, K_MSEC(TOKEN_USB_WTX_MS));
	}
	k_mutex_unlock(&s_busy_lock);
}

static void process_message(size_t len)
{
	atomic_val_t gen = atomic_get(&s_gen);
	size_t n;

	k_mutex_lock(&s_busy_lock, K_FOREVER);
	s_busy = true;
	k_work_schedule(&s_wtx_work, K_MSEC(TOKEN_USB_WTX_MS));
	k_mutex_unlock(&s_busy_lock);

	n = ccid_handle(&s_ccid, s_rx, len, s_tx, sizeof(s_tx));

	k_mutex_lock(&s_busy_lock, K_FOREVER);
	s_busy = false;
	(void)k_work_cancel_delayable(&s_wtx_work);
	k_mutex_unlock(&s_busy_lock);

	s_rx_len = 0U;
	if (atomic_get(&s_gen) != gen) {
		/* The bus was reset while the command ran: the host no longer
		 * waits for this answer, and re-arms OUT on configuration. */
		return;
	}
	if (n >= CCID_HDR_LEN) {
		send_answer(n);
	} else {
		arm_out();
	}
}

static void rx_work_fn(struct k_work *w)
{
	size_t want;

	ARG_UNUSED(w);
	if (s_discard) {
		/* Oversized message: drop packets until the host's short packet. */
		if (s_pkt_len < TOKEN_USB_BULK_MPS) {
			s_discard = false;
			s_rx_len = CCID_HDR_LEN; /* answer "bad length" to the header we kept */
			process_message(CCID_HDR_LEN);
			return;
		}
		arm_out();
		return;
	}
	if (s_pkt_len > (sizeof(s_rx) - s_rx_len)) {
		s_pkt_len = sizeof(s_rx) - s_rx_len;
	}
	memcpy(&s_rx[s_rx_len], s_pkt, s_pkt_len);
	s_rx_len += s_pkt_len;

	want = ccid_msg_len(s_rx, s_rx_len);
	if (want == 0U) {
		arm_out(); /* header incomplete */
		return;
	}
	if (want > CCID_MAX_OUT_MSG) {
		LOG_WRN("CCID message too long — discarded");
		if (s_pkt_len < TOKEN_USB_BULK_MPS) {
			process_message(CCID_HDR_LEN);
		} else {
			s_discard = true;
			arm_out();
		}
		return;
	}
	if (s_rx_len < want) {
		arm_out();
		return;
	}
	process_message(want);
}

static void reset_work_fn(struct k_work *w)
{
	ARG_UNUSED(w);
	s_rx_len = 0U;
	s_discard = false;
	ccid_init(&s_ccid, token_engine_process, ccid_power);
	token_engine_session_reset();
}

static void read_cb(uint8_t ep, int size, void *priv)
{
	if (size > 0) {
		s_pkt_len = (size_t)size;
		k_work_submit_to_queue(&s_wq, &s_rx_work);
		return;
	}
	(void)usb_transfer(ep, s_pkt, sizeof(s_pkt), USB_TRANS_READ, read_cb, priv);
}

static void notify_slot(void)
{
	struct usb_cfg_data *cfg = s_cfg;

	(void)ccid_notify_slot(true, s_notify);
	if (cfg != NULL) {
		(void)usb_transfer(cfg->endpoint[EP_INT_IDX].ep_addr, s_notify, sizeof(s_notify),
				   USB_TRANS_WRITE | USB_TRANS_NO_ZLP, NULL, NULL);
	}
}

static void status_cb(struct usb_cfg_data *cfg, enum usb_dc_status_code status,
		      const uint8_t *param)
{
	ARG_UNUSED(param);
	switch (status) {
	case USB_DC_CONFIGURED:
		LOG_INF("USB configured (CCID)");
		s_cfg = cfg;
		k_work_submit_to_queue(&s_wq, &s_reset_work);
		arm_out();
		notify_slot();
		break;
	case USB_DC_RESET:
	case USB_DC_DISCONNECTED:
		atomic_inc(&s_gen);
		if (status == USB_DC_DISCONNECTED) {
			s_cfg = NULL;
		}
		k_work_submit_to_queue(&s_wq, &s_reset_work);
		break;
	default:
		break;
	}
}

/* CCID class requests (§5.3). Clock and data-rate lists: none (APDU level). */
static int class_req(struct usb_setup_packet *setup, int32_t *len, uint8_t **data)
{
	ARG_UNUSED(data);
	if (setup->bRequest == CCID_REQ_ABORT) {
		/* Commands run to completion; the following PC_to_RDR_Abort is answered. */
		*len = 0;
		return 0;
	}
	return -ENOTSUP;
}

static struct usb_ep_cfg_data s_ep_data[] = {
	{ .ep_cb = usb_transfer_ep_callback, .ep_addr = TOKEN_USB_EP_BULK_OUT },
	{ .ep_cb = usb_transfer_ep_callback, .ep_addr = TOKEN_USB_EP_BULK_IN },
	{ .ep_cb = usb_transfer_ep_callback, .ep_addr = TOKEN_USB_EP_INT_IN },
};

USBD_DEFINE_CFG_DATA(token_usb_config) = {
	.usb_device_description = NULL,
	.interface_descriptor = &token_usb_desc.if0,
	.cb_usb_status = status_cb,
	.interface = {
		.class_handler = class_req,
		.custom_handler = NULL,
		.vendor_handler = NULL,
	},
	.num_endpoints = ARRAY_SIZE(s_ep_data),
	.endpoint = s_ep_data,
};

int token_usb_init(void)
{
	memcpy(token_usb_desc.ccid, ccid_class_descriptor(), CCID_CLASS_DESC_LEN);
	ccid_init(&s_ccid, token_engine_process, ccid_power);

	k_work_queue_init(&s_wq);
	k_work_queue_start(&s_wq, s_wq_stack, K_THREAD_STACK_SIZEOF(s_wq_stack),
			   TOKEN_USB_WQ_PRIO, NULL);
	k_thread_name_set(&s_wq.thread, "qdsd_apdu");
	k_work_init(&s_rx_work, rx_work_fn);
	k_work_init(&s_reset_work, reset_work_fn);
	k_work_init_delayable(&s_wtx_work, wtx_work_fn);
	return 0;
}

int token_usb_enable(void)
{
	int rc;

	if (s_enabled) {
		return 0;
	}
	rc = usb_enable(NULL);
	if (rc != 0) {
		LOG_ERR("usb_enable failed: %d", rc);
		return rc;
	}
	s_enabled = true;
	LOG_INF("USB CCID reader enabled (VID %04X PID %04X)", TOKEN_USB_VID, TOKEN_USB_PID);
	return 0;
}
