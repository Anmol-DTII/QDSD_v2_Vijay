/**
 * @file token_msc.c
 * @brief Install drive: USB mass-storage interface (Bulk-Only, SCSI) on the
 *        external QSPI flash, next to the CCID reader (docs/INSTALL_DRIVE.md).
 *
 * Interface 1 of the composite device (CCID is interface 0): class 08
 * (mass storage), subclass 06 (SCSI), protocol 50 (Bulk-Only). Every OS
 * binds its own driver. The commands are handled by src/usb/msc.c (shared
 * with the host tests); this file only moves packets, on its own work queue
 * so that reading the drive never waits for a slow APDU (RSA key generation)
 * and an APDU never waits for the drive.
 *
 * Read-only: msc.c reports write protection and refuses writes. Nothing in
 * the firmware writes the drive except FACTORY_DRIVE in MANUFACTURING.
 */
#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/usb/usb_device.h>

#include <usb_descriptor.h>

#include "port/port.h"
#include "usb/msc.h"
#include "usb/token_msc.h"
#include "usb/token_usb_desc.h"

LOG_MODULE_REGISTER(token_msc, LOG_LEVEL_INF);

#define EP_OUT_IDX 0
#define EP_IN_IDX  1

#define MSC_EP_BULK_OUT 0x03U
#define MSC_EP_BULK_IN  0x83U

/* ── Descriptors ────────────────────────────────────────────────────── */

USBD_CLASS_DESCR_DEFINE(primary, 1) struct {
	struct usb_if_descriptor if0;
	struct usb_ep_descriptor out_ep;
	struct usb_ep_descriptor in_ep;
} __packed token_msc_desc = {
	.if0 = {
		.bLength = sizeof(struct usb_if_descriptor),
		.bDescriptorType = USB_DESC_INTERFACE,
		.bInterfaceNumber = 0, /* renumbered by the stack: see msc_if_config() */
		.bAlternateSetting = 0,
		.bNumEndpoints = 2,
		.bInterfaceClass = MSC_IF_CLASS,
		.bInterfaceSubClass = MSC_IF_SUBCLASS,
		.bInterfaceProtocol = MSC_IF_PROTOCOL,
		.iInterface = 0,
	},
	.out_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = MSC_EP_BULK_OUT,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = sys_cpu_to_le16(TOKEN_USB_BULK_MPS),
		.bInterval = 0,
	},
	.in_ep = {
		.bLength = sizeof(struct usb_ep_descriptor),
		.bDescriptorType = USB_DESC_ENDPOINT,
		.bEndpointAddress = MSC_EP_BULK_IN,
		.bmAttributes = USB_DC_EP_BULK,
		.wMaxPacketSize = sys_cpu_to_le16(TOKEN_USB_BULK_MPS),
		.bInterval = 0,
	},
};

/* ── State ──────────────────────────────────────────────────────────── */

#define MSC_WQ_STACK 2048
#define MSC_WQ_PRIO  6
#define MSC_XFER     4096U /* one IN transfer: 8 blocks */

K_THREAD_STACK_DEFINE(s_msc_wq_stack, MSC_WQ_STACK);
static struct k_work_q s_wq;
static struct k_work s_rx_work;
static struct k_work s_tx_work;
static K_MUTEX_DEFINE(s_lock);

static struct usb_cfg_data *volatile s_cfg;
static msc_t s_msc;
static bool s_ready;
static msc_next_t s_next;
static uint8_t s_pkt[TOKEN_USB_BULK_MPS];
static size_t s_pkt_len;
static uint8_t __aligned(4) s_xfer[MSC_XFER];
static uint8_t s_max_lun;

static int read_blocks(uint32_t lba, uint8_t *buf, uint32_t blocks)
{
	return port_drive_read(lba * MSC_BLOCK_SIZE, buf, (size_t)blocks * MSC_BLOCK_SIZE);
}

static void read_cb(uint8_t ep, int size, void *priv);
static void in_done(uint8_t ep, int size, void *priv);

static void arm_out(void)
{
	struct usb_cfg_data *cfg = s_cfg;

	if (cfg != NULL) {
		(void)usb_transfer(cfg->endpoint[EP_OUT_IDX].ep_addr, s_pkt, sizeof(s_pkt),
				   USB_TRANS_READ, read_cb, cfg);
	}
}

static void stall(void)
{
	struct usb_cfg_data *cfg = s_cfg;

	if (cfg != NULL) {
		(void)usb_ep_set_stall(cfg->endpoint[EP_IN_IDX].ep_addr);
		(void)usb_ep_set_stall(cfg->endpoint[EP_OUT_IDX].ep_addr);
	}
}

static void act(msc_next_t next)
{
	if (next == MSC_SEND_IN) {
		k_work_submit_to_queue(&s_wq, &s_tx_work);
	} else if (next == MSC_STALL) {
		stall();
	} else {
		arm_out();
	}
}

/* Next IN transfer: data, then the status; the host knows the lengths, so
 * no zero-length packet is ever added. */
static void tx_work_fn(struct k_work *w)
{
	struct usb_cfg_data *cfg = s_cfg;
	size_t n;

	ARG_UNUSED(w);
	k_mutex_lock(&s_lock, K_FOREVER);
	n = msc_tx(&s_msc, s_xfer, sizeof(s_xfer), &s_next);
	k_mutex_unlock(&s_lock);
	if (n == 0U) {
		act(s_next);
		return;
	}
	if ((cfg == NULL) ||
	    (usb_transfer(cfg->endpoint[EP_IN_IDX].ep_addr, s_xfer, n,
			  USB_TRANS_WRITE | USB_TRANS_NO_ZLP, in_done, cfg) != 0)) {
		LOG_ERR("IN start failed");
	}
}

static void in_done(uint8_t ep, int size, void *priv)
{
	ARG_UNUSED(ep);
	ARG_UNUSED(priv);
	if (size < 0) {
		return; /* cancelled by a bus reset */
	}
	if (s_next == MSC_SEND_IN) {
		k_work_submit_to_queue(&s_wq, &s_tx_work);
	} else {
		act(s_next);
	}
}

static void rx_work_fn(struct k_work *w)
{
	msc_next_t next;

	ARG_UNUSED(w);
	k_mutex_lock(&s_lock, K_FOREVER);
	next = msc_rx(&s_msc, s_pkt, s_pkt_len);
	k_mutex_unlock(&s_lock);
	act(next);
}

static void read_cb(uint8_t ep, int size, void *priv)
{
	if (size > 0) {
		s_pkt_len = (size_t)size;
		k_work_submit_to_queue(&s_wq, &s_rx_work);
		return;
	}
	if (size == 0) {
		(void)usb_transfer(ep, s_pkt, sizeof(s_pkt), USB_TRANS_READ, read_cb, priv);
	}
}

static void status_cb(struct usb_cfg_data *cfg, enum usb_dc_status_code status,
		      const uint8_t *param)
{
	ARG_UNUSED(param);
	switch (status) {
	case USB_DC_CONFIGURED:
		s_cfg = cfg;
		k_mutex_lock(&s_lock, K_FOREVER);
		msc_reset(&s_msc);
		k_mutex_unlock(&s_lock);
		arm_out();
		break;
	case USB_DC_RESET:
	case USB_DC_DISCONNECTED:
		if (status == USB_DC_DISCONNECTED) {
			s_cfg = NULL;
		}
		k_mutex_lock(&s_lock, K_FOREVER);
		msc_reset(&s_msc);
		k_mutex_unlock(&s_lock);
		break;
	default:
		break;
	}
}

/* Bulk-Only class requests: Get Max LUN (one unit, LUN 0) and reset recovery. */
static int class_req(struct usb_setup_packet *setup, int32_t *len, uint8_t **data)
{
	if (setup->bRequest == MSC_REQ_GET_MAX_LUN) {
		s_max_lun = 0U;
		*data = &s_max_lun;
		*len = 1;
		return 0;
	}
	if (setup->bRequest == MSC_REQ_RESET) {
		k_mutex_lock(&s_lock, K_FOREVER);
		msc_reset(&s_msc);
		k_mutex_unlock(&s_lock);
		*len = 0;
		arm_out(); /* the host clears the halts next, then sends a CBW */
		return 0;
	}
	return -ENOTSUP;
}

/*
 * Zephyr's USB device stack finds where each function's descriptors start by
 * bInterfaceNumber == 0, then calls this to give it its real number (1 here,
 * after the CCID reader). A function declared with any other number is taken
 * for part of the previous one, and enumeration fails ("Failed to validate
 * endpoints").
 */
static void msc_if_config(struct usb_desc_header *head, uint8_t bInterfaceNumber)
{
	ARG_UNUSED(head);
	token_msc_desc.if0.bInterfaceNumber = bInterfaceNumber;
}

static struct usb_ep_cfg_data s_ep_data[] = {
	{ .ep_cb = usb_transfer_ep_callback, .ep_addr = MSC_EP_BULK_OUT },
	{ .ep_cb = usb_transfer_ep_callback, .ep_addr = MSC_EP_BULK_IN },
};

USBD_DEFINE_CFG_DATA(token_msc_config) = {
	.usb_device_description = NULL,
	.interface_descriptor = &token_msc_desc.if0,
	.interface_config = msc_if_config,
	.cb_usb_status = status_cb,
	.interface = {
		.class_handler = class_req,
		.custom_handler = NULL,
		.vendor_handler = NULL,
	},
	.num_endpoints = ARRAY_SIZE(s_ep_data),
	.endpoint = s_ep_data,
};

void token_msc_set_medium(bool present, uint32_t blocks)
{
	if (!s_ready) {
		msc_init(&s_msc, read_blocks, TOKEN_USB_BULK_MPS);
		s_ready = true;
	}
	k_mutex_lock(&s_lock, K_FOREVER);
	msc_set_medium(&s_msc, present, blocks);
	k_mutex_unlock(&s_lock);
	LOG_INF("Install drive: %s (%u KB)", present ? "image present" : "no image",
		(unsigned int)(present ? blocks / 2U : 0U));
}

int token_msc_init(void)
{
	if (!s_ready) {
		msc_init(&s_msc, read_blocks, TOKEN_USB_BULK_MPS);
		s_ready = true;
	}
	k_work_queue_init(&s_wq);
	k_work_queue_start(&s_wq, s_msc_wq_stack, K_THREAD_STACK_SIZEOF(s_msc_wq_stack), MSC_WQ_PRIO,
			   NULL);
	k_thread_name_set(&s_wq.thread, "qdsd_msc");
	k_work_init(&s_rx_work, rx_work_fn);
	k_work_init(&s_tx_work, tx_work_fn);
	return 0;
}
