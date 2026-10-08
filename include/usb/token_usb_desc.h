/**
 * @file token_usb_desc.h
 * @brief USB identity and endpoints of the CCID interface (protocol v3.2).
 *
 * VID/PID are unchanged from Phase 2 (Nordic's development VID 0x1915):
 * production units need DTII's own USB-IF VID/PID (docs/USB_CCID.md).
 * No vendor descriptors are needed any more: every OS binds its built-in
 * smart-card reader driver to interface class 0x0B.
 */
#ifndef TOKEN_USB_DESC_H
#define TOKEN_USB_DESC_H

#include <stdint.h>

#include "usb/ccid.h"

#define TOKEN_USB_VID              0x1915U
#define TOKEN_USB_PID              0x520FU

#define TOKEN_USB_INTERFACE_NUM    0U
#define TOKEN_USB_INTERFACE_CLASS  0x0BU /* Smart Card (CCID) */

#define TOKEN_USB_EP_BULK_OUT      0x01U
#define TOKEN_USB_EP_BULK_IN       0x81U
#define TOKEN_USB_EP_INT_IN        0x82U

#define TOKEN_USB_BULK_MPS         64U
#define TOKEN_USB_INT_MPS          8U
#define TOKEN_USB_INT_INTERVAL     16U /* ms (full speed) */

/** Seconds of APDU processing before each CCID time extension. */
#define TOKEN_USB_WTX_MS           1000U

#endif /* TOKEN_USB_DESC_H */
