/**
 * @file token_usb.h
 * @brief USB CCID transport for the token (class 0x0B, one slot).
 */
#ifndef TOKEN_USB_H
#define TOKEN_USB_H

/** Register descriptors and the APDU work queue (before usb_enable). */
int token_usb_init(void);
/** Attach to the bus (after the TS3USB221 gate is open). */
int token_usb_enable(void);

#endif /* TOKEN_USB_H */
