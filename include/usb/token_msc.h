/**
 * @file token_msc.h
 * @brief Install drive: the read-only USB disk next to the CCID reader.
 */
#ifndef TOKEN_MSC_H
#define TOKEN_MSC_H

#include <stdbool.h>
#include <stdint.h>

/** Register the mass-storage interface (before usb_enable). */
int token_msc_init(void);
/** A valid image is in flash (or not); blocks of 512 bytes. */
void token_msc_set_medium(bool present, uint32_t blocks);

#endif /* TOKEN_MSC_H */
