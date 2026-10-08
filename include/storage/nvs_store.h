#ifndef NVS_STORE_H
#define NVS_STORE_H

/**
 * @file nvs_store.h
 * @brief Internal nRF52840 NVS mount (partition qdsd_nvs_partition).
 *
 * Since firmware 0.6 no record is kept in MCU flash. NVS is mounted only so
 * the token can read the records firmware 0.3-0.5 left there (device
 * certificate 0x0100, slot records 0x0110+slot, DSC certificates 0x0120+slot),
 * move them into the secure elements, and delete them (src/token/token_store.c).
 * Phase-2 ids (0x0001-0x0021) are never read.
 */

#include <stdbool.h>

#include <zephyr/fs/nvs.h>

int qdsd_nvs_init(void);
bool qdsd_nvs_ready(void);
struct nvs_fs *qdsd_nvs_fs(void);

#endif /* NVS_STORE_H */
