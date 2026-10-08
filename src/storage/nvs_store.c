/**
 * @file nvs_store.c
 * @brief Mount NVS on the internal storage partition (end of nRF flash).
 *
 * Product builds (--sysbuild) use the NCS Partition Manager: the partition is
 * `nvs_storage` from pm_static.yml. Builds without it (prj_noupdate.conf,
 * upstream-Zephyr CI) use the devicetree label `qdsd_nvs_partition` from the
 * board definition. Both point at the same flash on the QDSD board, so
 * records written by 0.3-0.5 are found and migrated.
 */

#include <errno.h>

#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/fs/nvs.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>

#include "storage/nvs_store.h"

LOG_MODULE_REGISTER(nvs_store, LOG_LEVEL_INF);

#if defined(CONFIG_PARTITION_MANAGER_ENABLED)
#define STORAGE_PARTITION        nvs_storage
#else
#define STORAGE_PARTITION        qdsd_nvs_partition
#endif
#define STORAGE_PARTITION_DEVICE FIXED_PARTITION_DEVICE(STORAGE_PARTITION)
#define STORAGE_PARTITION_OFFSET FIXED_PARTITION_OFFSET(STORAGE_PARTITION)
#define STORAGE_PARTITION_SIZE   FIXED_PARTITION_SIZE(STORAGE_PARTITION)

static struct nvs_fs s_nvs;
static bool s_ready;

int qdsd_nvs_init(void)
{
	struct flash_pages_info info;
	int ret;

	s_ready = false;

	s_nvs.flash_device = STORAGE_PARTITION_DEVICE;
	if (!device_is_ready(s_nvs.flash_device)) {
		LOG_ERR("NVS flash device not ready");
		return -ENODEV;
	}

	s_nvs.offset = STORAGE_PARTITION_OFFSET;
	ret = flash_get_page_info_by_offs(s_nvs.flash_device, s_nvs.offset, &info);
	if (ret != 0) {
		LOG_ERR("NVS page info failed: %d", ret);
		return ret;
	}

	if (info.size == 0U) {
		return -EINVAL;
	}

	s_nvs.sector_size = info.size;
	s_nvs.sector_count = STORAGE_PARTITION_SIZE / info.size;
	if (s_nvs.sector_count == 0U) {
		LOG_ERR("NVS storage partition too small");
		return -EINVAL;
	}

	ret = nvs_mount(&s_nvs);
	if (ret != 0) {
		LOG_ERR("NVS mount failed: %d", ret);
		return ret;
	}

	s_ready = true;
	LOG_INF("NVS ready — %u sectors x %u B @ 0x%08X (cert + pubkey)",
		s_nvs.sector_count, s_nvs.sector_size, (uint32_t)s_nvs.offset);
	return 0;
}

bool qdsd_nvs_ready(void)
{
	return s_ready;
}

struct nvs_fs *qdsd_nvs_fs(void)
{
	return s_ready ? &s_nvs : NULL;
}
