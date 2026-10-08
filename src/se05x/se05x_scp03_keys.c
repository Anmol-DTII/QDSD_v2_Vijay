/**
 * @file se05x_scp03_keys.c
 * @brief Platform SCP03 key binding for SE050 and SE052F.
 *
 * Production: keys come from scp03_prod_keys.h, generated per batch by the
 * manufacturing key ceremony and never committed (see .gitignore). The nRF
 * APPROTECT lock (prj.conf) keeps them from being read out over SWD.
 *
 * Lab (CONFIG_QDSD_SCP03_LAB_KEYS): NXP's published default keys. These are
 * public, so a lab image gives no protection on the I2C link.
 */
#include <zephyr/logging/log.h>

#include "se05x/se05x_scp03_keys.h"

LOG_MODULE_REGISTER(se05x_scp03, LOG_LEVEL_INF);

#if defined(CONFIG_PLUGANDTRUST) && defined(CONFIG_PLUGANDTRUST_SCP03)

#include "se05x/se05x_smlog_shim.h"
#include "se05x_APDU_apis.h"

#if defined(CONFIG_QDSD_SCP03_LAB_KEYS)

#if defined(CONFIG_QDSD_SE050_C1)
/* NXP Plug & Trust ex_sss_tp_scp03_keys.h — SE050C1, OEF A200. LAB ONLY. */
static const uint8_t k_dev_enc[16] = {
	0x85, 0x2B, 0x59, 0x62, 0xE9, 0xCC, 0xE5, 0xD0,
	0xBE, 0x74, 0x6B, 0x83, 0x3B, 0xCC, 0x62, 0x87,
};
static const uint8_t k_dev_mac[16] = {
	0xDB, 0x0A, 0xA3, 0x19, 0xA4, 0x08, 0x69, 0x6C,
	0x8E, 0x10, 0x7A, 0xB4, 0xE3, 0xC2, 0x6B, 0x47,
};
static const uint8_t k_dev_dek[16] = {
	0x4C, 0x2F, 0x75, 0xC6, 0xA2, 0x78, 0xA4, 0xAE,
	0xE5, 0xC9, 0xAF, 0x7C, 0x50, 0xEE, 0xA8, 0x0C,
};
#else
/* NXP Plug & Trust ex_sss_tp_scp03_keys.h — SE050C2, OEF A201. LAB ONLY. */
static const uint8_t k_dev_enc[16] = {
	0xBD, 0x1D, 0xE2, 0x0A, 0x81, 0xEA, 0xB2, 0xBF,
	0x3B, 0x70, 0x9A, 0x9D, 0x69, 0xA3, 0x12, 0x54,
};
static const uint8_t k_dev_mac[16] = {
	0x9A, 0x76, 0x1B, 0x8D, 0xBA, 0x6B, 0xED, 0xF2,
	0x27, 0x41, 0xE4, 0x5D, 0x8D, 0x42, 0x36, 0xF5,
};
static const uint8_t k_dev_dek[16] = {
	0x9B, 0x99, 0x3B, 0x60, 0x0F, 0x1C, 0x64, 0xF5,
	0xAD, 0xC0, 0x63, 0x19, 0x2A, 0x96, 0xC9, 0x47,
};
#endif

/* AN14277 Table 4 — SE052F, OEF B501. LAB ONLY. */
static const uint8_t k_dsc_enc[16] = {
	0x3A, 0xE4, 0x41, 0xC7, 0x47, 0xE3, 0x2E, 0xBC,
	0x16, 0xB3, 0xBB, 0x2D, 0x84, 0x3C, 0x6D, 0xD8,
};
static const uint8_t k_dsc_mac[16] = {
	0x6C, 0x18, 0xF3, 0xD0, 0x8F, 0xEE, 0x1C, 0xB9,
	0x6A, 0x3C, 0x8D, 0xE5, 0xD3, 0x53, 0x8A, 0xAA,
};
static const uint8_t k_dsc_dek[16] = {
	0xB0, 0xE6, 0xA5, 0x69, 0x7D, 0xBD, 0x92, 0x92,
	0x43, 0xA4, 0x82, 0xCF, 0x9E, 0x4D, 0x65, 0x22,
};

#else /* production */

#if !__has_include("scp03_prod_keys.h")
#error "Production build needs scp03_prod_keys.h (manufacturing key ceremony). \
For bench builds merge prj_lab.conf (CONFIG_QDSD_SCP03_LAB_KEYS=y)."
#endif
#include "scp03_prod_keys.h"
static const uint8_t k_dev_enc[16] = QDSD_SCP03_SE050_ENC;
static const uint8_t k_dev_mac[16] = QDSD_SCP03_SE050_MAC;
static const uint8_t k_dev_dek[16] = QDSD_SCP03_SE050_DEK;
static const uint8_t k_dsc_enc[16] = QDSD_SCP03_SE052F_ENC;
static const uint8_t k_dsc_mac[16] = QDSD_SCP03_SE052F_MAC;
static const uint8_t k_dsc_dek[16] = QDSD_SCP03_SE052F_DEK;

#endif

void se05x_scp03_bind(int which, Se05xSession_t *s)
{
	const bool dev = (which == 0);

	s->pScp03_enc_key = (uint8_t *)(dev ? k_dev_enc : k_dsc_enc);
	s->pScp03_mac_key = (uint8_t *)(dev ? k_dev_mac : k_dsc_mac);
	s->pScp03_dek_key = (uint8_t *)(dev ? k_dev_dek : k_dsc_dek);
	s->scp03_enc_key_len = 16U;
	s->scp03_mac_key_len = 16U;
	s->scp03_dek_key_len = 16U;
	s->session_resume = 0U;
#if defined(CONFIG_QDSD_SCP03_LAB_KEYS)
	LOG_WRN("%s: NXP default SCP03 keys (LAB ONLY)", dev ? "SE050" : "SE052F");
#endif
}

#endif /* CONFIG_PLUGANDTRUST && CONFIG_PLUGANDTRUST_SCP03 */
