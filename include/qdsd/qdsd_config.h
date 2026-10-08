/**
 * @file qdsd_config.h
 * @brief Build-time limits for the QDSD core. Zephyr builds map Kconfig here.
 */
#ifndef QDSD_CONFIG_H
#define QDSD_CONFIG_H

#if defined(CONFIG_QDSD_DSC_SLOTS)
#define QDSD_DSC_SLOTS CONFIG_QDSD_DSC_SLOTS
#else
#define QDSD_DSC_SLOTS 4U
#endif

#if defined(CONFIG_QDSD_SESSION_IDLE_S)
#define QDSD_SESSION_IDLE_MS ((uint64_t)CONFIG_QDSD_SESSION_IDLE_S * 1000U)
#else
#define QDSD_SESSION_IDLE_MS (8ULL * 3600U * 1000U)
#endif

#if defined(CONFIG_QDSD_NONCE_TTL_S)
#define QDSD_NONCE_TTL_MS ((uint64_t)CONFIG_QDSD_NONCE_TTL_S * 1000U)
#else
#define QDSD_NONCE_TTL_MS 600000U
#endif

/** Largest X.509 certificate (device or DSC) the token stores. */
#define QDSD_CERT_MAX      2048U
/** Largest command APDU (header + extended Lc + data + Le). */
#define QDSD_APDU_MAX      (QDSD_CERT_MAX + 64U)
/** Largest response body (data + SW). */
#define QDSD_RSP_MAX       2048U
/** Chunk size for GET_CERT / GET_DEVICE_CERT. */
#define QDSD_READ_CHUNK    1024U
/** Failed signature checks before a nonce is discarded. */
#define QDSD_NONCE_MAX_FAILS 3U
/** Outstanding nonces (several apps can wait for phone approval at once). */
#if defined(CONFIG_QDSD_NONCE_SLOTS)
#define QDSD_NONCE_SLOTS CONFIG_QDSD_NONCE_SLOTS
#else
#define QDSD_NONCE_SLOTS 4U
#endif
/** Largest firmware chunk per UPDATE_WRITE. */
#define QDSD_FW_CHUNK_MAX  1024U
/* FACTORY_DRIVE: largest image chunk per APDU (extended APDUs). */
#define QDSD_DRIVE_CHUNK_MAX 2048U
/** Signing receipts kept in the SE050 (ring, oldest overwritten). */
#if defined(CONFIG_QDSD_RECEIPT_RING)
#define QDSD_RECEIPT_RING CONFIG_QDSD_RECEIPT_RING
#else
#define QDSD_RECEIPT_RING 16U
#endif
/** Largest .pfx import package (certificate + wrapped private key). */
#define QDSD_IMPORT_MAX    3072U

#define QDSD_PROTOCOL_VERSION 3U
#define QDSD_PROTOCOL_MINOR   3U
#define QDSD_FW_MAJOR 0U
#define QDSD_FW_MINOR 7U
#define QDSD_FW_PATCH 0U
#define QDSD_FW_BUILD 0U

#endif /* QDSD_CONFIG_H */
