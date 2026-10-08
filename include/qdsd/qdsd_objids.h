/**
 * @file qdsd_objids.h
 * @brief Object-ID map of both secure elements (docs/OBJECT_IDS.md).
 *
 * Every secure object QDSD creates lives in one of two ranges, one per
 * element, set by Kconfig so a deployment can move them (for example to stay
 * clear of another application on the same chip). The defaults are the ids
 * firmware 0.3-0.5 used, so tokens already in the field keep working.
 *
 * Changing a base on a token that has objects orphans them: only do it for
 * new production, together with the factory tool.
 *
 * Ids in 0x7FFF0000-0x7FFFFFFF and 0xF0000000-0xFFFFFFFF are reserved by
 * NXP (applet and trust-provisioned objects) and are listed at the end.
 */
#ifndef QDSD_OBJIDS_H
#define QDSD_OBJIDS_H

#include <stdint.h>

#if defined(CONFIG_QDSD_OID_SE050_BASE)
#define QDSD_OID_SE050_BASE ((uint32_t)CONFIG_QDSD_OID_SE050_BASE)
#else
#define QDSD_OID_SE050_BASE 0x51DE0000U
#endif

#if defined(CONFIG_QDSD_OID_SE052F_BASE)
#define QDSD_OID_SE052F_BASE ((uint32_t)CONFIG_QDSD_OID_SE052F_BASE)
#else
#define QDSD_OID_SE052F_BASE 0x5D5C0000U
#endif

/* ── SE050: device trust ─────────────────────────────────────────────── */
#define OID_DEVKEY        (QDSD_OID_SE050_BASE + 0x0001U) /* P-256 key pair, device key   */
#define OID_CMD_PUB       (QDSD_OID_SE050_BASE + 0x0002U) /* P-256 public, DTI command key */
#define OID_ACT_PUB       (QDSD_OID_SE050_BASE + 0x0003U) /* P-256 public, phone key       */
#define OID_STATE         (QDSD_OID_SE050_BASE + 0x0010U) /* binary 96 B, lifecycle record */
#define OID_CTR_BASE      (QDSD_OID_SE050_BASE + 0x0021U) /* counters: +0 binding, +1 keygen,
							    +2 sign, +3 policy           */
#define OID_DEVICE_CERT   (QDSD_OID_SE050_BASE + 0x0030U) /* binary, device certificate    */
#define OID_RECEIPT_BASE  (QDSD_OID_SE050_BASE + 0x0100U) /* binary 528 B each, + entry
							    (0..RECEIPT_RING-1)          */

/* ── SE052F: DSC keys and their records ─────────────────────────────── */
#define OID_DSC_KEY_BASE  (QDSD_OID_SE052F_BASE + 0x0000U) /* + slot: P-256 or RSA-2048 pair */
#define OID_SLOT_REC_BASE (QDSD_OID_SE052F_BASE + 0x0100U) /* + slot: binary 48 B           */
#define OID_SLOT_CRT_BASE (QDSD_OID_SE052F_BASE + 0x0200U) /* + slot: binary, DSC certificate */

/* ── NXP reserved ids used by QDSD ───────────────────────────────────── */
#define OID_FACTORY_RESET 0x7FFF0205U /* UserID: secret for DeleteAll (both elements) */
#define OID_UNIQUE_ID     0x7FFF0206U /* 18-byte chip unique id (read only)          */
#define OID_NXP_ATT_KEY   0xF0000012U /* NXP ECC attestation key (trust-provisioned) */

#endif /* QDSD_OBJIDS_H */
