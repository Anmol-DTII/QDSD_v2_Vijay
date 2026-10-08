/**
 * @file tlv.h
 * @brief Minimal BER-length TLV reader/writer (1-byte tags).
 */
#ifndef QDSD_TLV_H
#define QDSD_TLV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint8_t       *buf;
	size_t         cap;
	size_t         len;
	bool           overflow;
} tlv_writer_t;

void tlv_writer_init(tlv_writer_t *w, uint8_t *buf, size_t cap);
void tlv_put_raw(tlv_writer_t *w, const void *data, size_t len);
void tlv_put(tlv_writer_t *w, uint8_t tag, const void *val, size_t len);
void tlv_put_u8(tlv_writer_t *w, uint8_t tag, uint8_t v);
void tlv_put_u16(tlv_writer_t *w, uint8_t tag, uint16_t v);
void tlv_put_u32(tlv_writer_t *w, uint8_t tag, uint32_t v);
void tlv_put_u64(tlv_writer_t *w, uint8_t tag, uint64_t v);
static inline bool tlv_ok(const tlv_writer_t *w) { return !w->overflow; }

typedef struct {
	const uint8_t *p;
	size_t         left;
} tlv_reader_t;

typedef struct {
	uint8_t        tag;
	size_t         len;
	const uint8_t *val;
} tlv_item_t;

void tlv_reader_init(tlv_reader_t *r, const uint8_t *buf, size_t len);
/** 1 = item read, 0 = end of input, -1 = malformed. */
int tlv_next(tlv_reader_t *r, tlv_item_t *out);

/**
 * Find the single occurrence of tag in buf. Returns 0 and fills out,
 * -ENOENT if absent, -EBADMSG if malformed or duplicated.
 */
int tlv_find(const uint8_t *buf, size_t len, uint8_t tag, tlv_item_t *out);

uint16_t tlv_be16(const uint8_t *p);
uint32_t tlv_be32(const uint8_t *p);
uint64_t tlv_be64(const uint8_t *p);
void     tlv_wr_be16(uint8_t *p, uint16_t v);
void     tlv_wr_be32(uint8_t *p, uint32_t v);
void     tlv_wr_be64(uint8_t *p, uint64_t v);

#endif /* QDSD_TLV_H */
