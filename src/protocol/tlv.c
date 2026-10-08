/**
 * @file tlv.c
 * @brief Minimal BER-length TLV reader/writer.
 */
#include <errno.h>
#include <string.h>

#include "protocol/tlv.h"

uint16_t tlv_be16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t tlv_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t tlv_be64(const uint8_t *p)
{
	return ((uint64_t)tlv_be32(p) << 32) | (uint64_t)tlv_be32(p + 4);
}

void tlv_wr_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

void tlv_wr_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

void tlv_wr_be64(uint8_t *p, uint64_t v)
{
	tlv_wr_be32(p, (uint32_t)(v >> 32));
	tlv_wr_be32(p + 4, (uint32_t)v);
}

void tlv_writer_init(tlv_writer_t *w, uint8_t *buf, size_t cap)
{
	w->buf = buf;
	w->cap = cap;
	w->len = 0U;
	w->overflow = false;
}

void tlv_put_raw(tlv_writer_t *w, const void *data, size_t len)
{
	if (w->overflow || (len > (w->cap - w->len))) {
		w->overflow = true;
		return;
	}
	if (len > 0U) {
		memcpy(&w->buf[w->len], data, len);
	}
	w->len += len;
}

void tlv_put(tlv_writer_t *w, uint8_t tag, const void *val, size_t len)
{
	uint8_t hdr[4];
	size_t hlen = 0U;

	if (len > 0xFFFFU) {
		w->overflow = true;
		return;
	}

	hdr[hlen++] = tag;
	if (len < 0x80U) {
		hdr[hlen++] = (uint8_t)len;
	} else if (len <= 0xFFU) {
		hdr[hlen++] = 0x81U;
		hdr[hlen++] = (uint8_t)len;
	} else {
		hdr[hlen++] = 0x82U;
		hdr[hlen++] = (uint8_t)(len >> 8);
		hdr[hlen++] = (uint8_t)len;
	}
	tlv_put_raw(w, hdr, hlen);
	tlv_put_raw(w, val, len);
}

void tlv_put_u8(tlv_writer_t *w, uint8_t tag, uint8_t v)
{
	tlv_put(w, tag, &v, 1U);
}

void tlv_put_u16(tlv_writer_t *w, uint8_t tag, uint16_t v)
{
	uint8_t b[2];

	tlv_wr_be16(b, v);
	tlv_put(w, tag, b, sizeof(b));
}

void tlv_put_u32(tlv_writer_t *w, uint8_t tag, uint32_t v)
{
	uint8_t b[4];

	tlv_wr_be32(b, v);
	tlv_put(w, tag, b, sizeof(b));
}

void tlv_put_u64(tlv_writer_t *w, uint8_t tag, uint64_t v)
{
	uint8_t b[8];

	tlv_wr_be64(b, v);
	tlv_put(w, tag, b, sizeof(b));
}

void tlv_reader_init(tlv_reader_t *r, const uint8_t *buf, size_t len)
{
	r->p = buf;
	r->left = (buf == NULL) ? 0U : len;
}

int tlv_next(tlv_reader_t *r, tlv_item_t *out)
{
	size_t len;
	size_t hlen;

	if (r->left == 0U) {
		return 0;
	}
	if (r->left < 2U) {
		return -1;
	}

	out->tag = r->p[0];
	if (r->p[1] < 0x80U) {
		len = r->p[1];
		hlen = 2U;
	} else if (r->p[1] == 0x81U) {
		if (r->left < 3U) {
			return -1;
		}
		len = r->p[2];
		if (len < 0x80U) {
			return -1; /* non-minimal length */
		}
		hlen = 3U;
	} else if (r->p[1] == 0x82U) {
		if (r->left < 4U) {
			return -1;
		}
		len = tlv_be16(&r->p[2]);
		if (len < 0x100U) {
			return -1; /* non-minimal length */
		}
		hlen = 4U;
	} else {
		return -1;
	}

	if (len > (r->left - hlen)) {
		return -1;
	}

	out->len = len;
	out->val = &r->p[hlen];
	r->p += hlen + len;
	r->left -= hlen + len;
	return 1;
}

int tlv_find(const uint8_t *buf, size_t len, uint8_t tag, tlv_item_t *out)
{
	tlv_reader_t r;
	tlv_item_t it;
	bool found = false;
	int rc;

	tlv_reader_init(&r, buf, len);
	while ((rc = tlv_next(&r, &it)) == 1) {
		if (it.tag == tag) {
			if (found) {
				return -EBADMSG;
			}
			*out = it;
			found = true;
		}
	}
	if (rc < 0) {
		return -EBADMSG;
	}
	return found ? 0 : -ENOENT;
}
