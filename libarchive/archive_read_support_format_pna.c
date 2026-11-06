/*-
 * Copyright (c) 2026 Daiki Tsunekawa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.
 */

/*
 * Reader for the Portable Network Archive (PNA) format.
 *
 * A PNA archive is a PNG-style chunk stream: an 8-byte signature
 * followed by chunks of the form <length:u32be> <type:4> <data>
 * <crc32:u32be>, where the CRC covers the type and the data.
 * Entries are FHED..FEND sequences; a solid block wraps a whole
 * entry stream (itself chunk-framed) in SHED..SDAT..SEND and
 * compresses it as a unit.  Split archives are a sequence of such
 * streams, each signed and numbered, with an ANXT chunk before the
 * AEND of every part but the last; chunk boundaries never split
 * across parts, so a reader can treat the parts as one continuous
 * chunk stream once the per-part framing is skipped.
 *
 * Encryption is not supported: entries whose FHED announces an
 * encryption method (and solid blocks likewise) are rejected.
 *
 * Entry data streams without bound; only metadata materialization
 * is capped, as a safety valve against crafted archives:
 * PNA_MAX_BUFFERED_CHUNK bounds a single header or ancillary
 * chunk held in memory, and PNA_MAX_LINK_TARGET bounds a link
 * target string.  The fSIZ chunk is a hint and never drives an
 * allocation.
 */

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_ZSTD_H
#include <zstd.h>
#endif
#if defined(HAVE_LZMA_H) && defined(HAVE_LIBLZMA)
#include <lzma.h>
#define HAVE_PNA_LZMA 1
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_read_private.h"
#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif
#include "archive_endian.h"

/*
 * CRC-32 of the PNG/zlib polynomial, updated in bounded pieces
 * so the same call serves zlib's crc32 (uInt length) and the
 * archive_crc32.h fallback (size_t length).
 */
static unsigned long
pna_crc32(unsigned long crc, const void *buf, size_t len)
{
	const unsigned char *p = buf;

	while (len > 0) {
		size_t n = len > 0x40000000U ? 0x40000000U : len;
		crc = crc32(crc, p, n);
		p += n;
		len -= n;
	}
	return (crc);
}

/* Compression methods recorded in FHED/SHED. */
#define PNA_COMPRESSION_NONE		0
#define PNA_COMPRESSION_DEFLATE		1
#define PNA_COMPRESSION_ZSTD		2
#define PNA_COMPRESSION_XZ		4

/* Entry kinds recorded in FHED. */
#define PNA_KIND_FILE			0
#define PNA_KIND_DIRECTORY		1
#define PNA_KIND_SYMLINK		2
#define PNA_KIND_HARDLINK		3

/* Largest ancillary/FHED chunk we buffer in memory.  Data chunks
 * (FDAT/SDAT) are streamed and never go through this path. */
#define PNA_MAX_BUFFERED_CHUNK		(16U * 1024 * 1024)
/* Link targets are materialized as archive_entry strings. */
#define PNA_MAX_LINK_TARGET		(1024U * 1024)

static const unsigned char pna_signature[8] =
    { 0x89, 0x50, 0x4e, 0x41, 0x0d, 0x0a, 0x1a, 0x0a };

struct pna_decompressor {
	int		 method;
	int		 initialized;
	int		 stream_end;
#if defined(HAVE_ZLIB_H)
	z_stream	 zstream;
#endif
#if defined(HAVE_ZSTD_H)
	ZSTD_DStream	*zstdstream;
#endif
#if defined(HAVE_PNA_LZMA)
	lzma_stream	 lzmastream;
#endif
};

struct pna_chunk {
	char		 type[4];
	uint32_t	 remaining;
	unsigned long	 crc;
	int		 active;
};

struct archive_read_pna {
	/* Archive framing. */
	int		 framing_done;
	uint32_t	 archive_number;
	int		 anxt;
	/* Current chunk of the physical stream. */
	struct pna_chunk outer;
	/* Solid block state. */
	int		 in_solid;
	struct pna_decompressor solid_dec;
	int		 solid_dec_started;
	int		 solid_input_done;
	int		 solid_send_consumed;
	unsigned char	*solid_buf;
	size_t		 solid_buf_cap;
	size_t		 solid_buf_len;
	size_t		 solid_buf_pos;
	/* Current chunk of the solid (inner) stream. */
	struct pna_chunk inner;
	/* Current entry state. */
	int		 entry_open;
	int		 entry_in_solid;
	int		 entry_data_end;
	int		 entry_kind;
	int		 entry_compression;
	struct pna_decompressor dec;
	int		 dec_started;
	/* Decompressed data handed out through the block API. */
	unsigned char	*out_buf;
	size_t		 out_len;
	size_t		 out_pos;
	int64_t		 data_offset;
};

static int pna_bid(struct archive_read *, int);
static int pna_cleanup(struct archive_read *);
static int pna_read_header(struct archive_read *, struct archive_entry *);
static int pna_read_data(struct archive_read *, const void **,
    size_t *, int64_t *);
static int pna_read_data_skip(struct archive_read *);

static int decompressor_init(struct archive_read *, struct pna_decompressor *,
    int);
static void decompressor_free(struct pna_decompressor *);
static int decompressor_produce(struct archive_read *,
    struct pna_decompressor *, const void *, size_t, size_t *,
    void *, size_t, size_t *);

int
archive_read_support_format_pna(struct archive *_a)
{
	struct archive_read *a = (struct archive_read *)_a;
	struct archive_read_pna *p;
	int r;

	archive_check_magic(_a, ARCHIVE_READ_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_read_support_format_pna");

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA data");
		return (ARCHIVE_FATAL);
	}
#if defined(HAVE_PNA_LZMA)
	memset(&p->dec.lzmastream, 0, sizeof(p->dec.lzmastream));
	memset(&p->solid_dec.lzmastream, 0,
	    sizeof(p->solid_dec.lzmastream));
#endif

	r = __archive_read_register_format(a, p, "pna",
	    pna_bid, NULL, pna_read_header, pna_read_data,
	    pna_read_data_skip, NULL, pna_cleanup,
	    NULL, NULL);
	if (r != ARCHIVE_OK) {
		free(p);
		return (r);
	}
	return (ARCHIVE_OK);
}

static int
pna_bid(struct archive_read *a, int best_bid)
{
	const void *buf;
	ssize_t avail;

	(void)best_bid;
	buf = __archive_read_ahead(a, sizeof(pna_signature), &avail);
	if (buf == NULL || avail < (ssize_t)sizeof(pna_signature))
		return (0);
	if (memcmp(buf, pna_signature, sizeof(pna_signature)) != 0)
		return (0);
	return (64);
}

static int
pna_cleanup(struct archive_read *a)
{
	struct archive_read_pna *p = a->format->data;

	decompressor_free(&p->dec);
	decompressor_free(&p->solid_dec);
	free(p->solid_buf);
	free(p->out_buf);
	free(p);
	a->format->data = NULL;
	return (ARCHIVE_OK);
}

/*
 * Decompressor plumbing.  A decompressor consumes part of one
 * input slice and produces part of one output buffer per call;
 * stream_end is set when the underlying compressed stream is
 * complete.  For PNA_COMPRESSION_NONE it is a plain copy.
 */
static int
decompressor_init(struct archive_read *a, struct pna_decompressor *d,
    int method)
{
	d->method = method;
	d->stream_end = 0;
	d->initialized = 1;
	switch (method) {
	case PNA_COMPRESSION_NONE:
		d->stream_end = 0;
		return (ARCHIVE_OK);
	case PNA_COMPRESSION_DEFLATE:
#if defined(HAVE_ZLIB_H)
		memset(&d->zstream, 0, sizeof(d->zstream));
		if (inflateInit(&d->zstream) != Z_OK) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Failed to initialize zlib inflater");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA entry is deflate-compressed, but this version of "
		    "libarchive was compiled without zlib support");
		return (ARCHIVE_FATAL);
#endif
	case PNA_COMPRESSION_ZSTD:
#if defined(HAVE_ZSTD_H)
		d->zstdstream = ZSTD_createDStream();
		if (d->zstdstream == NULL ||
		    ZSTD_isError(ZSTD_initDStream(d->zstdstream))) {
			archive_set_error(&a->archive, ENOMEM,
			    "Failed to initialize zstd decompressor");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA entry is zstd-compressed, but this version of "
		    "libarchive was compiled without libzstd support");
		return (ARCHIVE_FATAL);
#endif
	case PNA_COMPRESSION_XZ:
#if defined(HAVE_PNA_LZMA)
		if (lzma_stream_decoder(&d->lzmastream, UINT64_MAX, 0)
		    != LZMA_OK) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Failed to initialize lzma decoder");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA entry is xz-compressed, but this version of "
		    "libarchive was compiled without liblzma support");
		return (ARCHIVE_FATAL);
#endif
	default:
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unsupported PNA compression method %d", method);
		return (ARCHIVE_FATAL);
	}
}

static void
decompressor_free(struct pna_decompressor *d)
{
	if (!d->initialized)
		return;
	switch (d->method) {
	case PNA_COMPRESSION_DEFLATE:
#if defined(HAVE_ZLIB_H)
		inflateEnd(&d->zstream);
#endif
		break;
	case PNA_COMPRESSION_ZSTD:
#if defined(HAVE_ZSTD_H)
		if (d->zstdstream != NULL)
			ZSTD_freeDStream(d->zstdstream);
		d->zstdstream = NULL;
#endif
		break;
	case PNA_COMPRESSION_XZ:
#if defined(HAVE_PNA_LZMA)
		lzma_end(&d->lzmastream);
#endif
		break;
	default:
		break;
	}
	d->initialized = 0;
}

static int
decompressor_produce(struct archive_read *a, struct pna_decompressor *d,
    const void *in, size_t in_len, size_t *in_used,
    void *out, size_t out_cap, size_t *out_made)
{
	*in_used = 0;
	*out_made = 0;
	if (d->stream_end)
		return (ARCHIVE_OK);
	switch (d->method) {
	case PNA_COMPRESSION_NONE: {
		size_t n = in_len < out_cap ? in_len : out_cap;
		if (n > 0)
			memcpy(out, in, n);
		*in_used = n;
		*out_made = n;
		return (ARCHIVE_OK);
	}
	case PNA_COMPRESSION_DEFLATE: {
#if defined(HAVE_ZLIB_H)
		int ret;
		/* zlib counts in uInt; feed at most 1 GiB per call so
		 * the counts cannot truncate (same bound as the
		 * CRC helper). */
		size_t in_slice = in_len > 0x40000000U
		    ? 0x40000000U : in_len;
		size_t out_slice = out_cap > 0x40000000U
		    ? 0x40000000U : out_cap;
		d->zstream.next_in = (Bytef *)(uintptr_t)in;
		d->zstream.avail_in = (uInt)in_slice;
		d->zstream.next_out = out;
		d->zstream.avail_out = (uInt)out_slice;
		ret = inflate(&d->zstream, Z_NO_FLUSH);
		*in_used = in_slice - d->zstream.avail_in;
		*out_made = out_slice - d->zstream.avail_out;
		if (ret == Z_STREAM_END) {
			d->stream_end = 1;
			return (ARCHIVE_OK);
		}
		if (ret == Z_OK || ret == Z_BUF_ERROR)
			return (ARCHIVE_OK);
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Deflate decompression failed");
		return (ARCHIVE_FATAL);
#else
		(void)in; (void)in_len; (void)out; (void)out_cap;
		return (ARCHIVE_FATAL);
#endif
	}
	case PNA_COMPRESSION_ZSTD: {
#if defined(HAVE_ZSTD_H)
		ZSTD_inBuffer inbuf = { in, in_len, 0 };
		ZSTD_outBuffer outbuf = { out, out_cap, 0 };
		size_t ret = ZSTD_decompressStream(d->zstdstream,
		    &outbuf, &inbuf);
		*in_used = inbuf.pos;
		*out_made = outbuf.pos;
		if (ZSTD_isError(ret)) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Zstd decompression failed: %s",
			    ZSTD_getErrorName(ret));
			return (ARCHIVE_FATAL);
		}
		if (ret == 0)
			d->stream_end = 1;
		return (ARCHIVE_OK);
#else
		(void)in; (void)in_len; (void)out; (void)out_cap;
		return (ARCHIVE_FATAL);
#endif
	}
	case PNA_COMPRESSION_XZ: {
#if defined(HAVE_PNA_LZMA)
		lzma_ret ret;
		d->lzmastream.next_in = in;
		d->lzmastream.avail_in = in_len;
		d->lzmastream.next_out = out;
		d->lzmastream.avail_out = out_cap;
		ret = lzma_code(&d->lzmastream, LZMA_RUN);
		*in_used = in_len - d->lzmastream.avail_in;
		*out_made = out_cap - d->lzmastream.avail_out;
		if (ret == LZMA_STREAM_END) {
			d->stream_end = 1;
			return (ARCHIVE_OK);
		}
		if (ret == LZMA_OK || ret == LZMA_BUF_ERROR)
			return (ARCHIVE_OK);
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "XZ decompression failed");
		return (ARCHIVE_FATAL);
#else
		(void)in; (void)in_len; (void)out; (void)out_cap;
		return (ARCHIVE_FATAL);
#endif
	}
	default:
		return (ARCHIVE_FATAL);
	}
}

/*
 * Physical stream primitives.  All of them return ARCHIVE_OK or
 * ARCHIVE_FATAL.  A chunk's CRC is verified as a side effect of
 * consuming the last byte of its data.
 */
static int
phys_read_exact(struct archive_read *a, void *dst, size_t n)
{
	unsigned char *p = dst;

	while (n > 0) {
		const void *buf;
		ssize_t avail;
		size_t take;

		buf = __archive_read_ahead(a, 1, &avail);
		if (buf == NULL || avail <= 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA archive");
			return (ARCHIVE_FATAL);
		}
		take = (size_t)avail < n ? (size_t)avail : n;
		memcpy(p, buf, take);
		__archive_read_consume(a, take);
		p += take;
		n -= take;
	}
	return (ARCHIVE_OK);
}

/* Open the next raw chunk of the physical stream into p->outer. */
static int
phys_open_raw(struct archive_read *a, struct archive_read_pna *p)
{
	unsigned char hdr[8];

	if (phys_read_exact(a, hdr, sizeof(hdr)) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	p->outer.remaining = archive_be32dec(hdr);
	memcpy(p->outer.type, hdr + 4, 4);
	p->outer.crc = pna_crc32(0, hdr + 4, 4);
	p->outer.active = 1;
	if (p->outer.remaining == 0) {
		/* An empty chunk's CRC follows its header at once. */
		unsigned char crcbuf[4];
		p->outer.active = 0;
		if (phys_read_exact(a, crcbuf, sizeof(crcbuf)) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (archive_be32dec(crcbuf) != (uint32_t)p->outer.crc) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA chunk CRC mismatch (chunk %.4s)",
			    p->outer.type);
			return (ARCHIVE_FATAL);
		}
	}
	return (ARCHIVE_OK);
}

static const unsigned char *
phys_slice(struct archive_read *a, struct archive_read_pna *p, size_t *len)
{
	const void *buf;
	ssize_t avail;

	if (!p->outer.active || p->outer.remaining == 0)
		return (NULL);
	buf = __archive_read_ahead(a, 1, &avail);
	if (buf == NULL || avail <= 0)
		return (NULL);
	*len = (size_t)avail < p->outer.remaining
	    ? (size_t)avail : p->outer.remaining;
	return (buf);
}

static int
phys_consume(struct archive_read *a, struct archive_read_pna *p,
    const unsigned char *ptr, size_t n)
{
	p->outer.crc = pna_crc32(p->outer.crc, ptr, n);
	__archive_read_consume(a, n);
	p->outer.remaining -= (uint32_t)n;
	if (p->outer.remaining == 0) {
		unsigned char crcbuf[4];
		p->outer.active = 0;
		if (phys_read_exact(a, crcbuf, sizeof(crcbuf)) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (archive_be32dec(crcbuf) != (uint32_t)p->outer.crc) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA chunk CRC mismatch (chunk %.4s)",
			    p->outer.type);
			return (ARCHIVE_FATAL);
		}
	}
	return (ARCHIVE_OK);
}

static int
phys_drain(struct archive_read *a, struct archive_read_pna *p)
{
	while (p->outer.active && p->outer.remaining > 0) {
		const unsigned char *ptr;
		size_t len;

		ptr = phys_slice(a, p, &len);
		if (ptr == NULL) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->outer.type);
			return (ARCHIVE_FATAL);
		}
		if (phys_consume(a, p, ptr, len) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	return (ARCHIVE_OK);
}

static int
phys_read_chunk_exact(struct archive_read *a, struct archive_read_pna *p,
    void *dst, size_t n)
{
	unsigned char *out = dst;

	if (n > p->outer.remaining) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA chunk %.4s is too short", p->outer.type);
		return (ARCHIVE_FATAL);
	}
	while (n > 0) {
		const unsigned char *ptr;
		size_t len, take;

		ptr = phys_slice(a, p, &len);
		if (ptr == NULL) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->outer.type);
			return (ARCHIVE_FATAL);
		}
		take = len < n ? len : n;
		memcpy(out, ptr, take);
		if (phys_consume(a, p, ptr, take) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		out += take;
		n -= take;
	}
	return (ARCHIVE_OK);
}

/*
 * Open the next logical chunk of the physical stream.  ANXT/AEND
 * part framing of split archives is handled transparently: when a
 * part ends with ANXT, the signature and AHED of the next part are
 * consumed and verified here.  Returns 1 when a chunk is open in
 * p->outer, 0 at the end of the (final part of the) archive, or
 * ARCHIVE_FATAL.
 */
static int
outer_open_chunk(struct archive_read *a, struct archive_read_pna *p)
{
	for (;;) {
		if (phys_open_raw(a, p) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (p->anxt && memcmp(p->outer.type, "AEND", 4) != 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "ANXT chunk is not followed by AEND");
			return (ARCHIVE_FATAL);
		}
		if (memcmp(p->outer.type, "ANXT", 4) == 0) {
			if (phys_drain(a, p) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			p->anxt = 1;
			continue;
		}
		if (memcmp(p->outer.type, "AEND", 4) == 0) {
			unsigned char sig[8];
			unsigned char ahed[8];
			uint32_t number;

			if (phys_drain(a, p) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (!p->anxt)
				return (0);
			p->anxt = 0;
			/* The archive continues in a following part. */
			if (phys_read_exact(a, sig, sizeof(sig)) != ARCHIVE_OK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA archive continues in a following "
				    "part, but no more data is available");
				return (ARCHIVE_FATAL);
			}
			if (memcmp(sig, pna_signature,
			    sizeof(pna_signature)) != 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Bad signature in following PNA part");
				return (ARCHIVE_FATAL);
			}
			if (phys_open_raw(a, p) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (memcmp(p->outer.type, "AHED", 4) != 0 ||
			    p->outer.remaining != 8) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Following PNA part does not start "
				    "with an AHED chunk");
				return (ARCHIVE_FATAL);
			}
			if (phys_read_chunk_exact(a, p, ahed, 8)
			    != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			number = archive_be32dec(ahed + 4);
			if (ahed[0] != 0 || number != p->archive_number + 1) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA part number out of sequence");
				return (ARCHIVE_FATAL);
			}
			p->archive_number = number;
			continue;
		}
		if (memcmp(p->outer.type, "AHED", 4) == 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Unexpected AHED chunk in PNA archive");
			return (ARCHIVE_FATAL);
		}
		return (1);
	}
}

/*
 * Solid stream: the decompressed contents of the SDAT chunks form
 * an inner chunk stream.  solid_fill() refills p->solid_buf from
 * the physical stream; it returns the number of bytes added, 0
 * when the inner stream is exhausted, or ARCHIVE_FATAL.
 */
static ssize_t
solid_fill(struct archive_read *a, struct archive_read_pna *p)
{
	if (p->solid_input_done)
		return (0);
	/* Compact and ensure there is room to decompress into. */
	if (p->solid_buf_pos > 0) {
		p->solid_buf_len -= p->solid_buf_pos;
		if (p->solid_buf_len > 0)
			memmove(p->solid_buf, p->solid_buf + p->solid_buf_pos,
			    p->solid_buf_len);
		p->solid_buf_pos = 0;
	}
	if (p->solid_buf_cap - p->solid_buf_len < 65536) {
		size_t ncap = p->solid_buf_cap == 0
		    ? 65536 : p->solid_buf_cap * 2;
		unsigned char *nbuf = realloc(p->solid_buf, ncap);
		if (nbuf == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA solid buffer");
			return (ARCHIVE_FATAL);
		}
		p->solid_buf = nbuf;
		p->solid_buf_cap = ncap;
	}
	for (;;) {
		const unsigned char *ptr;
		size_t len, in_used, out_made;
		int r;

		if (p->outer.active) {
			if (memcmp(p->outer.type, "SDAT", 4) != 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Expected SDAT chunk in solid block");
				return (ARCHIVE_FATAL);
			}
			if (p->outer.remaining == 0) {
				/* Chunk finished; open the next one. */
				p->outer.active = 0;
				continue;
			}
			ptr = phys_slice(a, p, &len);
			if (ptr == NULL) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Truncated SDAT chunk");
				return (ARCHIVE_FATAL);
			}
			r = decompressor_produce(a, &p->solid_dec, ptr, len,
			    &in_used, p->solid_buf + p->solid_buf_len,
			    p->solid_buf_cap - p->solid_buf_len, &out_made);
			if (phys_consume(a, p, ptr, in_used) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (r != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			p->solid_buf_len += out_made;
			if (p->solid_dec.stream_end) {
				p->solid_input_done = 1;
				/* Discard any padding after the stream. */
				if (p->outer.active &&
				    phys_drain(a, p) != ARCHIVE_OK)
					return (ARCHIVE_FATAL);
			}
			if (out_made > 0 || p->solid_input_done)
				return ((ssize_t)out_made);
			if (in_used == 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA decompression made no progress");
				return (ARCHIVE_FATAL);
			}
			/* No output yet: keep feeding the decompressor. */
			continue;
		}
		/* No SDAT chunk is open: read the next physical chunk. */
		if (outer_open_chunk(a, p) != 1)
			return (ARCHIVE_FATAL);
		if (memcmp(p->outer.type, "SDAT", 4) == 0)
			continue;
		if (memcmp(p->outer.type, "SEND", 4) == 0) {
			if (p->solid_dec.method != PNA_COMPRESSION_NONE &&
			    !p->solid_dec.stream_end) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Truncated solid compression stream");
				return (ARCHIVE_FATAL);
			}
			if (phys_drain(a, p) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			p->solid_input_done = 1;
			p->solid_send_consumed = 1;
			return (0);
		}
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Expected SDAT or SEND chunk in solid block");
		return (ARCHIVE_FATAL);
	}
}

/* Read raw bytes from the inner stream (no chunk accounting). */
static int
solid_read_raw(struct archive_read *a, struct archive_read_pna *p,
    void *dst, size_t n)
{
	unsigned char *out = dst;

	while (n > 0) {
		size_t avail, take;

		if (p->solid_buf_pos == p->solid_buf_len) {
			if (solid_fill(a, p) <= 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Truncated solid stream in PNA archive");
				return (ARCHIVE_FATAL);
			}
		}
		avail = p->solid_buf_len - p->solid_buf_pos;
		take = avail < n ? avail : n;
		memcpy(out, p->solid_buf + p->solid_buf_pos, take);
		p->solid_buf_pos += take;
		out += take;
		n -= take;
	}
	return (ARCHIVE_OK);
}

/*
 * Open the next chunk of the inner (solid) stream into p->inner.
 * Returns 1 when a chunk is open, 0 at the end of the inner
 * stream, or ARCHIVE_FATAL.
 */
static int
inner_open_chunk(struct archive_read *a, struct archive_read_pna *p)
{
	unsigned char hdr[8];

	if (p->solid_buf_pos == p->solid_buf_len && solid_fill(a, p) == 0)
		return (0);
	if (solid_read_raw(a, p, hdr, sizeof(hdr)) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	p->inner.remaining = archive_be32dec(hdr);
	memcpy(p->inner.type, hdr + 4, 4);
	p->inner.crc = pna_crc32(0, hdr + 4, 4);
	p->inner.active = 1;
	if (p->inner.remaining == 0) {
		unsigned char crcbuf[4];
		p->inner.active = 0;
		if (solid_read_raw(a, p, crcbuf, sizeof(crcbuf))
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (archive_be32dec(crcbuf) != (uint32_t)p->inner.crc) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA chunk CRC mismatch (chunk %.4s)",
			    p->inner.type);
			return (ARCHIVE_FATAL);
		}
	}
	return (1);
}

static const unsigned char *
inner_slice(struct archive_read_pna *p, size_t *len)
{
	size_t avail;

	if (!p->inner.active || p->inner.remaining == 0)
		return (NULL);
	avail = p->solid_buf_len - p->solid_buf_pos;
	if (avail == 0)
		return (NULL);
	*len = avail < p->inner.remaining ? avail : p->inner.remaining;
	return (p->solid_buf + p->solid_buf_pos);
}

static int
inner_consume(struct archive_read *a, struct archive_read_pna *p, size_t n)
{
	p->inner.crc = pna_crc32(p->inner.crc,
	    p->solid_buf + p->solid_buf_pos, n);
	p->solid_buf_pos += n;
	p->inner.remaining -= (uint32_t)n;
	if (p->inner.remaining == 0) {
		unsigned char crcbuf[4];
		p->inner.active = 0;
		if (solid_read_raw(a, p, crcbuf, sizeof(crcbuf))
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (archive_be32dec(crcbuf) != (uint32_t)p->inner.crc) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA chunk CRC mismatch (chunk %.4s)",
			    p->inner.type);
			return (ARCHIVE_FATAL);
		}
	}
	return (ARCHIVE_OK);
}

static int
inner_drain(struct archive_read *a, struct archive_read_pna *p)
{
	while (p->inner.active && p->inner.remaining > 0) {
		const unsigned char *ptr;
		size_t len;

		if (p->solid_buf_pos == p->solid_buf_len &&
		    solid_fill(a, p) <= 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->inner.type);
			return (ARCHIVE_FATAL);
		}
		ptr = inner_slice(p, &len);
		if (ptr == NULL) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->inner.type);
			return (ARCHIVE_FATAL);
		}
		if (inner_consume(a, p, len) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	return (ARCHIVE_OK);
}

static int
inner_read_chunk_exact(struct archive_read *a, struct archive_read_pna *p,
    void *dst, size_t n)
{
	unsigned char *out = dst;

	if (n > p->inner.remaining) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA chunk %.4s is too short", p->inner.type);
		return (ARCHIVE_FATAL);
	}
	while (n > 0) {
		const unsigned char *ptr;
		size_t len, take;

		if (p->solid_buf_pos == p->solid_buf_len &&
		    solid_fill(a, p) <= 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->inner.type);
			return (ARCHIVE_FATAL);
		}
		ptr = inner_slice(p, &len);
		if (ptr == NULL) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA chunk %.4s", p->inner.type);
			return (ARCHIVE_FATAL);
		}
		take = len < n ? len : n;
		memcpy(out, ptr, take);
		if (inner_consume(a, p, take) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		out += take;
		n -= take;
	}
	return (ARCHIVE_OK);
}

/*
 * Source dispatchers: the current entry's chunks come either from
 * the physical stream (normal entries) or from the solid stream
 * (entries inside a solid block), selected by p->entry_in_solid.
 */
static int
src_open_chunk(struct archive_read *a, struct archive_read_pna *p)
{
	if (p->entry_in_solid)
		return (inner_open_chunk(a, p));
	return (outer_open_chunk(a, p));
}

static struct pna_chunk *
src_chunk(struct archive_read_pna *p)
{
	return (p->entry_in_solid ? &p->inner : &p->outer);
}

static const unsigned char *
src_slice(struct archive_read *a, struct archive_read_pna *p, size_t *len)
{
	if (p->entry_in_solid) {
		if (p->solid_buf_pos == p->solid_buf_len &&
		    p->inner.remaining > 0) {
			if (solid_fill(a, p) <= 0)
				return (NULL);
		}
		return (inner_slice(p, len));
	}
	return (phys_slice(a, p, len));
}

static int
src_consume(struct archive_read *a, struct archive_read_pna *p,
    const unsigned char *ptr, size_t n)
{
	if (p->entry_in_solid) {
		(void)ptr;
		return (inner_consume(a, p, n));
	}
	return (phys_consume(a, p, ptr, n));
}

static int
src_drain_chunk(struct archive_read *a, struct archive_read_pna *p)
{
	if (p->entry_in_solid)
		return (inner_drain(a, p));
	return (phys_drain(a, p));
}

static int
src_read_chunk_exact(struct archive_read *a, struct archive_read_pna *p,
    void *dst, size_t n)
{
	if (p->entry_in_solid)
		return (inner_read_chunk_exact(a, p, dst, n));
	return (phys_read_chunk_exact(a, p, dst, n));
}

/*
 * Produce decompressed bytes of the current entry into `out`.
 * Returns the number of bytes produced (0 once the entry's data
 * is exhausted, with p->entry_data_end set), or ARCHIVE_FATAL.
 */
static ssize_t
pna_produce(struct archive_read *a, struct archive_read_pna *p,
    unsigned char *out, size_t cap)
{
	size_t total = 0;

	if (!p->dec_started) {
		if (decompressor_init(a, &p->dec, p->entry_compression)
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		p->dec_started = 1;
	}
	while (total < cap && !p->entry_data_end) {
		struct pna_chunk *chunk = src_chunk(p);
		const unsigned char *ptr = NULL;
		size_t len = 0, in_used, out_made;
		int r;

		if (chunk->active && chunk->remaining > 0 &&
		    memcmp(chunk->type, "FDAT", 4) == 0) {
			ptr = src_slice(a, p, &len);
			if (ptr == NULL) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Truncated PNA entry data");
				return (ARCHIVE_FATAL);
			}
		}
		if (ptr == NULL) {
			/* Move to the next chunk of this entry. */
			r = src_open_chunk(a, p);
			if (r != 1) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Truncated PNA entry (no FEND chunk)");
				return (ARCHIVE_FATAL);
			}
			if (memcmp(chunk->type, "FDAT", 4) == 0)
				continue;
			if (memcmp(chunk->type, "FEND", 4) == 0) {
				if (p->entry_compression !=
				    PNA_COMPRESSION_NONE &&
				    !p->dec.stream_end) {
					archive_set_error(&a->archive,
					    ARCHIVE_ERRNO_MISC,
					    "Truncated compressed stream "
					    "in PNA entry");
					return (ARCHIVE_FATAL);
				}
				p->entry_data_end = 1;
				p->entry_open = 0;
				break;
			}
			if (memcmp(chunk->type, "PHSF", 4) == 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA encryption is not supported");
				return (ARCHIVE_FATAL);
			}
			if ((chunk->type[0] & 0x20) != 0) {
				/*
				 * Ancillary chunk after the data has
				 * started: the header has already been
				 * returned, so it can only be skipped.
				 */
				if (src_drain_chunk(a, p) != ARCHIVE_OK)
					return (ARCHIVE_FATAL);
				continue;
			}
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Unknown critical chunk %.4s in PNA entry",
			    chunk->type);
			return (ARCHIVE_FATAL);
		}
		r = decompressor_produce(a, &p->dec, ptr, len, &in_used,
		    out + total, cap - total, &out_made);
		if (src_consume(a, p, ptr, in_used) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (r != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		total += out_made;
		if (in_used == 0 && out_made == 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA decompression made no progress");
			return (ARCHIVE_FATAL);
		}
	}
	return ((ssize_t)total);
}

/* Timestamps collected while parsing an entry header. */
struct pna_times {
	int64_t		sec[3];		/* 0=birthtime, 1=mtime, 2=atime */
	long		nsec[3];
	unsigned int	has_sec;
	unsigned int	has_nsec;
};

static void
pna_apply_times(struct archive_entry *entry, struct pna_times *t)
{
	int i;

	for (i = 0; i < 3; i++) {
		long nsec = 0;
		if ((t->has_sec & (1U << i)) == 0)
			continue;
		if ((t->has_nsec & (1U << i)) != 0)
			nsec = t->nsec[i];
		switch (i) {
		case 0:
			/* PNA cTIM is the creation timestamp, which
			 * libarchive carries as birthtime, not ctime. */
			archive_entry_set_birthtime(entry, t->sec[0], nsec);
			break;
		case 1:
			archive_entry_set_mtime(entry, t->sec[1], nsec);
			break;
		case 2:
			archive_entry_set_atime(entry, t->sec[2], nsec);
			break;
		}
	}
	/* A TNS chunk without its TIM chunk is ignored (spec 4.5). */
}

static int
pna_set_name(struct archive_read *a, struct archive_entry *entry,
    const unsigned char *data, size_t len, int is_group)
{
	char *name = malloc(len + 1);

	if (name == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA name");
		return (ARCHIVE_FATAL);
	}
	memcpy(name, data, len);
	name[len] = '\0';
	if (is_group)
		archive_entry_set_gname(entry, name);
	else
		archive_entry_set_uname(entry, name);
	free(name);
	return (ARCHIVE_OK);
}

/*
 * Apply one ancillary chunk to the entry being built.  `data` is
 * the whole chunk data, already read and CRC-verified.
 */
static int
pna_apply_ancillary(struct archive_read *a, struct archive_entry *entry,
    struct pna_times *times, int64_t *size, int *has_size,
    const char *type, const unsigned char *data, uint32_t len)
{
	if (memcmp(type, "cTIM", 4) == 0 || memcmp(type, "mTIM", 4) == 0 ||
	    memcmp(type, "aTIM", 4) == 0) {
		int idx = type[0] == 'c' ? 0 : type[0] == 'm' ? 1 : 2;
		if (len != 8)
			goto bad_length;
		times->sec[idx] = (int64_t)archive_be64dec(data);
		times->has_sec |= 1U << idx;
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "cTNS", 4) == 0 || memcmp(type, "mTNS", 4) == 0 ||
	    memcmp(type, "aTNS", 4) == 0) {
		int idx = type[0] == 'c' ? 0 : type[0] == 'm' ? 1 : 2;
		uint32_t v;
		if (len != 4)
			goto bad_length;
		v = archive_be32dec(data);
		if (v >= 1000000000U) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA timestamp nanoseconds out of range");
			return (ARCHIVE_FATAL);
		}
		times->nsec[idx] = (long)v;
		times->has_nsec |= 1U << idx;
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fSIZ", 4) == 0) {
		/* A hint only; kept here solely as the entry size
		 * (there is no other size source in the format).
		 * Overlong encodings keep their low 8 bytes, per
		 * the format's treatment of this chunk. */
		uint64_t v = 0;
		uint32_t i, start = len > 8 ? len - 8 : 0;
		for (i = start; i < len; i++)
			v = (v << 8) | data[i];
		*size = (int64_t)v;
		*has_size = 1;
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fUId", 4) == 0) {
		if (len != 8)
			goto bad_length;
		archive_entry_set_uid(entry,
		    (uid_t)archive_be64dec(data));
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fGId", 4) == 0) {
		if (len != 8)
			goto bad_length;
		archive_entry_set_gid(entry,
		    (gid_t)archive_be64dec(data));
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fONm", 4) == 0 || memcmp(type, "fGNm", 4) == 0) {
		if (len < 1 || (uint32_t)data[0] != len - 1)
			goto bad_length;
		return (pna_set_name(a, entry, data + 1, len - 1,
		    type[1] == 'G'));
	}
	if (memcmp(type, "fOSi", 4) == 0 || memcmp(type, "fGSi", 4) == 0) {
		/* Windows SIDs have no archive_entry counterpart. */
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fMOd", 4) == 0) {
		if (len != 2)
			goto bad_length;
		/* Only permission bits are defined; the rest is
		 * reserved and must be ignored (spec 4.5). */
		archive_entry_set_perm(entry,
		    (mode_t)(archive_be16dec(data) & 07777));
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "fPRM", 4) == 0) {
		/* Deprecated combined permission chunk. */
		const unsigned char *p = data;
		const unsigned char *end = data + len;
		uint8_t unl, gnl;

		if (end - p < 9)
			goto bad_length;
		archive_entry_set_uid(entry,
		    (uid_t)archive_be64dec(p));
		p += 8;
		unl = *p++;
		if (end - p < unl + 9)
			goto bad_length;
		if (pna_set_name(a, entry, p, unl, 0) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		p += unl;
		archive_entry_set_gid(entry,
		    (gid_t)archive_be64dec(p));
		p += 8;
		gnl = *p++;
		if (end - p < gnl + 2)
			goto bad_length;
		if (pna_set_name(a, entry, p, gnl, 1) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		p += gnl;
		archive_entry_set_perm(entry,
		    (mode_t)(archive_be16dec(p) & 07777));
		return (ARCHIVE_OK);
	}
	if (memcmp(type, "xATR", 4) == 0) {
		uint32_t nl, vl;
		char *name;
		int r;

		if (len < 8)
			goto bad_length;
		nl = archive_be32dec(data);
		if (nl > len - 8)
			goto bad_length;
		vl = archive_be32dec(data + 4 + nl);
		if (vl != len - 8 - nl)
			goto bad_length;
		name = malloc(nl + 1);
		if (name == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA xattr name");
			return (ARCHIVE_FATAL);
		}
		memcpy(name, data + 4, nl);
		name[nl] = '\0';
		archive_entry_xattr_add_entry(entry, name,
		    data + 8 + nl, vl);
		r = ARCHIVE_OK;
		free(name);
		return (r);
	}
	/* fLTP: the link target type; FHED's entry kind, which the
	 * reader already used, is authoritative.  Anything else is
	 * an unknown ancillary chunk and is ignored by definition. */
	return (ARCHIVE_OK);

bad_length:
	archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
	    "Invalid size for PNA chunk %.4s", type);
	return (ARCHIVE_FATAL);
}

/*
 * Parse one entry.  On entry, the FHED chunk is open in the
 * current source; on success the entry header is complete and,
 * for entries with data, the first FDAT chunk has been opened
 * (and verified empty or not) by pna_produce on demand.
 */
static int
pna_parse_entry(struct archive_read *a, struct archive_read_pna *p,
    struct archive_entry *entry)
{
	struct pna_chunk *chunk = src_chunk(p);
	struct pna_times times;
	unsigned char *buf;
	uint32_t len;
	int kind, compression, r;
	int64_t size = 0;
	int has_size = 0;

	memset(&times, 0, sizeof(times));
	if (p->dec_started) {
		decompressor_free(&p->dec);
		p->dec_started = 0;
	}
	p->entry_data_end = 0;
	p->data_offset = 0;
	p->out_len = p->out_pos = 0;

	len = chunk->remaining;
	if (len < 6 || len > PNA_MAX_BUFFERED_CHUNK) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Invalid FHED chunk size in PNA archive");
		return (ARCHIVE_FATAL);
	}
	buf = malloc(len);
	if (buf == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA header");
		return (ARCHIVE_FATAL);
	}
	r = src_read_chunk_exact(a, p, buf, len);
	if (r != ARCHIVE_OK) {
		free(buf);
		return (ARCHIVE_FATAL);
	}
	if (buf[0] != 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unsupported PNA entry header version %d", buf[0]);
		free(buf);
		return (ARCHIVE_FATAL);
	}
	kind = buf[2];
	compression = buf[3];
	if (buf[4] != 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA encryption is not supported");
		free(buf);
		return (ARCHIVE_FATAL);
	}
	/* buf[5] (cipher mode) is meaningless without encryption. */
	if (kind > 3) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unsupported PNA entry kind %d", kind);
		free(buf);
		return (ARCHIVE_FATAL);
	}
	if (compression != PNA_COMPRESSION_NONE &&
	    compression != PNA_COMPRESSION_DEFLATE &&
	    compression != PNA_COMPRESSION_ZSTD &&
	    compression != PNA_COMPRESSION_XZ) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unsupported PNA compression method %d", compression);
		free(buf);
		return (ARCHIVE_FATAL);
	}
	{
		char *path = malloc(len - 6 + 1);
		if (path == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA pathname");
			free(buf);
			return (ARCHIVE_FATAL);
		}
		memcpy(path, buf + 6, len - 6);
		path[len - 6] = '\0';
		archive_entry_set_pathname(entry, path);
		free(path);
	}
	free(buf);
	p->entry_kind = kind;
	p->entry_compression = compression;
	switch (kind) {
	case PNA_KIND_DIRECTORY:
		archive_entry_set_filetype(entry, AE_IFDIR);
		break;
	case PNA_KIND_SYMLINK:
		archive_entry_set_filetype(entry, AE_IFLNK);
		break;
	default:
		archive_entry_set_filetype(entry, AE_IFREG);
		break;
	}

	for (;;) {
		char type[4];

		r = src_open_chunk(a, p);
		if (r != 1) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Truncated PNA entry (no FEND chunk)");
			return (ARCHIVE_FATAL);
		}
		memcpy(type, chunk->type, 4);
		if (memcmp(type, "FDAT", 4) == 0) {
			if (kind == PNA_KIND_SYMLINK ||
			    kind == PNA_KIND_HARDLINK) {
				/*
				 * A link's data is its target string;
				 * consume it now so it can be reported
				 * through archive_entry.
				 */
				unsigned char tmp[4096];
				unsigned char *target = NULL;
				size_t tlen = 0, tcap = 0;
				ssize_t n;

				p->entry_open = 1;
				while (!p->entry_data_end) {
					n = pna_produce(a, p, tmp, sizeof(tmp));
					if (n < 0) {
						free(target);
						return (ARCHIVE_FATAL);
					}
					if (n == 0)
						break;
					if (tlen + (size_t)n >
					    PNA_MAX_LINK_TARGET) {
						archive_set_error(&a->archive,
						    ARCHIVE_ERRNO_MISC,
						    "PNA link target is "
						    "too large");
						free(target);
						return (ARCHIVE_FATAL);
					}
					if (tlen + (size_t)n > tcap) {
						size_t ncap = tcap == 0
						    ? 4096 : tcap * 2;
						unsigned char *nt = realloc(
						    target, ncap);
						if (nt == NULL) {
							archive_set_error(
							    &a->archive,
							    ENOMEM,
							    "Can't allocate "
							    "PNA link target");
							free(target);
							return (
							    ARCHIVE_FATAL);
						}
						target = nt;
						tcap = ncap;
					}
					memcpy(target + tlen, tmp, (size_t)n);
					tlen += (size_t)n;
				}
				{
					char *tstr = malloc(tlen + 1);
					if (tstr == NULL) {
						archive_set_error(&a->archive,
						    ENOMEM, "Can't allocate "
						    "PNA link target");
						free(target);
						return (ARCHIVE_FATAL);
					}
					if (tlen > 0)
						memcpy(tstr, target, tlen);
					tstr[tlen] = '\0';
					if (kind == PNA_KIND_SYMLINK)
						archive_entry_set_symlink(
						    entry, tstr);
					else
						archive_entry_set_hardlink(
						    entry, tstr);
					free(tstr);
				}
				free(target);
				pna_apply_times(entry, &times);
				p->entry_open = 0;
				return (ARCHIVE_OK);
			}
			/* Regular data: the header is complete. */
			pna_apply_times(entry, &times);
			if (has_size && kind == PNA_KIND_FILE && size >= 0)
				archive_entry_set_size(entry, size);
			p->entry_open = 1;
			return (ARCHIVE_OK);
		}
		if (memcmp(type, "FEND", 4) == 0) {
			pna_apply_times(entry, &times);
			if (has_size && kind == PNA_KIND_FILE && size >= 0)
				archive_entry_set_size(entry, size);
			p->entry_data_end = 1;
			return (ARCHIVE_OK);
		}
		if (memcmp(type, "PHSF", 4) == 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA encryption is not supported");
			return (ARCHIVE_FATAL);
		}
		if ((type[0] & 0x20) != 0) {
			uint32_t clen = chunk->remaining;
			unsigned char *cbuf = NULL;

			if (clen > PNA_MAX_BUFFERED_CHUNK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA ancillary chunk %.4s is too large",
				    type);
				return (ARCHIVE_FATAL);
			}
			if (clen > 0) {
				cbuf = malloc(clen);
				if (cbuf == NULL) {
					archive_set_error(&a->archive,
					    ENOMEM, "Can't allocate PNA "
					    "chunk");
					return (ARCHIVE_FATAL);
				}
				r = src_read_chunk_exact(a, p, cbuf, clen);
				if (r != ARCHIVE_OK) {
					free(cbuf);
					return (ARCHIVE_FATAL);
				}
			}
			r = pna_apply_ancillary(a, entry, &times,
			    &size, &has_size, type, cbuf, clen);
			free(cbuf);
			if (r != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			continue;
		}
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unknown critical chunk %.4s in PNA entry", type);
		return (ARCHIVE_FATAL);
	}
}

static int
pna_read_header(struct archive_read *a, struct archive_entry *entry)
{
	struct archive_read_pna *p = a->format->data;
	int r;

	if (!p->framing_done) {
		unsigned char sig[8];
		unsigned char ahed[8];

		if (phys_read_exact(a, sig, sizeof(sig)) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (memcmp(sig, pna_signature, sizeof(pna_signature)) != 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Not a PNA archive");
			return (ARCHIVE_FATAL);
		}
		if (phys_open_raw(a, p) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (memcmp(p->outer.type, "AHED", 4) != 0 ||
		    p->outer.remaining != 8) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "PNA archive does not start with an AHED chunk");
			return (ARCHIVE_FATAL);
		}
		if (phys_read_chunk_exact(a, p, ahed, 8) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (ahed[0] != 0) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Unsupported PNA archive header version %d",
			    ahed[0]);
			return (ARCHIVE_FATAL);
		}
		p->archive_number = archive_be32dec(ahed + 4);
		p->framing_done = 1;
	}
	if (p->entry_open) {
		r = pna_read_data_skip(a);
		if (r != ARCHIVE_OK)
			return (r);
	}
	a->archive.archive_format = ARCHIVE_FORMAT_PNA;
	for (;;) {
		if (p->in_solid) {
			p->entry_in_solid = 1;
			r = inner_open_chunk(a, p);
			if (r == ARCHIVE_FATAL)
				return (ARCHIVE_FATAL);
			if (r == 0) {
				/* The solid stream is exhausted. */
				p->in_solid = 0;
				p->entry_in_solid = 0;
				if (!p->solid_send_consumed) {
					r = outer_open_chunk(a, p);
					if (r != 1 ||
					    memcmp(p->outer.type, "SEND",
					    4) != 0) {
						archive_set_error(&a->archive,
						    ARCHIVE_ERRNO_MISC,
						    "Expected SEND chunk "
						    "after solid block");
						return (ARCHIVE_FATAL);
					}
					if (phys_drain(a, p) != ARCHIVE_OK)
						return (ARCHIVE_FATAL);
					p->solid_send_consumed = 1;
				}
				if (p->solid_dec_started) {
					decompressor_free(&p->solid_dec);
					p->solid_dec_started = 0;
				}
				p->solid_input_done = 0;
				p->solid_buf_len = p->solid_buf_pos = 0;
				continue;
			}
			if (memcmp(p->inner.type, "FHED", 4) == 0)
				return (pna_parse_entry(a, p, entry));
			if ((p->inner.type[0] & 0x20) != 0) {
				if (inner_drain(a, p) != ARCHIVE_OK)
					return (ARCHIVE_FATAL);
				continue;
			}
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Unexpected chunk %.4s in solid PNA stream",
			    p->inner.type);
			return (ARCHIVE_FATAL);
		}
		p->entry_in_solid = 0;
		r = outer_open_chunk(a, p);
		if (r == 0)
			return (ARCHIVE_EOF);
		if (r != 1)
			return (ARCHIVE_FATAL);
		if (memcmp(p->outer.type, "FHED", 4) == 0)
			return (pna_parse_entry(a, p, entry));
		if (memcmp(p->outer.type, "SHED", 4) == 0) {
			unsigned char shed[5];
			int compression;

			if (p->outer.remaining != 5) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Invalid SHED chunk size in PNA archive");
				return (ARCHIVE_FATAL);
			}
			if (phys_read_chunk_exact(a, p, shed, 5)
			    != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			if (shed[0] != 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Unsupported PNA solid header version %d",
				    shed[0]);
				return (ARCHIVE_FATAL);
			}
			compression = shed[2];
			if (shed[3] != 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA encryption is not supported");
				return (ARCHIVE_FATAL);
			}
			if (compression != PNA_COMPRESSION_NONE &&
			    compression != PNA_COMPRESSION_DEFLATE &&
			    compression != PNA_COMPRESSION_ZSTD &&
			    compression != PNA_COMPRESSION_XZ) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Unsupported PNA compression method %d",
				    compression);
				return (ARCHIVE_FATAL);
			}
			if (p->solid_dec_started) {
				decompressor_free(&p->solid_dec);
				p->solid_dec_started = 0;
			}
			if (decompressor_init(a, &p->solid_dec, compression)
			    != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			p->solid_dec_started = 1;
			p->solid_input_done = 0;
			p->solid_send_consumed = 0;
			p->solid_buf_len = p->solid_buf_pos = 0;
			p->in_solid = 1;
			continue;
		}
		if ((p->outer.type[0] & 0x20) != 0) {
			if (phys_drain(a, p) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			continue;
		}
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Unexpected chunk %.4s in PNA archive", p->outer.type);
		return (ARCHIVE_FATAL);
	}
}

static int
pna_read_data(struct archive_read *a, const void **buff, size_t *size,
    int64_t *offset)
{
	struct archive_read_pna *p = a->format->data;
	ssize_t made;

	if (!p->entry_open || p->entry_data_end) {
		*buff = NULL;
		*size = 0;
		*offset = p->data_offset;
		return (ARCHIVE_EOF);
	}
	if (p->out_buf == NULL) {
		p->out_buf = malloc(65536);
		if (p->out_buf == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA data buffer");
			return (ARCHIVE_FATAL);
		}
	}
	made = pna_produce(a, p, p->out_buf, 65536);
	if (made < 0)
		return (ARCHIVE_FATAL);
	if (made == 0) {
		*buff = NULL;
		*size = 0;
		*offset = p->data_offset;
		return (ARCHIVE_EOF);
	}
	*buff = p->out_buf;
	*size = (size_t)made;
	*offset = p->data_offset;
	p->data_offset += made;
	return (ARCHIVE_OK);
}

static int
pna_read_data_skip(struct archive_read *a)
{
	struct archive_read_pna *p = a->format->data;
	unsigned char scratch[8192];

	while (p->entry_open && !p->entry_data_end) {
		ssize_t n = pna_produce(a, p, scratch, sizeof(scratch));
		if (n < 0)
			return (ARCHIVE_FATAL);
		if (n == 0)
			break;
	}
	return (ARCHIVE_OK);
}
