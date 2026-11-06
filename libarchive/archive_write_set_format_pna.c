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
 * Writer for the Portable Network Archive (PNA) format.
 *
 * The output layout mirrors the reference implementation: a
 * signature and AHED chunk, then for each entry an FHED chunk,
 * ancillary metadata chunks (fSIZ, cTIM/mTIM/aTIM with their TNS
 * companions, fUId/fGId, fONm/fGNm, fMOd, xATR), the data as FDAT
 * chunks of at most 64 KiB of (possibly compressed) stream, and a
 * closing FEND; the archive ends with AEND.  With the "solid"
 * option the whole entry stream is buffered, compressed as a
 * unit, and emitted between SHED and SEND as SDAT chunks.
 *
 * PNA encryption is never emitted.  Split output is not
 * supported: a libarchive writer drives a single output stream,
 * so multi-part files cannot be expressed.
 *
 * Format options:
 *   compression = store | deflate | zstd | xz   (aliases: none,
 *                 zlib, lzma)
 *   solid       = true | false (a valueless "solid" means true)
 */

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
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
#include "archive_write_private.h"
#include "archive_write_set_format_private.h"
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

#define PNA_COMPRESSION_NONE		0
#define PNA_COMPRESSION_DEFLATE		1
#define PNA_COMPRESSION_ZSTD		2
#define PNA_COMPRESSION_XZ		4

#define PNA_KIND_FILE			0
#define PNA_KIND_DIRECTORY		1
#define PNA_KIND_SYMLINK		2
#define PNA_KIND_HARDLINK		3

/* Data chunks carry at most this many bytes of the data stream. */
#define PNA_CHUNK_DATA_MAX		65536

static const unsigned char pna_signature[8] =
    { 0x89, 0x50, 0x4e, 0x41, 0x0d, 0x0a, 0x1a, 0x0a };

struct pna_compressor {
	int		 method;
	int		 initialized;
	int		 stream_end;
#if defined(HAVE_ZLIB_H)
	z_stream	 zstream;
#endif
#if defined(HAVE_ZSTD_H)
	ZSTD_CStream	*zstdstream;
#endif
#if defined(HAVE_PNA_LZMA)
	lzma_stream	 lzmastream;
#endif
};

struct archive_write_pna {
	int		 compression;
	int		 solid;
	int		 framing_written;
	/* Per-entry compression. */
	struct pna_compressor comp;
	int		 comp_started;
	int		 entry_open;
	int		 entry_kind;
	int		 entry_data_fed;
	/* Copy of the current link entry's target, for finish. */
	char		*entry_linktarget;
	/* Staging for compressed output waiting to fill a chunk. */
	unsigned char	*stage;
	size_t		 stage_len;
	/* While closing a solid archive, staged output goes to
	 * SDAT chunks of the physical stream instead of FDAT
	 * chunks of the entry stream. */
	int		 flushing_solid;
	/* Buffered entry stream for solid archives. */
	unsigned char	*solid_buf;
	size_t		 solid_len;
	size_t		 solid_cap;
};

static int archive_write_pna_options(struct archive_write *,
    const char *, const char *);
static int archive_write_pna_header(struct archive_write *,
    struct archive_entry *);
static ssize_t archive_write_pna_data(struct archive_write *,
    const void *, size_t);
static int archive_write_pna_finish_entry(struct archive_write *);
static int archive_write_pna_close(struct archive_write *);
static int archive_write_pna_free(struct archive_write *);

static int compressor_init(struct archive_write *,
    struct pna_compressor *, int);
static void compressor_free(struct pna_compressor *);
static int emit_bytes(struct archive_write *, const void *, size_t);
static int emit_chunk(struct archive_write *, struct archive_write_pna *,
    const char *, const void *, size_t);
static int stream_chunk(struct archive_write *, struct archive_write_pna *,
    const char *, const void *, size_t);
static int flush_stage(struct archive_write *, struct archive_write_pna *);
static int feed_data(struct archive_write *, struct archive_write_pna *,
    const void *, size_t, int);

int
archive_write_set_format_pna(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;
	struct archive_write_pna *w;

	archive_check_magic(_a, ARCHIVE_WRITE_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_write_set_format_pna");

	/* If another format was already registered, unregister it. */
	if (a->format_free != NULL)
		(a->format_free)(a);

	w = calloc(1, sizeof(*w));
	if (w == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA data");
		return (ARCHIVE_FATAL);
	}
#if defined(HAVE_PNA_LZMA)
	memset(&w->comp.lzmastream, 0, sizeof(w->comp.lzmastream));
#endif
#if defined(HAVE_ZSTD_H)
	w->compression = PNA_COMPRESSION_ZSTD;
#elif defined(HAVE_ZLIB_H)
	w->compression = PNA_COMPRESSION_DEFLATE;
#else
	w->compression = PNA_COMPRESSION_NONE;
#endif
	w->stage = malloc(PNA_CHUNK_DATA_MAX);
	if (w->stage == NULL) {
		free(w);
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA data");
		return (ARCHIVE_FATAL);
	}

	a->format_data = w;
	a->format_name = "pna";
	a->format_options = archive_write_pna_options;
	a->format_write_header = archive_write_pna_header;
	a->format_write_data = archive_write_pna_data;
	a->format_finish_entry = archive_write_pna_finish_entry;
	a->format_close = archive_write_pna_close;
	a->format_free = archive_write_pna_free;
	a->archive.archive_format = ARCHIVE_FORMAT_PNA;
	a->archive.archive_format_name = "Portable Network Archive";
	return (ARCHIVE_OK);
}

static int
archive_write_pna_options(struct archive_write *a, const char *key,
    const char *val)
{
	struct archive_write_pna *w = a->format_data;

	if (strcmp(key, "compression") == 0) {
		if (val == NULL)
			return (ARCHIVE_FAILED);
		if (strcmp(val, "store") == 0 || strcmp(val, "none") == 0)
			w->compression = PNA_COMPRESSION_NONE;
		else if (strcmp(val, "deflate") == 0 ||
		    strcmp(val, "zlib") == 0) {
#if !defined(HAVE_ZLIB_H)
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "deflate compression not supported by this "
			    "version of libarchive");
			return (ARCHIVE_FATAL);
#else
			w->compression = PNA_COMPRESSION_DEFLATE;
#endif
		} else if (strcmp(val, "zstd") == 0) {
#if !defined(HAVE_ZSTD_H)
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "zstd compression not supported by this "
			    "version of libarchive");
			return (ARCHIVE_FATAL);
#else
			w->compression = PNA_COMPRESSION_ZSTD;
#endif
		} else if (strcmp(val, "xz") == 0 ||
		    strcmp(val, "lzma") == 0) {
#if !defined(HAVE_PNA_LZMA)
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "xz compression not supported by this "
			    "version of libarchive");
			return (ARCHIVE_FATAL);
#else
			w->compression = PNA_COMPRESSION_XZ;
#endif
		} else {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Unsupported PNA compression '%s'", val);
			return (ARCHIVE_FAILED);
		}
		return (ARCHIVE_OK);
	}
	if (strcmp(key, "solid") == 0) {
		if (val == NULL || strcmp(val, "true") == 0 ||
		    strcmp(val, "1") == 0)
			w->solid = 1;
		else if (strcmp(val, "false") == 0 || strcmp(val, "0") == 0)
			w->solid = 0;
		else
			return (ARCHIVE_FAILED);
		return (ARCHIVE_OK);
	}
	return (ARCHIVE_WARN);
}

static int
compressor_init(struct archive_write *a, struct pna_compressor *c,
    int method)
{
	c->method = method;
	c->stream_end = 0;
	c->initialized = 1;
	switch (method) {
	case PNA_COMPRESSION_NONE:
		return (ARCHIVE_OK);
	case PNA_COMPRESSION_DEFLATE:
#if defined(HAVE_ZLIB_H)
		memset(&c->zstream, 0, sizeof(c->zstream));
		if (deflateInit(&c->zstream, Z_DEFAULT_COMPRESSION) != Z_OK) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Failed to initialize zlib deflater");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		(void)a;
		return (ARCHIVE_FATAL);
#endif
	case PNA_COMPRESSION_ZSTD:
#if defined(HAVE_ZSTD_H)
		c->zstdstream = ZSTD_createCStream();
		if (c->zstdstream == NULL ||
		    ZSTD_isError(ZSTD_initCStream(c->zstdstream, 0))) {
			archive_set_error(&a->archive, ENOMEM,
			    "Failed to initialize zstd compressor");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		(void)a;
		return (ARCHIVE_FATAL);
#endif
	case PNA_COMPRESSION_XZ:
#if defined(HAVE_PNA_LZMA)
		if (lzma_easy_encoder(&c->lzmastream, LZMA_PRESET_DEFAULT,
		    LZMA_CHECK_CRC64) != LZMA_OK) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Failed to initialize lzma encoder");
			return (ARCHIVE_FATAL);
		}
		return (ARCHIVE_OK);
#else
		(void)a;
		return (ARCHIVE_FATAL);
#endif
	default:
		return (ARCHIVE_FATAL);
	}
}

static void
compressor_free(struct pna_compressor *c)
{
	if (!c->initialized)
		return;
	switch (c->method) {
	case PNA_COMPRESSION_DEFLATE:
#if defined(HAVE_ZLIB_H)
		deflateEnd(&c->zstream);
#endif
		break;
	case PNA_COMPRESSION_ZSTD:
#if defined(HAVE_ZSTD_H)
		if (c->zstdstream != NULL)
			ZSTD_freeCStream(c->zstdstream);
		c->zstdstream = NULL;
#endif
		break;
	case PNA_COMPRESSION_XZ:
#if defined(HAVE_PNA_LZMA)
		lzma_end(&c->lzmastream);
#endif
		break;
	default:
		break;
	}
	c->initialized = 0;
}

/* Write raw bytes to the archive client. */
static int
emit_bytes(struct archive_write *a, const void *buf, size_t len)
{
	if (len == 0)
		return (ARCHIVE_OK);
	if (__archive_write_output(a, buf, len) < 0)
		return (ARCHIVE_FATAL);
	return (ARCHIVE_OK);
}

/* Write one framed chunk to the physical output. */
static int
emit_chunk(struct archive_write *a, struct archive_write_pna *w,
    const char *type, const void *data, size_t len)
{
	unsigned char hdr[8];
	unsigned char crcbuf[4];
	unsigned long crc;

	(void)w;
	if (len > UINT32_MAX) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA chunk is too large");
		return (ARCHIVE_FATAL);
	}
	archive_be32enc(hdr, (uint32_t)len);
	memcpy(hdr + 4, type, 4);
	crc = pna_crc32(pna_crc32(0, hdr + 4, 4), data, len);
	archive_be32enc(crcbuf, (uint32_t)crc);
	if (emit_bytes(a, hdr, sizeof(hdr)) != ARCHIVE_OK ||
	    emit_bytes(a, data, len) != ARCHIVE_OK ||
	    emit_bytes(a, crcbuf, sizeof(crcbuf)) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	return (ARCHIVE_OK);
}

/*
 * Write one framed chunk to the entry stream: the physical
 * output for a plain archive, the buffered solid stream for a
 * solid one.
 */
static int
stream_chunk(struct archive_write *a, struct archive_write_pna *w,
    const char *type, const void *data, size_t len)
{
	unsigned char hdr[8];
	unsigned char crcbuf[4];
	unsigned long crc;
	size_t need;

	if (!w->solid)
		return (emit_chunk(a, w, type, data, len));
	if (len > UINT32_MAX) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA chunk is too large");
		return (ARCHIVE_FATAL);
	}
	archive_be32enc(hdr, (uint32_t)len);
	memcpy(hdr + 4, type, 4);
	crc = pna_crc32(pna_crc32(0, hdr + 4, 4), data, len);
	archive_be32enc(crcbuf, (uint32_t)crc);
	need = w->solid_len + 8 + len + 4;
	if (need > w->solid_cap) {
		size_t ncap = w->solid_cap == 0 ? 65536 : w->solid_cap;
		unsigned char *nbuf;
		while (ncap < need)
			ncap *= 2;
		nbuf = realloc(w->solid_buf, ncap);
		if (nbuf == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA solid buffer");
			return (ARCHIVE_FATAL);
		}
		w->solid_buf = nbuf;
		w->solid_cap = ncap;
	}
	memcpy(w->solid_buf + w->solid_len, hdr, 8);
	w->solid_len += 8;
	if (len > 0) {
		memcpy(w->solid_buf + w->solid_len, data, len);
		w->solid_len += len;
	}
	memcpy(w->solid_buf + w->solid_len, crcbuf, 4);
	w->solid_len += 4;
	return (ARCHIVE_OK);
}

/* Emit the staged compressed bytes as one data chunk. */
static int
flush_stage(struct archive_write *a, struct archive_write_pna *w)
{
	int r;

	if (w->stage_len == 0)
		return (ARCHIVE_OK);
	if (w->flushing_solid)
		r = emit_chunk(a, w, "SDAT", w->stage, w->stage_len);
	else
		r = stream_chunk(a, w, "FDAT", w->stage, w->stage_len);
	w->stage_len = 0;
	return (r);
}

/*
 * Feed uncompressed data through the entry compressor, emitting
 * data chunks as the staging buffer fills.  With finish=1 the
 * compression stream is ended and any staged remainder emitted.
 */
static int
feed_data(struct archive_write *a, struct archive_write_pna *w,
    const void *buf, size_t len, int finish)
{
	struct pna_compressor *c = &w->comp;
	const unsigned char *in = buf;
	size_t in_left = len;

	if (c->method == PNA_COMPRESSION_NONE) {
		while (in_left > 0) {
			size_t room = PNA_CHUNK_DATA_MAX - w->stage_len;
			size_t take = in_left < room ? in_left : room;
			memcpy(w->stage + w->stage_len, in, take);
			w->stage_len += take;
			in += take;
			in_left -= take;
			if (w->stage_len == PNA_CHUNK_DATA_MAX &&
			    flush_stage(a, w) != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
		}
		if (finish)
			return (flush_stage(a, w));
		return (ARCHIVE_OK);
	}
	for (;;) {
		size_t in_used, out_made;
		int r = ARCHIVE_OK;

		switch (c->method) {
		case PNA_COMPRESSION_DEFLATE: {
#if defined(HAVE_ZLIB_H)
			int zret;
			/* zlib counts in uInt; feed at most 1 GiB
			 * per call so the count cannot truncate
			 * (same bound as the CRC helper). */
			size_t in_slice = in_left > 0x40000000U
			    ? 0x40000000U : in_left;
			c->zstream.next_in = (Bytef *)(uintptr_t)in;
			c->zstream.avail_in = (uInt)in_slice;
			c->zstream.next_out = w->stage + w->stage_len;
			c->zstream.avail_out =
			    (uInt)(PNA_CHUNK_DATA_MAX - w->stage_len);
			zret = deflate(&c->zstream,
			    finish ? Z_FINISH : Z_NO_FLUSH);
			in_used = in_slice - c->zstream.avail_in;
			out_made = PNA_CHUNK_DATA_MAX - w->stage_len -
			    c->zstream.avail_out;
			if (zret == Z_STREAM_END)
				c->stream_end = 1;
			else if (zret != Z_OK &&
			    !(finish && zret == Z_BUF_ERROR)) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Deflate compression failed");
				r = ARCHIVE_FATAL;
			}
#else
			in_used = 0;
			out_made = 0;
			r = ARCHIVE_FATAL;
#endif
			break;
		}
		case PNA_COMPRESSION_ZSTD: {
#if defined(HAVE_ZSTD_H)
			ZSTD_inBuffer inbuf = { in, in_left, 0 };
			ZSTD_outBuffer outbuf = {
				w->stage + w->stage_len,
				PNA_CHUNK_DATA_MAX - w->stage_len, 0 };
			size_t zret = ZSTD_compressStream2(c->zstdstream,
			    &outbuf, &inbuf,
			    finish ? ZSTD_e_end : ZSTD_e_continue);
			in_used = inbuf.pos;
			out_made = outbuf.pos;
			if (ZSTD_isError(zret)) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Zstd compression failed: %s",
				    ZSTD_getErrorName(zret));
				r = ARCHIVE_FATAL;
			} else if (finish && zret == 0)
				c->stream_end = 1;
#else
			in_used = 0;
			out_made = 0;
			r = ARCHIVE_FATAL;
#endif
			break;
		}
		case PNA_COMPRESSION_XZ: {
#if defined(HAVE_PNA_LZMA)
			lzma_ret lret;
			c->lzmastream.next_in = in;
			c->lzmastream.avail_in = in_left;
			c->lzmastream.next_out = w->stage + w->stage_len;
			c->lzmastream.avail_out =
			    PNA_CHUNK_DATA_MAX - w->stage_len;
			lret = lzma_code(&c->lzmastream,
			    finish ? LZMA_FINISH : LZMA_RUN);
			in_used = in_left - c->lzmastream.avail_in;
			out_made = PNA_CHUNK_DATA_MAX - w->stage_len -
			    c->lzmastream.avail_out;
			if (lret == LZMA_STREAM_END)
				c->stream_end = 1;
			else if (lret != LZMA_OK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "XZ compression failed");
				r = ARCHIVE_FATAL;
			}
#else
			in_used = 0;
			out_made = 0;
			r = ARCHIVE_FATAL;
#endif
			break;
		}
		default:
			in_used = 0;
			out_made = 0;
			r = ARCHIVE_FATAL;
			break;
		}
		if (r != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		in += in_used;
		in_left -= in_used;
		w->stage_len += out_made;
		if (w->stage_len == PNA_CHUNK_DATA_MAX &&
		    flush_stage(a, w) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (c->stream_end)
			break;
		if (!finish && in_left == 0)
			break;
		if (finish && in_left == 0 && out_made == 0) {
			/*
			 * A finishing call that neither consumed nor
			 * produced anything and did not end the
			 * stream should not be retried forever; the
			 * libraries end the stream on the call that
			 * consumes the last input byte, so treat
			 * this as an error.
			 */
			if (in_used == 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "PNA compression made no progress");
				return (ARCHIVE_FATAL);
			}
		}
	}
	if (finish)
		return (flush_stage(a, w));
	return (ARCHIVE_OK);
}

static int
write_framing(struct archive_write *a, struct archive_write_pna *w)
{
	static const unsigned char ahed[8] = { 0 };

	if (w->framing_written)
		return (ARCHIVE_OK);
	if (emit_bytes(a, pna_signature, sizeof(pna_signature))
	    != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (emit_chunk(a, w, "AHED", ahed, sizeof(ahed)) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	w->framing_written = 1;
	return (ARCHIVE_OK);
}

static int
write_time_chunks(struct archive_write *a, struct archive_write_pna *w,
    struct archive_entry *entry)
{
	static const char *const tim_names[3] = { "cTIM", "mTIM", "aTIM" };
	static const char *const tns_names[3] = { "cTNS", "mTNS", "aTNS" };
	int i;

	for (i = 0; i < 3; i++) {
		time_t sec;
		long nsec;
		unsigned char tb[8];
		int is_set;

		switch (i) {
		case 0:
			/* PNA cTIM is the creation timestamp:
			 * the entry's birthtime, not its ctime. */
			is_set = archive_entry_birthtime_is_set(entry);
			sec = archive_entry_birthtime(entry);
			nsec = archive_entry_birthtime_nsec(entry);
			break;
		case 1:
			is_set = archive_entry_mtime_is_set(entry);
			sec = archive_entry_mtime(entry);
			nsec = archive_entry_mtime_nsec(entry);
			break;
		default:
			is_set = archive_entry_atime_is_set(entry);
			sec = archive_entry_atime(entry);
			nsec = archive_entry_atime_nsec(entry);
			break;
		}
		if (!is_set)
			continue;
		archive_be64enc(tb, (uint64_t)(int64_t)sec);
		if (stream_chunk(a, w, tim_names[i], tb, 8) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (nsec != 0) {
			unsigned char nb[4];
			archive_be32enc(nb, (uint32_t)nsec);
			if (stream_chunk(a, w, tns_names[i], nb, 4)
			    != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
		}
	}
	return (ARCHIVE_OK);
}

static int
write_name_chunk(struct archive_write *a, struct archive_write_pna *w,
    const char *type, const char *name)
{
	unsigned char buf[256];
	size_t len;

	if (name == NULL)
		return (ARCHIVE_OK);
	len = strlen(name);
	if (len > 255)
		return (ARCHIVE_OK);	/* Not representable; omit. */
	buf[0] = (unsigned char)len;
	memcpy(buf + 1, name, len);
	return (stream_chunk(a, w, type, buf, len + 1));
}

static int
archive_write_pna_header(struct archive_write *a,
    struct archive_entry *entry)
{
	struct archive_write_pna *w = a->format_data;
	const char *pathname;
	const char *linktarget = NULL;
	unsigned char *fhed;
	size_t plen;
	int kind;

	if (write_framing(a, w) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (w->comp_started) {
		compressor_free(&w->comp);
		w->comp_started = 0;
	}
	if (archive_entry_hardlink(entry) != NULL) {
		kind = PNA_KIND_HARDLINK;
		linktarget = archive_entry_hardlink(entry);
	} else if (archive_entry_filetype(entry) == AE_IFLNK) {
		kind = PNA_KIND_SYMLINK;
		linktarget = archive_entry_symlink(entry);
	} else if (archive_entry_filetype(entry) == AE_IFDIR) {
		kind = PNA_KIND_DIRECTORY;
	} else if (archive_entry_filetype(entry) == AE_IFREG) {
		kind = PNA_KIND_FILE;
	} else {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA cannot represent this file type");
		return (ARCHIVE_FAILED);
	}
	pathname = archive_entry_pathname(entry);
	if (pathname == NULL) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA entry has no pathname");
		return (ARCHIVE_FAILED);
	}
	plen = strlen(pathname);
	fhed = malloc(6 + plen);
	if (fhed == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate PNA header");
		return (ARCHIVE_FATAL);
	}
	fhed[0] = 0;	/* header major version */
	fhed[1] = 0;	/* header minor version */
	fhed[2] = (unsigned char)kind;
	/* In solid mode the entry stream itself is uncompressed;
	 * compression applies to the solid stream as a whole. */
	fhed[3] = (unsigned char)(w->solid ? PNA_COMPRESSION_NONE
	    : w->compression);
	fhed[4] = 0;	/* no encryption */
	fhed[5] = 0;	/* cipher mode: meaningless unencrypted */
	memcpy(fhed + 6, pathname, plen);
	if (stream_chunk(a, w, "FHED", fhed, 6 + plen) != ARCHIVE_OK) {
		free(fhed);
		return (ARCHIVE_FATAL);
	}
	free(fhed);

	/* Ancillary metadata, in a fixed order. */
	if (kind == PNA_KIND_FILE && archive_entry_size_is_set(entry) &&
	    archive_entry_size(entry) >= 0) {
		uint64_t v = (uint64_t)archive_entry_size(entry);
		unsigned char sb[8];
		int i = 8;

		/* Minimal big-endian; zero is the empty encoding. */
		while (v > 0) {
			sb[--i] = (unsigned char)(v & 0xff);
			v >>= 8;
		}
		if (stream_chunk(a, w, "fSIZ", sb + i, 8 - i)
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	if (write_time_chunks(a, w, entry) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (archive_entry_uid_is_set(entry)) {
		unsigned char ib[8];
		archive_be64enc(ib, (uint64_t)archive_entry_uid(entry));
		if (stream_chunk(a, w, "fUId", ib, 8) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	if (archive_entry_gid_is_set(entry)) {
		unsigned char ib[8];
		archive_be64enc(ib, (uint64_t)archive_entry_gid(entry));
		if (stream_chunk(a, w, "fGId", ib, 8) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	if (write_name_chunk(a, w, "fONm", archive_entry_uname(entry))
	    != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (write_name_chunk(a, w, "fGNm", archive_entry_gname(entry))
	    != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (archive_entry_perm_is_set(entry)) {
		unsigned char pb[2];
		archive_be16enc(pb,
		    (uint16_t)(archive_entry_perm(entry) & 07777));
		if (stream_chunk(a, w, "fMOd", pb, 2) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	{
		int count = archive_entry_xattr_count(entry);
		int i;

		archive_entry_xattr_reset(entry);
		for (i = 0; i < count; i++) {
			const char *name;
			const void *value;
			size_t vsize;
			unsigned char *xb;
			size_t nl, total;

			if (archive_entry_xattr_next(entry, &name,
			    &value, &vsize) != ARCHIVE_OK)
				continue;
			nl = strlen(name);
			total = 8 + nl + vsize;
			xb = malloc(total);
			if (xb == NULL) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't allocate PNA xattr chunk");
				return (ARCHIVE_FATAL);
			}
			archive_be32enc(xb, (uint32_t)nl);
			memcpy(xb + 4, name, nl);
			archive_be32enc(xb + 4 + nl, (uint32_t)vsize);
			if (vsize > 0)
				memcpy(xb + 8 + nl, value, vsize);
			if (stream_chunk(a, w, "xATR", xb, total)
			    != ARCHIVE_OK) {
				free(xb);
				return (ARCHIVE_FATAL);
			}
			free(xb);
		}
	}

	if (compressor_init(a, &w->comp, w->solid ? PNA_COMPRESSION_NONE
	    : w->compression) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	w->comp_started = 1;
	w->entry_open = 1;
	w->entry_kind = kind;
	w->entry_data_fed = 0;
	w->stage_len = 0;
	free(w->entry_linktarget);
	w->entry_linktarget = NULL;
	if (linktarget != NULL) {
		w->entry_linktarget = strdup(linktarget);
		if (w->entry_linktarget == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate PNA link target");
			return (ARCHIVE_FATAL);
		}
	}
	return (ARCHIVE_OK);
}

static ssize_t
archive_write_pna_data(struct archive_write *a, const void *buff,
    size_t len)
{
	struct archive_write_pna *w = a->format_data;

	if (!w->entry_open) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "PNA data written without a header");
		return (ARCHIVE_FATAL);
	}
	if (len > 0)
		w->entry_data_fed = 1;
	if (feed_data(a, w, buff, len, 0) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	return ((ssize_t)len);
}

static int
archive_write_pna_finish_entry(struct archive_write *a)
{
	struct archive_write_pna *w = a->format_data;

	if (!w->entry_open)
		return (ARCHIVE_OK);
	/*
	 * The data of a link entry is its target.  A client that
	 * had no data to write (the usual case) leaves the target
	 * in the entry itself; feed it from there.
	 */
	if (!w->entry_data_fed && w->entry_linktarget != NULL) {
		if (feed_data(a, w, w->entry_linktarget,
		    strlen(w->entry_linktarget), 0) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	if (feed_data(a, w, NULL, 0, 1) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (w->comp_started) {
		compressor_free(&w->comp);
		w->comp_started = 0;
	}
	if (stream_chunk(a, w, "FEND", NULL, 0) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	w->entry_open = 0;
	return (ARCHIVE_OK);
}

static int
archive_write_pna_close(struct archive_write *a)
{
	struct archive_write_pna *w = a->format_data;

	if (write_framing(a, w) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	if (w->solid) {
		unsigned char shed_data[5] = { 0 };
		size_t off = 0;

		shed_data[2] = (unsigned char)w->compression;
		if (emit_chunk(a, w, "SHED", shed_data, sizeof(shed_data))
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (w->comp_started) {
			compressor_free(&w->comp);
			w->comp_started = 0;
		}
		if (compressor_init(a, &w->comp, w->compression)
		    != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		w->comp_started = 1;
		w->flushing_solid = 1;
		w->stage_len = 0;
		while (off < w->solid_len) {
			size_t take = w->solid_len - off;
			if (take > 65536)
				take = 65536;
			if (feed_data(a, w, w->solid_buf + off, take, 0)
			    != ARCHIVE_OK)
				return (ARCHIVE_FATAL);
			off += take;
		}
		if (feed_data(a, w, NULL, 0, 1) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		w->flushing_solid = 0;
		compressor_free(&w->comp);
		w->comp_started = 0;
		if (emit_chunk(a, w, "SEND", NULL, 0) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
	}
	if (emit_chunk(a, w, "AEND", NULL, 0) != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	return (ARCHIVE_OK);
}

static int
archive_write_pna_free(struct archive_write *a)
{
	struct archive_write_pna *w = a->format_data;

	if (w == NULL)
		return (ARCHIVE_OK);
	if (w->comp_started)
		compressor_free(&w->comp);
	free(w->stage);
	free(w->solid_buf);
	free(w->entry_linktarget);
	free(w);
	a->format_data = NULL;
	return (ARCHIVE_OK);
}
