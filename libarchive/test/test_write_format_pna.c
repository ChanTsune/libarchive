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

#include "test.h"
#if defined(HAVE_ZSTD_H)
#include <zstd.h>
#endif

/* PNA file signature: 89 'P' 'N' 'A' 0x0d 0x0a 0x1a 0x0a */
static const unsigned char pna_signature[8] =
    { 0x89, 0x50, 0x4e, 0x41, 0x0d, 0x0a, 0x1a, 0x0a };

static void
write_sample_entries(struct archive *a)
{
	struct archive_entry *ae;

	/* A directory. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "dir");
	archive_entry_set_filetype(ae, AE_IFDIR);
	archive_entry_set_perm(ae, 0755);
	archive_entry_set_mtime(ae, 1400000000, 0);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);

	/* A regular file with metadata. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "dir/hello.txt");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_perm(ae, 0660);
	archive_entry_set_size(ae, 18);
	archive_entry_set_birthtime(ae, 1400000001, 999);
	archive_entry_set_mtime(ae, 1234567890, 123456789);
	archive_entry_set_uid(ae, 1001);
	archive_entry_set_gid(ae, 1002);
	archive_entry_set_uname(ae, "alice");
	archive_entry_set_gname(ae, "staff");
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	assertEqualIntA(a, 18,
	    archive_write_data(a, "Hello, PNA world!\n", 18));

	/* A symbolic link. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "link");
	archive_entry_set_filetype(ae, AE_IFLNK);
	archive_entry_set_symlink(ae, "dir/hello.txt");
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);

	/* A hard link. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_pathname(ae, "hard");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_hardlink(ae, "dir/hello.txt");
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
}

static void
verify_sample_entries(struct archive *a)
{
	char buff[64];
	struct archive_entry *ae;

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir", archive_entry_pathname(ae));
	assertEqualInt(AE_IFDIR, archive_entry_filetype(ae));
	assertEqualInt(0755, archive_entry_perm(ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("dir/hello.txt", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(18, archive_entry_size(ae));
	assertEqualInt(1400000001, archive_entry_birthtime(ae));
	assertEqualInt(999, archive_entry_birthtime_nsec(ae));
	assertEqualInt(1234567890, archive_entry_mtime(ae));
	assertEqualInt(123456789, archive_entry_mtime_nsec(ae));
	assertEqualInt(1001, archive_entry_uid(ae));
	assertEqualInt(1002, archive_entry_gid(ae));
	assertEqualString("alice", archive_entry_uname(ae));
	assertEqualString("staff", archive_entry_gname(ae));
	assertEqualInt(0660, archive_entry_perm(ae));
	assertEqualInt(18, archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, "Hello, PNA world!\n", 18);

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("link", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString("dir/hello.txt", archive_entry_symlink(ae));

	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("hard", archive_entry_pathname(ae));
	assertEqualString("dir/hello.txt", archive_entry_hardlink(ae));

	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_FORMAT_PNA, archive_format(a));
}

static void
roundtrip(const char *compression, int solid)
{
	struct archive *a;
	char *buff;
	size_t used;
	const size_t bsiz = 65536;

	buff = malloc(bsiz);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_set_format_pna(a));
	if (compression != NULL)
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_option(a, "pna",
		    "compression", compression));
	if (solid)
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_option(a, "pna",
		    "solid", NULL));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, bsiz, &used));
	write_sample_entries(a);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualInt(ARCHIVE_OK, archive_write_free(a));

	/* The output must start with the PNA signature. */
	assert(used > 8);
	assertEqualMem(buff, pna_signature, 8);

	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_memory(a, buff, used));
	verify_sample_entries(a);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
	free(buff);
}

DEFINE_TEST(test_write_format_pna)
{
	roundtrip(NULL, 0);
}

DEFINE_TEST(test_write_format_pna_store)
{
	roundtrip("store", 0);
}

DEFINE_TEST(test_write_format_pna_deflate)
{
#if !defined(HAVE_ZLIB_H)
	skipping("deflate support requires zlib");
#else
	roundtrip("deflate", 0);
#endif
}

DEFINE_TEST(test_write_format_pna_zstd)
{
#if !defined(HAVE_ZSTD_H)
	skipping("zstd support requires libzstd");
#else
	roundtrip("zstd", 0);
#endif
}

DEFINE_TEST(test_write_format_pna_xz)
{
#if !defined(HAVE_LZMA_H)
	skipping("lzma support requires liblzma");
#else
	roundtrip("xz", 0);
#endif
}

DEFINE_TEST(test_write_format_pna_solid)
{
	roundtrip("store", 1);
}

DEFINE_TEST(test_write_format_pna_solid_zstd)
{
#if !defined(HAVE_ZSTD_H)
	skipping("zstd support requires libzstd");
#else
	struct archive *a;
	char *buff;
	size_t used;
	const size_t bsiz = 65536;
	unsigned char sdat[8192];
	size_t sdat_len = 0;
	unsigned char inner[8192];
	size_t inner_len;
	size_t pos;
	int shed_compression = -1;

	roundtrip("zstd", 1);

	/*
	 * Wire-level shape: in solid mode the entry stream must be
	 * composed uncompressed (inner FHED compression byte 0) and
	 * compression must apply once, to the solid stream (SHED
	 * compression byte 2).  A reader that accepts both shapes
	 * cannot pin this, so inspect the bytes directly.
	 */
	buff = malloc(bsiz);
	assert(buff != NULL);
	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_set_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "pna",
	    "compression", "zstd"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "pna", "solid", NULL));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, bsiz, &used));
	write_sample_entries(a);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualInt(ARCHIVE_OK, archive_write_free(a));

	/* Walk the physical chunks, collecting SHED and SDAT. */
	pos = 8;
	while (pos + 8 <= used) {
		const unsigned char *p =
		    (const unsigned char *)buff + pos;
		size_t len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) |
		    ((size_t)p[2] << 8) | (size_t)p[3];
		assert(pos + 8 + len + 4 <= used);
		if (memcmp(p + 4, "SHED", 4) == 0) {
			assertEqualInt(5, (int)len);
			shed_compression = p[8 + 2];
		} else if (memcmp(p + 4, "SDAT", 4) == 0) {
			assert(sdat_len + len <= sizeof(sdat));
			memcpy(sdat + sdat_len, p + 8, len);
			sdat_len += len;
		} else if (memcmp(p + 4, "AEND", 4) == 0) {
			break;
		}
		pos += 8 + len + 4;
	}
	assertEqualInt(2, shed_compression);
	assert(sdat_len > 0);
	inner_len = ZSTD_decompress(inner, sizeof(inner),
	    sdat, sdat_len);
	assert(!ZSTD_isError(inner_len));
	/* The first inner chunk is the first entry's FHED. */
	assert(inner_len > 8 + 6);
	assertEqualMem(inner + 4, "FHED", 4);
	assertEqualInt(0, inner[8 + 3]);
	/* Inner file data is stored uncompressed. */
	{
		const char *needle = "Hello, PNA world!\n";
		size_t i;
		int found = 0;
		for (i = 0; i + 18 <= inner_len; i++) {
			if (memcmp(inner + i, needle, 18) == 0) {
				found = 1;
				break;
			}
		}
		assert(found);
	}
	free(buff);
#endif
}

DEFINE_TEST(test_write_format_pna_by_name)
{
	struct archive *a;
	char *buff;
	size_t used;
	const size_t bsiz = 4096;

	buff = malloc(bsiz);
	assert(buff != NULL);
	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_by_name(a, "pna"));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, bsiz, &used));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualInt(ARCHIVE_OK, archive_write_free(a));
	/* An empty archive is exactly signature + AHED + AEND chunks. */
	assertEqualInt(8 + 20 + 12, (int)used);
	assertEqualMem(buff, pna_signature, 8);
	free(buff);
}
