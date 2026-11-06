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

/*
 * The reference archives were generated with the reference Rust
 * implementation (pna CLI 0.40.1) from the same source tree:
 *   root/            (directory)
 *   root/sub/        (directory)
 *   root/sub/note.txt  "second file\n"
 *   root/hello.txt     "Hello, PNA world!\n"
 *   root/empty         (empty file)
 *   root/link -> hello.txt     (symbolic link)
 *   root/hard -> root/hello.txt (hard link)
 */
static void
verify_pna_entries(struct archive *a)
{
	char buff[64];
	struct archive_entry *ae;

	/* root directory */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root", archive_entry_pathname(ae));
	assertEqualInt(AE_IFDIR, archive_entry_filetype(ae));

	/* root/sub directory */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/sub", archive_entry_pathname(ae));
	assertEqualInt(AE_IFDIR, archive_entry_filetype(ae));

	/* A regular file in a subdirectory. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/sub/note.txt", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(12, archive_entry_size(ae));
	assertEqualInt(12, archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, "second file\n", 12);

	/* A regular file. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/hello.txt", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(18, archive_entry_size(ae));
	assertEqualInt(18, archive_read_data(a, buff, sizeof(buff)));
	assertEqualMem(buff, "Hello, PNA world!\n", 18);
	assertEqualInt(archive_entry_is_encrypted(ae), 0);

	/* An empty file. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/empty", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(0, archive_entry_size(ae));
	assertEqualInt(0, archive_read_data(a, buff, sizeof(buff)));

	/* A symbolic link: the target is stored as the entry data. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/link", archive_entry_pathname(ae));
	assertEqualInt(AE_IFLNK, archive_entry_filetype(ae));
	assertEqualString("hello.txt", archive_entry_symlink(ae));

	/* A hard link. */
	assertEqualIntA(a, ARCHIVE_OK, archive_read_next_header(a, &ae));
	assertEqualString("root/hard", archive_entry_pathname(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualString("root/hello.txt", archive_entry_hardlink(ae));

	/* End of the archive. */
	assertEqualIntA(a, ARCHIVE_EOF, archive_read_next_header(a, &ae));
	assertEqualInt(7, archive_file_count(a));
	assertEqualIntA(a, ARCHIVE_FORMAT_PNA, archive_format(a));
}

static void
read_and_verify(const char *reffile)
{
	struct archive *a;

	extract_reference_file(reffile);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a, reffile, 10240));
	verify_pna_entries(a);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_pna)
{
	read_and_verify("test_read_format_pna.pna");
}

DEFINE_TEST(test_read_format_pna_deflate)
{
#if !defined(HAVE_ZLIB_H)
	skipping("deflate support requires zlib");
#else
	read_and_verify("test_read_format_pna_deflate.pna");
#endif
}

DEFINE_TEST(test_read_format_pna_zstd)
{
#if !defined(HAVE_ZSTD_H)
	skipping("zstd support requires libzstd");
#else
	read_and_verify("test_read_format_pna_zstd.pna");
#endif
}

DEFINE_TEST(test_read_format_pna_xz)
{
#if !defined(HAVE_LZMA_H)
	skipping("lzma support requires liblzma");
#else
	read_and_verify("test_read_format_pna_xz.pna");
#endif
}

DEFINE_TEST(test_read_format_pna_solid)
{
#if !defined(HAVE_ZSTD_H)
	skipping("the solid reference archive requires libzstd");
#else
	read_and_verify("test_read_format_pna_solid.pna");
#endif
}

DEFINE_TEST(test_read_format_pna_split)
{
	struct archive *a;
	const char *names[4];

	/* Reading the parts concatenated into a single stream. */
	read_and_verify("test_read_format_pna_split_concat.pna");

	/* Reading the parts through the multi-file client interface. */
	extract_reference_file("test_read_format_pna_split.part1.pna");
	extract_reference_file("test_read_format_pna_split.part2.pna");
	extract_reference_file("test_read_format_pna_split.part3.pna");
	names[0] = "test_read_format_pna_split.part1.pna";
	names[1] = "test_read_format_pna_split.part2.pna";
	names[2] = "test_read_format_pna_split.part3.pna";
	names[3] = NULL;
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filenames(a, names, 10240));
	verify_pna_entries(a);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_pna_meta)
{
	struct archive *a;
	struct archive_entry *ae;
	int found = 0;

	extract_reference_file("test_read_format_pna_meta.pna");
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a,
	    "test_read_format_pna_meta.pna", 10240));
	while (archive_read_next_header(a, &ae) == ARCHIVE_OK) {
		if (strcmp(archive_entry_pathname(ae),
		    "root/hello.txt") == 0) {
			found = 1;
			assertEqualInt(1234567890, archive_entry_mtime(ae));
			assertEqualInt(123456789,
			    archive_entry_mtime_nsec(ae));
			assertEqualInt(1001, archive_entry_uid(ae));
			assertEqualInt(1002, archive_entry_gid(ae));
			assertEqualString("alice", archive_entry_uname(ae));
			assertEqualString("staff", archive_entry_gname(ae));
			assertEqualInt(0660, archive_entry_perm(ae));
			/* cTIM is the creation timestamp: birthtime,
			 * not ctime.  Fixture values are the pna CLI's
			 * stored btime for this entry. */
			assertEqualInt(1793939843,
			    archive_entry_birthtime(ae));
			assertEqualInt(806821550,
			    archive_entry_birthtime_nsec(ae));
			assert(!archive_entry_ctime_is_set(ae));
			assert(archive_entry_atime_is_set(ae));
		}
	}
	assertEqualInt(1, found);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_pna_encrypted)
{
	struct archive *a;
	struct archive_entry *ae;
	const char reffile[] = "test_read_format_pna_encrypted.pna";

	extract_reference_file(reffile);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a, reffile, 10240));
	/* Encryption is not supported: reading must fail, not misparse. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_read_next_header(a, &ae));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

DEFINE_TEST(test_read_format_pna_crc)
{
	char buff[64];
	struct archive *a;
	struct archive_entry *ae;
	const char reffile[] = "test_read_format_pna_crc.pna";
	int r;

	extract_reference_file(reffile);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_pna(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_read_open_filename(a, reffile, 10240));
	/* Skip to the corrupted entry (root/hello.txt). */
	do {
		r = archive_read_next_header(a, &ae);
		assertEqualIntA(a, ARCHIVE_OK, r);
	} while (strcmp(archive_entry_pathname(ae), "root/hello.txt") != 0);
	/* Its FDAT chunk CRC does not match: the data read must fail. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_read_data(a, buff, sizeof(buff)));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}
