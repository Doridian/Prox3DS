#pragma once
#include <3ds.h>

// Reading zip archives in memory (JavaCard CAP files): the central directory, stored and deflated
// entries (our own inflate, RFC 1951).

typedef struct {
	char name[128];
	u16 method;   // 0 stored, 8 deflated
	u32 size;     // uncompressed
	u32 csize, offset; // compressed size, local header offset
} ZipEntry;

// Calls fn for each entry; stops early when fn returns false. Entries, -1 = not a zip.
int zipList(const u8 *zip, u32 len, bool (*fn)(const ZipEntry *e, void *ctx), void *ctx);
// An entry's contents into out (e->size bytes). false = broken / unsupported method.
bool zipExtract(const u8 *zip, u32 len, const ZipEntry *e, u8 *out);
// Raw deflate data -> out; bytes written, -1 = broken.
int inflate(const u8 *in, u32 inLen, u8 *out, u32 outMax);
