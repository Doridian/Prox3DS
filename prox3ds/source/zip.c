// Zip archives and inflate, see zip.h. Inflate after the structure of zlib's puff.c: canonical Huffman
// codes decoded a bit at a time, counts per length.
// puff.c (C) Mark Adler, zlib license; see CREDITS.md.

#include <string.h>

#include "zip.h"

static u32 rd16(const u8 *p) { return p[0] | p[1] << 8; }
static u32 rd32(const u8 *p) { return p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24; }

int zipList(const u8 *zip, u32 len, bool (*fn)(const ZipEntry *e, void *ctx), void *ctx)
{
	if (len < 22) return -1;
	// end of central directory: the last 22+ bytes (a comment may follow it)
	s32 eocd = -1;
	for (s32 i = len - 22; i >= 0 && i >= (s32)len - 22 - 65535; i--)
		if (rd32(zip + i) == 0x06054B50) {
			eocd = i;
			break;
		}
	if (eocd < 0) return -1;
	u32 n = rd16(zip + eocd + 10), off = rd32(zip + eocd + 16);
	int count = 0;
	for (u32 k = 0; k < n; k++) {
		if (off + 46 > len || rd32(zip + off) != 0x02014B50) return -1;
		const u8 *c = zip + off;
		u32 nl = rd16(c + 28), xl = rd16(c + 30), cl = rd16(c + 32);
		if (off + 46 + nl > len) return -1;
		ZipEntry e;
		e.method = rd16(c + 10);
		e.csize = rd32(c + 20), e.size = rd32(c + 24), e.offset = rd32(c + 42);
		u32 m = nl < sizeof(e.name) - 1 ? nl : sizeof(e.name) - 1;
		memcpy(e.name, c + 46, m);
		e.name[m] = 0;
		off += 46 + nl + xl + cl;
		count++;
		if (!fn(&e, ctx)) break;
	}
	return count;
}

bool zipExtract(const u8 *zip, u32 len, const ZipEntry *e, u8 *out)
{
	if (e->offset + 30 > len || rd32(zip + e->offset) != 0x04034B50) return false;
	u32 data = e->offset + 30 + rd16(zip + e->offset + 26) + rd16(zip + e->offset + 28);
	if (data > len || e->csize > len - data) return false;
	if (e->method == 0) {
		if (e->csize != e->size) return false;
		memcpy(out, zip + data, e->size);
		return true;
	}
	return e->method == 8 && inflate(zip + data, e->csize, out, e->size) == (int)e->size;
}

// --- inflate ---

typedef struct {
	const u8 *in;
	u32 inLen, pos, bitBuf, bitCnt;
	u8 *out;
	u32 outMax, outPos;
	bool err;
} St;

static u32 bits(St *s, int need)
{
	u32 v = s->bitBuf;
	while ((int)s->bitCnt < need) {
		if (s->pos >= s->inLen) {
			s->err = true;
			return 0;
		}
		v |= (u32)s->in[s->pos++] << s->bitCnt;
		s->bitCnt += 8;
	}
	s->bitBuf = v >> need;
	s->bitCnt -= need;
	return v & ((1u << need) - 1);
}

typedef struct {
	u16 count[16]; // codes per length
	u16 sym[288];  // symbols in code order
} Huff;

static int decode(St *s, const Huff *h)
{
	int code = 0, first = 0, index = 0;
	for (int len = 1; len < 16; len++) {
		code |= bits(s, 1);
		if (s->err) return -1;
		int count = h->count[len];
		if (code - count < first) return h->sym[index + (code - first)];
		index += count, first += count;
		first <<= 1, code <<= 1;
	}
	return -1;
}

// Lengths -> code. false = over-subscribed (incomplete is allowed, as zlib does for single codes).
static bool build(Huff *h, const u8 *lens, int n)
{
	u16 offs[16];
	memset(h->count, 0, sizeof(h->count));
	for (int i = 0; i < n; i++) h->count[lens[i]]++;
	if (h->count[0] == n) return true;
	int left = 1;
	for (int len = 1; len < 16; len++) {
		left <<= 1;
		left -= h->count[len];
		if (left < 0) return false;
	}
	offs[1] = 0;
	for (int len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->count[len];
	for (int i = 0; i < n; i++)
		if (lens[i]) h->sym[offs[lens[i]]++] = i;
	return true;
}

static bool codes(St *s, const Huff *lit, const Huff *dist)
{
	static const u16 lbase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
		115, 131, 163, 195, 227, 258 };
	static const u8 lext[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
	static const u16 dbase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
		1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
	static const u8 dext[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
		12, 13, 13 };
	for (;;) {
		int sym = decode(s, lit);
		if (sym < 0) return false;
		if (sym < 256) {
			if (s->outPos >= s->outMax) return false;
			s->out[s->outPos++] = sym;
		} else if (sym == 256) {
			return true;
		} else {
			sym -= 257;
			if (sym >= 29) return false;
			u32 len = lbase[sym] + bits(s, lext[sym]);
			int d = decode(s, dist);
			if (d < 0 || d >= 30) return false;
			u32 back = dbase[d] + bits(s, dext[d]);
			if (s->err || back > s->outPos || len > s->outMax - s->outPos) return false;
			for (; len; len--, s->outPos++) s->out[s->outPos] = s->out[s->outPos - back];
		}
	}
}

static bool fixed(St *s)
{
	static Huff lit, dist;
	static bool made;
	if (!made) {
		u8 l[288];
		int i = 0;
		for (; i < 144; i++) l[i] = 8;
		for (; i < 256; i++) l[i] = 9;
		for (; i < 280; i++) l[i] = 7;
		for (; i < 288; i++) l[i] = 8;
		build(&lit, l, 288);
		for (i = 0; i < 30; i++) l[i] = 5;
		build(&dist, l, 30);
		made = true;
	}
	return codes(s, &lit, &dist);
}

static bool dynamic(St *s)
{
	static const u8 order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
	u8 lens[320];
	Huff lit, dist;
	int nlen = bits(s, 5) + 257, ndist = bits(s, 5) + 1, ncode = bits(s, 4) + 4;
	if (s->err || nlen > 286 || ndist > 30) return false;
	memset(lens, 0, 19);
	for (int i = 0; i < ncode; i++) lens[order[i]] = bits(s, 3);
	if (s->err || !build(&lit, lens, 19)) return false;
	for (int i = 0; i < nlen + ndist;) {
		int sym = decode(s, &lit);
		if (sym < 0) return false;
		if (sym < 16) {
			lens[i++] = sym;
			continue;
		}
		int val = 0, rep;
		if (sym == 16) {
			if (!i) return false;
			val = lens[i - 1], rep = 3 + bits(s, 2);
		} else if (sym == 17) {
			rep = 3 + bits(s, 3);
		} else {
			rep = 11 + bits(s, 7);
		}
		if (s->err || i + rep > nlen + ndist) return false;
		while (rep--) lens[i++] = val;
	}
	if (!lens[256]) return false;
	return build(&lit, lens, nlen) && build(&dist, lens + nlen, ndist) && codes(s, &lit, &dist);
}

int inflate(const u8 *in, u32 inLen, u8 *out, u32 outMax)
{
	St s = { in, inLen, 0, 0, 0, out, outMax, 0, false };
	int last;
	do {
		last = bits(&s, 1);
		int type = bits(&s, 2);
		if (s.err) return -1;
		if (type == 0) {
			s.bitBuf = s.bitCnt = 0; // to the byte boundary
			if (s.pos + 4 > inLen) return -1;
			u32 len = rd16(in + s.pos), nlen = rd16(in + s.pos + 2);
			s.pos += 4;
			if ((len ^ 0xFFFF) != nlen || len > inLen - s.pos || len > outMax - s.outPos) return -1;
			memcpy(out + s.outPos, in + s.pos, len);
			s.pos += len, s.outPos += len;
		} else if (type == 1) {
			if (!fixed(&s)) return -1;
		} else if (type == 2) {
			if (!dynamic(&s)) return -1;
		} else {
			return -1;
		}
	} while (!last);
	return s.outPos;
}
