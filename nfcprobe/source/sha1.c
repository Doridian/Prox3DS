// SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1. Plain C, see sha1.h.

#include <string.h>

#include "sha1.h"

typedef struct {
	uint32_t h[5];
	u8 buf[64];
	u32 n;
	u64 total;
} Sha1;

#define ROL(x, n) ((x) << (n) | (x) >> (32 - (n)))

static void block(Sha1 *s, const u8 *b)
{
	uint32_t w[80], a = s->h[0], bb = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
	for (int i = 0; i < 16; i++) w[i] = b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 80; i++) w[i] = ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	for (int i = 0; i < 80; i++) {
		uint32_t f, k;
		if (i < 20) f = (bb & c) | (~bb & d), k = 0x5A827999;
		else if (i < 40) f = bb ^ c ^ d, k = 0x6ED9EBA1;
		else if (i < 60) f = (bb & c) | (bb & d) | (c & d), k = 0x8F1BBCDC;
		else f = bb ^ c ^ d, k = 0xCA62C1D6;
		uint32_t t = ROL(a, 5) + f + e + k + w[i];
		e = d, d = c, c = ROL(bb, 30), bb = a, a = t;
	}
	s->h[0] += a, s->h[1] += bb, s->h[2] += c, s->h[3] += d, s->h[4] += e;
}

static void init(Sha1 *s)
{
	static const uint32_t h0[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	memcpy(s->h, h0, sizeof(h0));
	s->n = 0, s->total = 0;
}

static void add(Sha1 *s, const u8 *m, u32 len)
{
	s->total += len;
	while (len) {
		u32 k = 64 - s->n < len ? 64 - s->n : len;
		memcpy(s->buf + s->n, m, k);
		s->n += k, m += k, len -= k;
		if (s->n == 64) block(s, s->buf), s->n = 0;
	}
}

static void done(Sha1 *s, u8 out[20])
{
	u64 bits = s->total * 8;
	u8 pad = 0x80, z = 0, l[8];
	add(s, &pad, 1);
	while (s->n != 56) add(s, &z, 1);
	for (int i = 0; i < 8; i++) l[i] = bits >> (56 - 8 * i);
	add(s, l, 8);
	for (int i = 0; i < 20; i++) out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));
}

void sha1(const u8 *m, u32 len, u8 out[20])
{
	Sha1 s;
	init(&s);
	add(&s, m, len);
	done(&s, out);
}

void hmacSha1(const u8 *key, u32 klen, const u8 *m, u32 len, u8 out[20])
{
	u8 k[64] = { 0 }, pad[64], inner[20];
	if (klen > 64) sha1(key, klen, k);
	else memcpy(k, key, klen);
	Sha1 s;
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	init(&s), add(&s, pad, 64), add(&s, m, len), done(&s, inner);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5C;
	init(&s), add(&s, pad, 64), add(&s, inner, 20), done(&s, out);
}

void pbkdf2Sha1(const u8 *pw, u32 pwLen, const u8 *salt, u32 saltLen, u32 iter, u8 *out, u32 outLen)
{
	u8 m[128], u[20], t[20];
	for (u32 blk = 1; outLen; blk++) {
		u32 sl = saltLen < sizeof(m) - 4 ? saltLen : sizeof(m) - 4;
		memcpy(m, salt, sl);
		m[sl] = blk >> 24, m[sl + 1] = blk >> 16, m[sl + 2] = blk >> 8, m[sl + 3] = blk;
		hmacSha1(pw, pwLen, m, sl + 4, u);
		memcpy(t, u, 20);
		for (u32 i = 1; i < iter; i++) {
			hmacSha1(pw, pwLen, u, 20, u);
			for (int j = 0; j < 20; j++) t[j] ^= u[j];
		}
		u32 k = outLen < 20 ? outLen : 20;
		memcpy(out, t, k);
		out += k, outLen -= k;
	}
}
