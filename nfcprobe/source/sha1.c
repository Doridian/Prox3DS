// SHA-1, HMAC-SHA1, PBKDF2-HMAC-SHA1, SHA-256. Plain C, see sha1.h.

#include <string.h>

#include "sha1.h"

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

void sha1Init(Sha1 *s)
{
	static const uint32_t h0[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	memcpy(s->h, h0, sizeof(h0));
	s->n = 0, s->total = 0;
}

void sha1Add(Sha1 *s, const u8 *m, u32 len)
{
	s->total += len;
	while (len) {
		u32 k = 64 - s->n < len ? 64 - s->n : len;
		memcpy(s->buf + s->n, m, k);
		s->n += k, m += k, len -= k;
		if (s->n == 64) block(s, s->buf), s->n = 0;
	}
}

void sha1Done(Sha1 *s, u8 out[20])
{
	u64 bits = s->total * 8;
	u8 pad = 0x80, z = 0, l[8];
	sha1Add(s, &pad, 1);
	while (s->n != 56) sha1Add(s, &z, 1);
	for (int i = 0; i < 8; i++) l[i] = bits >> (56 - 8 * i);
	sha1Add(s, l, 8);
	for (int i = 0; i < 20; i++) out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));
}

void sha1(const u8 *m, u32 len, u8 out[20])
{
	Sha1 s;
	sha1Init(&s);
	sha1Add(&s, m, len);
	sha1Done(&s, out);
}

void hmacSha1(const u8 *key, u32 klen, const u8 *m, u32 len, u8 out[20])
{
	u8 k[64] = { 0 }, pad[64], inner[20];
	if (klen > 64) sha1(key, klen, k);
	else memcpy(k, key, klen);
	Sha1 s;
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	sha1Init(&s), sha1Add(&s, pad, 64), sha1Add(&s, m, len), sha1Done(&s, inner);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5C;
	sha1Init(&s), sha1Add(&s, pad, 64), sha1Add(&s, inner, 20), sha1Done(&s, out);
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

// --- SHA-256 ---

#define ROR(x, n) ((uint32_t)(x) >> (n) | (uint32_t)(x) << (32 - (n)))

static const uint32_t shaK[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void shaBlock(Sha256 *s, const u8 *b)
{
	uint32_t w[64], v[8];
	for (int i = 0; i < 16; i++) w[i] = (uint32_t)b[4 * i] << 24 | b[4 * i + 1] << 16 | b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ w[i - 15] >> 3;
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ w[i - 2] >> 10;
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	memcpy(v, s->h, sizeof(v));
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = v[7] + (ROR(v[4], 6) ^ ROR(v[4], 11) ^ ROR(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + shaK[i] + w[i];
		uint32_t t2 = (ROR(v[0], 2) ^ ROR(v[0], 13) ^ ROR(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
		memmove(v + 1, v, 7 * sizeof(uint32_t));
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) s->h[i] += v[i];
}

void sha256Init(Sha256 *s)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	memcpy(s->h, iv, sizeof(iv));
	s->n = 0, s->len = 0;
}

void sha256Add(Sha256 *s, const u8 *m, uint32_t len)
{
	s->len += len;
	while (len--) {
		s->buf[s->n++] = *m++;
		if (s->n == 64) shaBlock(s, s->buf), s->n = 0;
	}
}

void sha256Done(Sha256 *s, u8 out[32])
{
	uint64_t bits = s->len * 8;
	u8 pad = 0x80, z = 0;
	sha256Add(s, &pad, 1);
	while (s->n != 56) sha256Add(s, &z, 1);
	for (int i = 7; i >= 0; i--) {
		u8 b = bits >> (8 * i);
		sha256Add(s, &b, 1);
	}
	for (int i = 0; i < 32; i++) out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));
}
