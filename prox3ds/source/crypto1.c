// Crypto1, see crypto1.h. Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md.

#include "crypto1.h"

#define LF_POLY_ODD  0x29CE5C
#define LF_POLY_EVEN 0x870804

static u32 parity32(u32 x)
{
	return __builtin_parity(x);
}

static u8 filter(u32 x)
{
	u32 f = (0xF22C0 >> (x & 0xF)) & 16;
	f |= (0x6C9C0 >> ((x >> 4) & 0xF)) & 8;
	f |= (0x3C8B0 >> ((x >> 8) & 0xF)) & 4;
	f |= (0x1E458 >> ((x >> 12) & 0xF)) & 2;
	f |= (0x0D938 >> ((x >> 16) & 0xF)) & 1;
	return (0xEC57E80A >> f) & 1;
}

u8 oddParity(u8 b)
{
	return 1 ^ parity32(b);
}

void c1Init(Crypto1 *c, const u8 key[6])
{
	u64 k = 0;
	for (int i = 0; i < 6; i++) k = k << 8 | key[i];
	c->odd = c->even = 0;
	for (int i = 47; i > 0; i -= 2) {
		c->odd = c->odd << 1 | ((k >> ((i - 1) ^ 7)) & 1);
		c->even = c->even << 1 | ((k >> (i ^ 7)) & 1);
	}
}

u8 c1Bit(Crypto1 *c, u8 in, bool encrypted)
{
	u8 ret = filter(c->odd);
	u32 feed = (encrypted ? ret : 0) ^ (in ? 1 : 0);
	feed ^= LF_POLY_ODD & c->odd;
	feed ^= LF_POLY_EVEN & c->even;
	c->even = ((c->even << 1) | parity32(feed)) & 0xFFFFFF;
	u32 t = c->odd;
	c->odd = c->even;
	c->even = t;
	return ret;
}

u8 c1Byte(Crypto1 *c, u8 in, bool encrypted)
{
	u8 ret = 0;
	for (int i = 0; i < 8; i++) ret |= c1Bit(c, (in >> i) & 1, encrypted) << i;
	return ret;
}

u32 c1Word(Crypto1 *c, u32 in, bool encrypted)
{
	u32 ret = 0;
	for (int i = 0; i < 32; i++) ret |= (u32)c1Bit(c, (in >> (i ^ 24)) & 1, encrypted) << (i ^ 24);
	return ret;
}

u8 c1Peek(const Crypto1 *c)
{
	return filter(c->odd);
}

void c1Encrypt(Crypto1 *c, const u8 *in, u32 len, u8 *out, u8 *par)
{
	for (u32 i = 0; i < len; i++) {
		u8 b = in[i];
		out[i] = c1Byte(c, 0, false) ^ b;
		par[i] = c1Peek(c) ^ oddParity(b);
	}
}

void c1Decrypt(Crypto1 *c, const u8 *in, u32 len, u8 *out)
{
	for (u32 i = 0; i < len; i++) out[i] = c1Byte(c, 0, false) ^ in[i];
}

u32 prngSuccessor(u32 x, u32 n)
{
	x = __builtin_bswap32(x);
	while (n--) x = x >> 1 | (((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1) << 31;
	return __builtin_bswap32(x);
}
