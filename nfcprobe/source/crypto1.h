#pragma once
#include <3ds.h>

// Crypto1 (Mifare Classic), the crapto1 reference cipher; see tools/crypto1.py.
// Words are big-endian as on the wire, bytes go through the cipher LSB first.

typedef struct {
	u32 odd, even;
} Crypto1;

void c1Init(Crypto1 *c, const u8 key[6]);
u8 c1Bit(Crypto1 *c, u8 in, bool encrypted);
u8 c1Byte(Crypto1 *c, u8 in, bool encrypted);
u32 c1Word(Crypto1 *c, u32 in, bool encrypted);
u8 c1Peek(const Crypto1 *c);                          // keystream bit for a parity bit
void c1Encrypt(Crypto1 *c, const u8 *in, u32 len, u8 *out, u8 *par); // par: encrypted parity bits
void c1Decrypt(Crypto1 *c, const u8 *in, u32 len, u8 *out);
u32 prngSuccessor(u32 x, u32 n);
u8 oddParity(u8 b);
