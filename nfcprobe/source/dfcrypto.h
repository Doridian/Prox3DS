#pragma once
#include <3ds.h>

// The ciphers of DESFire EV1 secure messaging: DES, 2K3DES, 3K3DES (EDE) and AES-128, CBC with a running
// IV, CMAC, and DESFire's CRC32 (and AES-192 / 256 for the Java Card). Plain C, nothing fast; see
// tools/dfcrypto_test.py for the checks.

enum { DF_DES, DF_2K3DES, DF_3K3DES, DF_AES, DF_AES192, DF_AES256 }; // the AES-192 / 256 for the Java Card

typedef struct {
	u8 type, bs;      // DF_*, block size (8 / 16)
	u64 sub[3][16];   // DES: K1 K2 K3 round keys (DES: all K1, 2K3DES: K3 = K1)
	u8 rk[240];       // AES round keys
} DfCipher;

u32 dfKeyLen(u8 type); // 8 / 16 / 24 / 16
const char *dfKeyTypeName(u8 type);
void dfCipherInit(DfCipher *c, u8 type, const u8 *key);
void dfBlock(const DfCipher *c, u8 *b, bool enc);
// CBC in place, len a multiple of the block size; iv becomes the last ciphertext block.
void dfCbc(const DfCipher *c, u8 *iv, u8 *p, u32 len, bool enc);
// CMAC with iv as the starting chain value (EV1 keeps it running); iv and mac get the full result.
void dfCmac(const DfCipher *c, u8 *iv, const u8 *p, u32 len, u8 *mac);
// A DES key's 16 round subkeys as 8 six-bit S-box inputs each (the chip's UL-C emulation, chip/emu.c des()).
void dfDesSubkeys(const u8 key[8], u8 ks[16][8]);
u32 dfCrc32(const u8 *p, u32 len); // init FFFFFFFF, no final xor, appended LSB first
