#pragma once
#include "jcvm.h"

// The Java Card's crypto (javacard.security, javacardx.crypto) in C: keys, KeyBuilder, KeyPair, Cipher,
// Signature, KeyAgreement, MessageDigest. It does what the reference card does (a J3H145, JCOP 3: the
// algorithms it has and its quirks, tools/exp/cprobe/j3h145.txt and docs/NOTES.md), not only what the spec says.

u16 jcCryptoNatSize(int apiCls);
void jcCryptoNatClear(int apiCls, void *nat); // a transient key: back to not initialized
void jcRandom(u8 *out, u32 len);             // jccard.c: the console's RNG
// An RSA signature over a digest of hl bytes (SHA-1 / 224 / 256 / 384 / 512): PKCS#1 v1.5, or PSS with the salt
// as long as the hash (MGF1 with the same hash). For anything, not only the VM (emrtd.c: document signers).
bool rsaVerifyDigest(const u8 *n, u32 nLen, const u8 *e, u32 eLen, const u8 *h, u32 hl, const u8 *sig, u32 sigLen,
	bool pss);
