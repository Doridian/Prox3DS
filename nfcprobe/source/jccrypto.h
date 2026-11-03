#pragma once
#include "jcvm.h"

// The Java Card's crypto (javacard.security, javacardx.crypto) in C: keys, KeyBuilder, KeyPair, Cipher,
// Signature, KeyAgreement, MessageDigest. It does what the reference card does (a J3H145, JCOP 3: the
// algorithms it has and its quirks, tools/exp/cprobe/j3h145.txt and NOTES.md), not only what the spec says.

u16 jcCryptoNatSize(int apiCls);
void jcCryptoNatClear(int apiCls, void *nat); // a transient key: back to not initialized
void jcRandom(u8 *out, u32 len);             // jccard.c: the console's RNG
