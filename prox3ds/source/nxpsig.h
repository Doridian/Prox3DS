#pragma once
#include <3ds.h>

// NXP originality signatures: ECDSA without a hash (e = the UID as a big-endian number), r || s, on
// secp128r1 (Ultralight EV1, NTAG21x: 32 bytes) or secp224r1 (DESFire, NTAG 4xx: 56 bytes), checked
// against NXP's public keys (pm3 client/src/crypto/originality.c). The curve arithmetic is ecc.c's (not
// reentrant).

enum { SIG_MFU, SIG_DESFIRE, SIG_MFC }; // which keys to try

// The name of the NXP key the signature verifies with ("DESFire EV3", ...), NULL if none does.
const char *nxpSigCheck(int family, const u8 *uid, u32 uidLen, const u8 *sig, u32 sigLen);

// The ECDSA check itself: curve by size (16 or 28 byte numbers), pub = 04 || X || Y.
bool ecdsaVerify(u32 size, const u8 *pub, const u8 *data, u32 len, const u8 *sig);
