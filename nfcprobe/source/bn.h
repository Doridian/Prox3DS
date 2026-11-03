#pragma once
#include <3ds.h>

// Big numbers for the Java Card's RSA and elliptic curves (jccrypto.c, ecc.c): unsigned, 32-bit limbs
// little-endian, fixed size (RSA-2048 and a product of two 1024-bit primes fit), Montgomery arithmetic.
// Plain C, not constant time. Not reentrant: the bigger temporaries are static (the VM is one thread).

#define BN_N 66 // limbs

typedef struct {
	u32 v[BN_N];
} Bn;

void bnFromBytes(Bn *r, const u8 *b, u32 len); // big-endian, len <= 4 * BN_N
void bnToBytes(const Bn *a, u8 *b, u32 len);   // big-endian, left padded (the low len bytes)
void bnSet(Bn *r, u32 v);
int bnBits(const Bn *a);
int bnBit(const Bn *a, int i);
bool bnIsZero(const Bn *a);
int bnCmp(const Bn *a, const Bn *b);
u32 bnAdd(Bn *r, const Bn *a, const Bn *b); // the carry out
u32 bnSub(Bn *r, const Bn *a, const Bn *b); // the borrow out
void bnMul(Bn *r, const Bn *a, const Bn *b); // a * b (must fit in BN_N limbs)
void bnMulSmall(Bn *r, const Bn *a, u32 m);
u32 bnDivSmall(Bn *r, const Bn *a, u32 d); // r = a / d, the remainder back
u32 bnModSmall(const Bn *a, u32 d);
void bnMod(Bn *r, const Bn *a, const Bn *m); // a mod m (m not 0), any a
void bnShr1(Bn *a);

// Montgomery arithmetic mod an odd m of n limbs. Values in Montgomery form are a * R mod m, R = 2^(32n).
typedef struct {
	Bn m, rr; // the modulus, R^2 mod m
	u32 minv; // -m^-1 mod 2^32
	int n;
} BnMont;

bool bnMontInit(BnMont *M, const Bn *m); // false: m even or 0
void bnMontMul(const BnMont *M, Bn *r, const Bn *a, const Bn *b); // a, b < m
void bnToMont(const BnMont *M, Bn *r, const Bn *a);               // a any size
void bnFromMont(const BnMont *M, Bn *r, const Bn *a);
void bnModAdd(const BnMont *M, Bn *r, const Bn *a, const Bn *b);  // a, b < m (either form)
void bnModSub(const BnMont *M, Bn *r, const Bn *a, const Bn *b);
// r = a^e mod m (plain values; a any size).
void bnModExp(const BnMont *M, Bn *r, const Bn *a, const Bn *e);
void bnModInvPrime(const BnMont *M, Bn *r, const Bn *a); // a^(m-2) mod m: the inverse for a prime m (plain)

// RSA: out = in^d mod n with the parts as big-endian bytes; false = bad key / in >= n.
bool rsaExp(const u8 *n, u32 nLen, const u8 *e, u32 eLen, const u8 *in, u32 inLen, u8 *out);
// The CRT form: part = P, Q, DP1, DQ1, PQ (q^-1 mod p); out gets outLen bytes (the modulus length).
bool rsaCrt(const u8 *const part[5], const u16 partLen[5], const u8 *in, u32 inLen, u8 *out, u32 outLen);
// A random prime of bits bits (the top two set) with gcd(p - 1, e) = 1; rnd fills bytes.
void bnPrime(Bn *p, int bits, u32 e, void (*rnd)(u8 *, u32));
// d = e^-1 mod m for a small prime e (m even is fine); false: no inverse.
bool bnInvSmall(Bn *d, u32 e, const Bn *m);
