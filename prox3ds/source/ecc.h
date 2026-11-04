#pragma once
#include "bn.h"

// Elliptic curves over a prime field (y^2 = x^3 + ax + b) for the Java Card: ECDSA, ECDH, key pairs. Any
// curve the applet gives (up to 521 bits), Jacobian coordinates, Montgomery arithmetic (bn.h). Not constant
// time, not reentrant.

typedef struct {
	BnMont p, n;  // the field, the order of G
	Bn a, b;      // Montgomery form (mod p)
	Bn gx, gy;    // plain
	int len;      // field bytes
} EcCurve;

// The parts as big-endian bytes, G uncompressed (04 x y). false: not a usable curve.
bool ecCurveInit(EcCurve *c, const u8 *p, u32 pLen, const u8 *a, u32 aLen, const u8 *b, u32 bLen, const u8 *g,
	u32 gLen, const u8 *r, u32 rLen);
// An uncompressed point (04 x y) on the curve; false: not one.
bool ecPoint(const EcCurve *c, const u8 *pt, u32 len, Bn *x, Bn *y);
// The public point of the private scalar d: 04 x y into out (1 + 2 len bytes).
void ecPublic(const EcCurve *c, const Bn *d, u8 *out);
// d * Q into out: x (len bytes), or with xy the point (04 x y); false: Q is not a point on the curve or the
// result is infinity.
bool ecdh(const EcCurve *c, const Bn *d, const u8 *q, u32 qLen, u8 *out, bool xy);
// PACE generic mapping (TR-03110): d * G + H, H an uncompressed point on the curve; 04 x y into out.
bool ecPaceGm(const EcCurve *c, const Bn *d, const u8 *h, u32 hLen, u8 *out);
// ECDSA over a hash (truncated to the order's bits): r and s (plain) back.
void ecSign(const EcCurve *c, const Bn *d, const u8 *h, u32 hLen, void (*rnd)(u8 *, u32), Bn *r, Bn *s);
bool ecVerify(const EcCurve *c, const u8 *q, u32 qLen, const u8 *h, u32 hLen, const Bn *r, const Bn *s);
// A random scalar in [1, n - 1].
void ecRandomScalar(const EcCurve *c, Bn *d, void (*rnd)(u8 *, u32));
