// Elliptic curves over a prime field for the Java Card, see ecc.h.

#include <string.h>

#include "ecc.h"

typedef struct {
	Bn x, y, z; // Jacobian, Montgomery form; z = 0: infinity
} Pt;

static Bn oneM; // 1 in Montgomery form for the curve in use

static void mul(const EcCurve *c, Bn *r, const Bn *a, const Bn *b)
{
	bnMontMul(&c->p, r, a, b);
}

static void add(const EcCurve *c, Bn *r, const Bn *a, const Bn *b)
{
	bnModAdd(&c->p, r, a, b);
}

static void sub(const EcCurve *c, Bn *r, const Bn *a, const Bn *b)
{
	bnModSub(&c->p, r, a, b);
}

static void dbl(const EcCurve *c, Pt *r, const Pt *p)
{
	static Bn xx, yy, yyyy, zz, s, m, t;
	if (bnIsZero(&p->z) || bnIsZero(&p->y)) {
		memset(r, 0, sizeof(*r));
		return;
	}
	mul(c, &xx, &p->x, &p->x);
	mul(c, &yy, &p->y, &p->y);
	mul(c, &yyyy, &yy, &yy);
	mul(c, &zz, &p->z, &p->z);
	mul(c, &s, &p->x, &yy); // S = 4 X YY
	add(c, &s, &s, &s);
	add(c, &s, &s, &s);
	mul(c, &t, &zz, &zz); // M = 3 XX + a ZZ^2
	mul(c, &t, &t, &c->a);
	add(c, &m, &xx, &xx);
	add(c, &m, &m, &xx);
	add(c, &m, &m, &t);
	mul(c, &t, &p->y, &p->z); // Z3 = 2 Y Z
	add(c, &r->z, &t, &t);
	mul(c, &t, &m, &m); // X3 = M^2 - 2 S
	sub(c, &t, &t, &s);
	sub(c, &r->x, &t, &s);
	sub(c, &t, &s, &r->x); // Y3 = M (S - X3) - 8 YYYY
	mul(c, &t, &m, &t);
	add(c, &yyyy, &yyyy, &yyyy);
	add(c, &yyyy, &yyyy, &yyyy);
	add(c, &yyyy, &yyyy, &yyyy);
	sub(c, &r->y, &t, &yyyy);
}

static void padd(const EcCurve *c, Pt *r, const Pt *p, const Pt *q)
{
	static Bn u1, u2, s1, s2, z1z1, z2z2, h, hh, hhh, rr, t;
	if (bnIsZero(&p->z)) {
		*r = *q;
		return;
	}
	if (bnIsZero(&q->z)) {
		*r = *p;
		return;
	}
	mul(c, &z1z1, &p->z, &p->z);
	mul(c, &z2z2, &q->z, &q->z);
	mul(c, &u1, &p->x, &z2z2);
	mul(c, &u2, &q->x, &z1z1);
	mul(c, &s1, &p->y, &q->z);
	mul(c, &s1, &s1, &z2z2);
	mul(c, &s2, &q->y, &p->z);
	mul(c, &s2, &s2, &z1z1);
	if (!bnCmp(&u1, &u2)) {
		if (bnCmp(&s1, &s2)) memset(r, 0, sizeof(*r));
		else dbl(c, r, p);
		return;
	}
	sub(c, &h, &u2, &u1);
	sub(c, &rr, &s2, &s1);
	mul(c, &hh, &h, &h);
	mul(c, &hhh, &hh, &h);
	mul(c, &u1, &u1, &hh); // U1 H^2
	mul(c, &t, &p->z, &q->z);
	mul(c, &r->z, &t, &h);
	mul(c, &t, &rr, &rr); // X3 = R^2 - H^3 - 2 U1 H^2
	sub(c, &t, &t, &hhh);
	sub(c, &t, &t, &u1);
	sub(c, &r->x, &t, &u1);
	sub(c, &t, &u1, &r->x); // Y3 = R (U1 H^2 - X3) - S1 H^3
	mul(c, &t, &rr, &t);
	mul(c, &s1, &s1, &hhh);
	sub(c, &r->y, &t, &s1);
}

// k * (x, y) (plain affine in), Jacobian out
static void smul(const EcCurve *c, Pt *r, const Bn *k, const Bn *x, const Bn *y)
{
	static Pt base, acc;
	bnToMont(&c->p, &base.x, x);
	bnToMont(&c->p, &base.y, y);
	base.z = oneM;
	memset(&acc, 0, sizeof(acc));
	for (int i = bnBits(k) - 1; i >= 0; i--) {
		dbl(c, &acc, &acc);
		if (bnBit(k, i)) padd(c, &acc, &acc, &base);
	}
	*r = acc;
}

// plain affine x, y; false: infinity
static bool affine(const EcCurve *c, const Pt *p, Bn *x, Bn *y)
{
	static Bn zi, z2;
	if (bnIsZero(&p->z)) return false;
	bnFromMont(&c->p, &zi, &p->z);
	bnModInvPrime(&c->p, &zi, &zi);
	bnToMont(&c->p, &zi, &zi);
	mul(c, &z2, &zi, &zi);
	mul(c, x, &p->x, &z2);
	bnFromMont(&c->p, x, x);
	if (y) {
		mul(c, &z2, &z2, &zi);
		mul(c, y, &p->y, &z2);
		bnFromMont(&c->p, y, y);
	}
	return true;
}

static bool onCurve(const EcCurve *c, const Bn *x, const Bn *y)
{
	static Bn xm, ym, l, r;
	if (bnCmp(x, &c->p.m) >= 0 || bnCmp(y, &c->p.m) >= 0) return false;
	bnToMont(&c->p, &xm, x);
	bnToMont(&c->p, &ym, y);
	mul(c, &l, &ym, &ym);
	mul(c, &r, &xm, &xm); // x^3 + a x + b = (x^2 + a) x + b
	add(c, &r, &r, &c->a);
	mul(c, &r, &r, &xm);
	add(c, &r, &r, &c->b);
	return !bnCmp(&l, &r);
}

bool ecCurveInit(EcCurve *c, const u8 *p, u32 pLen, const u8 *a, u32 aLen, const u8 *b, u32 bLen, const u8 *g,
	u32 gLen, const u8 *r, u32 rLen)
{
	static Bn t;
	memset(c, 0, sizeof(*c));
	bnFromBytes(&t, p, pLen);
	c->len = (bnBits(&t) + 7) / 8;
	if (c->len < 16 || c->len > 66 || !bnMontInit(&c->p, &t)) return false;
	bnFromBytes(&t, r, rLen);
	if (bnBits(&t) < 64 || !bnMontInit(&c->n, &t)) return false;
	bnSet(&t, 1);
	bnToMont(&c->p, &oneM, &t);
	bnFromBytes(&t, a, aLen);
	bnToMont(&c->p, &c->a, &t);
	bnFromBytes(&t, b, bLen);
	bnToMont(&c->p, &c->b, &t);
	return ecPoint(c, g, gLen, &c->gx, &c->gy);
}

bool ecPoint(const EcCurve *c, const u8 *pt, u32 len, Bn *x, Bn *y)
{
	if (len != 1u + 2 * c->len || pt[0] != 4) return false;
	bnFromBytes(x, pt + 1, c->len);
	bnFromBytes(y, pt + 1 + c->len, c->len);
	return onCurve(c, x, y);
}

void ecPublic(const EcCurve *c, const Bn *d, u8 *out)
{
	static Pt q;
	static Bn x, y;
	bnSet(&x, 1);
	bnToMont(&c->p, &oneM, &x);
	smul(c, &q, d, &c->gx, &c->gy);
	affine(c, &q, &x, &y);
	out[0] = 4;
	bnToBytes(&x, out + 1, c->len);
	bnToBytes(&y, out + 1 + c->len, c->len);
}

bool ecdh(const EcCurve *c, const Bn *d, const u8 *q, u32 qLen, u8 *out, bool xy)
{
	static Pt r;
	static Bn x, y;
	bnSet(&x, 1);
	bnToMont(&c->p, &oneM, &x);
	if (!ecPoint(c, q, qLen, &x, &y)) return false;
	smul(c, &r, d, &x, &y);
	if (!affine(c, &r, &x, &y)) return false;
	if (xy) *out++ = 4;
	bnToBytes(&x, out, c->len);
	if (xy) bnToBytes(&y, out + c->len, c->len);
	return true;
}

bool ecPaceGm(const EcCurve *c, const Bn *d, const u8 *h, u32 hLen, u8 *out)
{
	static Pt r, hp;
	static Bn x, y;
	bnSet(&x, 1);
	bnToMont(&c->p, &oneM, &x);
	if (!ecPoint(c, h, hLen, &x, &y)) return false;
	bnToMont(&c->p, &hp.x, &x);
	bnToMont(&c->p, &hp.y, &y);
	hp.z = oneM;
	smul(c, &r, d, &c->gx, &c->gy);
	padd(c, &r, &r, &hp);
	if (!affine(c, &r, &x, &y)) return false;
	out[0] = 4;
	bnToBytes(&x, out + 1, c->len);
	bnToBytes(&y, out + 1 + c->len, c->len);
	return true;
}

// the hash as an integer mod n: its leftmost bits (as many as n has)
static void hashInt(const EcCurve *c, const u8 *h, u32 hLen, Bn *e)
{
	int nb = bnBits(&c->n.m);
	if (hLen > 4 * BN_N) hLen = 4 * BN_N;
	bnFromBytes(e, h, hLen);
	for (int sh = 8 * hLen - nb; sh > 0; sh--) bnShr1(e);
	if (bnCmp(e, &c->n.m) >= 0) bnSub(e, e, &c->n.m);
}

void ecRandomScalar(const EcCurve *c, Bn *d, void (*rnd)(u8 *, u32))
{
	int bits = bnBits(&c->n.m), bytes = (bits + 7) / 8;
	do {
		u8 b[68];
		rnd(b, bytes);
		b[0] &= 0xFF >> (8 * bytes - bits);
		bnFromBytes(d, b, bytes);
	} while (bnIsZero(d) || bnCmp(d, &c->n.m) >= 0);
}

void ecSign(const EcCurve *c, const Bn *d, const u8 *h, u32 hLen, void (*rnd)(u8 *, u32), Bn *r, Bn *s)
{
	static Pt R;
	static Bn k, e, t, dm;
	const BnMont *N = &c->n;
	bnSet(&t, 1);
	bnToMont(&c->p, &oneM, &t);
	hashInt(c, h, hLen, &e);
	for (;;) {
		ecRandomScalar(c, &k, rnd);
		smul(c, &R, &k, &c->gx, &c->gy);
		if (!affine(c, &R, &t, NULL)) continue;
		bnMod(r, &t, &N->m);
		if (bnIsZero(r)) continue;
		// s = k^-1 (e + r d) mod n
		bnToMont(N, &t, r);
		bnToMont(N, &dm, d);
		bnMontMul(N, &t, &t, &dm);
		bnToMont(N, &dm, &e);
		bnModAdd(N, &t, &t, &dm);
		bnModInvPrime(N, &k, &k);
		bnToMont(N, &k, &k);
		bnMontMul(N, &t, &t, &k);
		bnFromMont(N, s, &t);
		if (!bnIsZero(s)) return;
	}
}

bool ecVerify(const EcCurve *c, const u8 *q, u32 qLen, const u8 *h, u32 hLen, const Bn *r, const Bn *s)
{
	static Pt p1, p2;
	static Bn qx, qy, e, w, u1, u2, x;
	const BnMont *N = &c->n;
	bnSet(&x, 1);
	bnToMont(&c->p, &oneM, &x);
	if (bnIsZero(r) || bnIsZero(s) || bnCmp(r, &N->m) >= 0 || bnCmp(s, &N->m) >= 0) return false;
	if (!ecPoint(c, q, qLen, &qx, &qy)) return false;
	hashInt(c, h, hLen, &e);
	bnModInvPrime(N, &w, s); // w = s^-1, u1 = e w, u2 = r w
	bnToMont(N, &w, &w);
	bnToMont(N, &u1, &e);
	bnMontMul(N, &u1, &u1, &w);
	bnFromMont(N, &u1, &u1);
	bnToMont(N, &u2, r);
	bnMontMul(N, &u2, &u2, &w);
	bnFromMont(N, &u2, &u2);
	smul(c, &p1, &u1, &c->gx, &c->gy);
	smul(c, &p2, &u2, &qx, &qy);
	padd(c, &p1, &p1, &p2);
	if (!affine(c, &p1, &x, NULL)) return false;
	bnMod(&x, &x, &N->m);
	return !bnCmp(&x, r);
}
