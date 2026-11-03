// Big numbers, Montgomery arithmetic, RSA and primes for the Java Card, see bn.h.

#include <string.h>

#include "bn.h"

void bnFromBytes(Bn *r, const u8 *b, u32 len)
{
	memset(r, 0, sizeof(*r));
	for (u32 i = 0; i < len && i < 4 * BN_N; i++) r->v[i / 4] |= (u32)b[len - 1 - i] << (8 * (i % 4));
}

void bnToBytes(const Bn *a, u8 *b, u32 len)
{
	for (u32 i = 0; i < len; i++) b[len - 1 - i] = i < 4 * BN_N ? a->v[i / 4] >> (8 * (i % 4)) : 0;
}

void bnSet(Bn *r, u32 v)
{
	memset(r, 0, sizeof(*r));
	r->v[0] = v;
}

int bnBits(const Bn *a)
{
	for (int i = BN_N - 1; i >= 0; i--)
		if (a->v[i]) return 32 * i + 32 - __builtin_clz(a->v[i]);
	return 0;
}

int bnBit(const Bn *a, int i)
{
	return i >= 0 && i < 32 * BN_N ? a->v[i / 32] >> (i % 32) & 1 : 0;
}

bool bnIsZero(const Bn *a)
{
	for (int i = 0; i < BN_N; i++)
		if (a->v[i]) return false;
	return true;
}

static int cmpN(const u32 *a, const u32 *b, int n)
{
	for (int i = n - 1; i >= 0; i--)
		if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
	return 0;
}

int bnCmp(const Bn *a, const Bn *b)
{
	return cmpN(a->v, b->v, BN_N);
}

static u32 addN(u32 *r, const u32 *a, const u32 *b, int n)
{
	u64 c = 0;
	for (int i = 0; i < n; i++) {
		c += (u64)a[i] + b[i];
		r[i] = c;
		c >>= 32;
	}
	return c;
}

static u32 subN(u32 *r, const u32 *a, const u32 *b, int n)
{
	u32 borrow = 0;
	for (int i = 0; i < n; i++) {
		u64 d = (u64)a[i] - b[i] - borrow;
		r[i] = d;
		borrow = d >> 63;
	}
	return borrow;
}

u32 bnAdd(Bn *r, const Bn *a, const Bn *b)
{
	return addN(r->v, a->v, b->v, BN_N);
}

u32 bnSub(Bn *r, const Bn *a, const Bn *b)
{
	return subN(r->v, a->v, b->v, BN_N);
}

void bnMul(Bn *r, const Bn *a, const Bn *b)
{
	static u32 t[2 * BN_N];
	memset(t, 0, sizeof(t));
	int na = (bnBits(a) + 31) / 32, nb = (bnBits(b) + 31) / 32;
	for (int i = 0; i < na; i++) {
		u64 c = 0;
		for (int j = 0; j < nb; j++) {
			c += (u64)a->v[i] * b->v[j] + t[i + j];
			t[i + j] = c;
			c >>= 32;
		}
		t[i + nb] = c;
	}
	memcpy(r->v, t, sizeof(r->v));
}

void bnMulSmall(Bn *r, const Bn *a, u32 m)
{
	u64 c = 0;
	for (int i = 0; i < BN_N; i++) {
		c += (u64)a->v[i] * m;
		r->v[i] = c;
		c >>= 32;
	}
}

u32 bnDivSmall(Bn *r, const Bn *a, u32 d)
{
	u64 rem = 0;
	for (int i = BN_N - 1; i >= 0; i--) {
		rem = rem << 32 | a->v[i];
		r->v[i] = rem / d;
		rem %= d;
	}
	return rem;
}

u32 bnModSmall(const Bn *a, u32 d)
{
	u64 rem = 0;
	for (int i = BN_N - 1; i >= 0; i--) rem = (rem << 32 | a->v[i]) % d;
	return rem;
}

void bnShr1(Bn *a)
{
	for (int i = 0; i < BN_N; i++) a->v[i] = a->v[i] >> 1 | (i + 1 < BN_N ? a->v[i + 1] << 31 : 0);
}

// a mod m by shift and subtract (one bit at a time: slow, used outside the hot loops)
void bnMod(Bn *r, const Bn *a, const Bn *m)
{
	static Bn t;
	int n = (bnBits(m) + 31) / 32 + 1;
	if (n > BN_N) n = BN_N;
	memset(&t, 0, sizeof(t));
	for (int i = bnBits(a) - 1; i >= 0; i--) {
		u32 top = t.v[n - 1] >> 31;
		for (int k = n - 1; k > 0; k--) t.v[k] = t.v[k] << 1 | t.v[k - 1] >> 31;
		t.v[0] = t.v[0] << 1 | bnBit(a, i);
		if (top || cmpN(t.v, m->v, n) >= 0) subN(t.v, t.v, m->v, n);
	}
	*r = t;
}

// --- Montgomery ---

bool bnMontInit(BnMont *M, const Bn *m)
{
	if (!(m->v[0] & 1)) return false;
	M->m = *m;
	M->n = (bnBits(m) + 31) / 32;
	u32 x = 1;
	for (int i = 0; i < 5; i++) x *= 2 - m->v[0] * x;
	M->minv = -x;
	// R^2 mod m: 1 doubled 2 * 32n times
	Bn *r = &M->rr;
	bnSet(r, 1);
	for (int i = 0; i < 64 * M->n; i++) {
		u32 top = r->v[M->n - 1] >> 31;
		for (int k = M->n; k > 0; k--) r->v[k] = r->v[k] << 1 | r->v[k - 1] >> 31;
		r->v[0] <<= 1;
		r->v[M->n] = 0;
		if (top || cmpN(r->v, m->v, M->n) >= 0) subN(r->v, r->v, m->v, M->n);
	}
	return true;
}

// CIOS: r = a * b / R mod m
void bnMontMul(const BnMont *M, Bn *r, const Bn *a, const Bn *b)
{
	int n = M->n;
	u32 t[BN_N + 2];
	memset(t, 0, 4 * (n + 2));
	const u32 *m = M->m.v;
	for (int i = 0; i < n; i++) {
		u64 c = 0;
		u32 bi = b->v[i];
		for (int j = 0; j < n; j++) {
			c += (u64)a->v[j] * bi + t[j];
			t[j] = c;
			c >>= 32;
		}
		c += t[n];
		t[n] = c;
		t[n + 1] = c >> 32;
		u32 q = t[0] * M->minv;
		c = ((u64)q * m[0] + t[0]) >> 32;
		for (int j = 1; j < n; j++) {
			c += (u64)q * m[j] + t[j];
			t[j - 1] = c;
			c >>= 32;
		}
		c += t[n];
		t[n - 1] = c;
		t[n] = t[n + 1] + (c >> 32);
	}
	if (t[n] || cmpN(t, m, n) >= 0) subN(t, t, m, n);
	memset(r->v, 0, sizeof(r->v));
	memcpy(r->v, t, 4 * n);
}

void bnToMont(const BnMont *M, Bn *r, const Bn *a)
{
	static Bn t;
	if (bnCmp(a, &M->m) >= 0) bnMod(&t, a, &M->m);
	else t = *a;
	bnMontMul(M, r, &t, &M->rr);
}

void bnFromMont(const BnMont *M, Bn *r, const Bn *a)
{
	Bn one;
	bnSet(&one, 1);
	bnMontMul(M, r, a, &one);
}

void bnModAdd(const BnMont *M, Bn *r, const Bn *a, const Bn *b)
{
	u32 c = addN(r->v, a->v, b->v, M->n);
	if (c || cmpN(r->v, M->m.v, M->n) >= 0) subN(r->v, r->v, M->m.v, M->n);
}

void bnModSub(const BnMont *M, Bn *r, const Bn *a, const Bn *b)
{
	if (subN(r->v, a->v, b->v, M->n)) addN(r->v, r->v, M->m.v, M->n);
}

// 4-bit fixed window
void bnModExp(const BnMont *M, Bn *r, const Bn *a, const Bn *e)
{
	static Bn tab[16], acc;
	bnToMont(M, &tab[1], a);
	Bn one;
	bnSet(&one, 1);
	bnToMont(M, &tab[0], &one);
	for (int i = 2; i < 16; i++) bnMontMul(M, &tab[i], &tab[i - 1], &tab[1]);
	acc = tab[0];
	int bits = bnBits(e);
	for (int i = (bits + 3) / 4 - 1; i >= 0; i--) {
		for (int k = 0; k < 4; k++) bnMontMul(M, &acc, &acc, &acc);
		int w = e->v[i / 8] >> (4 * (i % 8)) & 15;
		if (w) bnMontMul(M, &acc, &acc, &tab[w]);
	}
	bnFromMont(M, r, &acc);
}

void bnModInvPrime(const BnMont *M, Bn *r, const Bn *a)
{
	Bn e, two;
	bnSet(&two, 2);
	bnSub(&e, &M->m, &two);
	bnModExp(M, r, a, &e);
}

// --- RSA ---

bool rsaExp(const u8 *n, u32 nLen, const u8 *e, u32 eLen, const u8 *in, u32 inLen, u8 *out)
{
	static BnMont M;
	static Bn m, x, y, ex;
	bnFromBytes(&m, n, nLen);
	bnFromBytes(&x, in, inLen);
	bnFromBytes(&ex, e, eLen);
	if (!bnMontInit(&M, &m) || bnCmp(&x, &m) >= 0) return false;
	bnModExp(&M, &y, &x, &ex);
	bnToBytes(&y, out, nLen);
	return true;
}

bool rsaCrt(const u8 *const part[5], const u16 partLen[5], const u8 *in, u32 inLen, u8 *out, u32 outLen)
{
	static BnMont P, Q;
	static Bn p, q, x, m1, m2, h, e;
	bnFromBytes(&p, part[0], partLen[0]);
	bnFromBytes(&q, part[1], partLen[1]);
	if (!bnMontInit(&P, &p) || !bnMontInit(&Q, &q)) return false;
	bnFromBytes(&x, in, inLen);
	bnMul(&h, &p, &q);
	if (bnCmp(&x, &h) >= 0) return false;
	bnFromBytes(&e, part[2], partLen[2]);
	bnModExp(&P, &m1, &x, &e);
	bnFromBytes(&e, part[3], partLen[3]);
	bnModExp(&Q, &m2, &x, &e);
	// h = qinv * (m1 - m2) mod p, x = m2 + h * q
	bnMod(&h, &m2, &p);
	bnModSub(&P, &h, &m1, &h);
	bnFromBytes(&e, part[4], partLen[4]);
	bnToMont(&P, &e, &e);
	bnToMont(&P, &h, &h);
	bnMontMul(&P, &h, &h, &e);
	bnFromMont(&P, &h, &h);
	bnMul(&x, &h, &q);
	bnAdd(&x, &x, &m2);
	bnToBytes(&x, out, outLen);
	return true;
}

// --- primes ---

static const u16 smallPrimes[] = { 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
	97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211,
	223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
	353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487,
	491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
	643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
	809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
	967, 971, 977, 983, 991, 997 };

// Miller-Rabin with the given bases
static bool probablePrime(const Bn *p, void (*rnd)(u8 *, u32), int rounds)
{
	static BnMont M;
	static Bn d, x, pm1, a;
	if (!bnMontInit(&M, p)) return false;
	Bn one;
	bnSet(&one, 1);
	bnSub(&pm1, p, &one);
	d = pm1;
	int s = 0;
	while (!(d.v[0] & 1)) bnShr1(&d), s++;
	int bytes = (bnBits(p) + 7) / 8;
	for (int r = 0; r < rounds; r++) {
		u8 b[4 * BN_N];
		rnd(b, bytes - 1); // a < p
		bnFromBytes(&a, b, bytes - 1);
		if (bnBits(&a) < 2) bnSet(&a, 2 + r);
		bnModExp(&M, &x, &a, &d);
		if (!bnCmp(&x, &one) || !bnCmp(&x, &pm1)) continue;
		bool ok = false;
		for (int i = 1; i < s && !ok; i++) {
			bnToMont(&M, &x, &x);
			bnMontMul(&M, &x, &x, &x);
			bnFromMont(&M, &x, &x);
			ok = !bnCmp(&x, &pm1);
		}
		if (!ok) return false;
	}
	return true;
}

void bnPrime(Bn *p, int bits, u32 e, void (*rnd)(u8 *, u32))
{
	int bytes = (bits + 7) / 8;
	for (;;) {
		u8 b[4 * BN_N];
		rnd(b, bytes);
		b[0] &= 0xFF >> (8 * bytes - bits);
		b[0] |= 0xC0 >> (8 * bytes - bits);
		b[bytes - 1] |= 1;
		bnFromBytes(p, b, bytes);
		// step by 2 through a range, small primes sieved by their remainders
		u16 rem[sizeof(smallPrimes) / 2];
		for (u32 i = 0; i < sizeof(smallPrimes) / 2; i++) rem[i] = bnModSmall(p, smallPrimes[i]);
		u32 er = bnModSmall(p, e);
		for (u32 step = 0; step < 4096; step += 2) {
			bool skip = (er + step) % e == 1; // p - 1 divisible by e
			for (u32 i = 0; i < sizeof(smallPrimes) / 2 && !skip; i++) skip = (rem[i] + step) % smallPrimes[i] == 0;
			if (skip) continue;
			Bn c, s;
			bnSet(&s, step);
			bnAdd(&c, p, &s);
			if (bnBits(&c) != bits) break;
			if (probablePrime(&c, rnd, 1) && probablePrime(&c, rnd, bits >= 1024 ? 3 : 6)) {
				*p = c;
				return;
			}
		}
	}
}

static u32 powSmall(u64 b, u32 e, u32 m)
{
	u64 r = 1;
	b %= m;
	for (; e; e >>= 1, b = b * b % m)
		if (e & 1) r = r * b % m;
	return r;
}

// k * m + 1 = 0 mod e: k = -m^-1 mod e, d = (k * m + 1) / e
bool bnInvSmall(Bn *d, u32 e, const Bn *m)
{
	u32 mr = bnModSmall(m, e);
	if (!mr) return false;
	u32 k = (e - powSmall(mr, e - 2, e)) % e;
	Bn t, one;
	bnMulSmall(&t, m, k);
	bnSet(&one, 1);
	bnAdd(&t, &t, &one);
	bnDivSmall(d, &t, e);
	return true;
}
