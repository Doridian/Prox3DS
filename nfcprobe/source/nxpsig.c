// ECDSA verification on secp128r1 / secp224r1 for NXP originality signatures, see nxpsig.h.
// Numbers are little-endian u32 limbs (up to 8); field and group order arithmetic in Montgomery form;
// points in Jacobian coordinates (a = -3).

#include <string.h>

#include "nxpsig.h"

#define NL 8 // limbs, enough for 256 bits

typedef u32 Num[NL];

typedef struct {
	int n;      // limbs in use
	Num m, r2;  // modulus, R^2 mod m (R = 2^(32 n))
	u32 inv;    // -m^-1 mod 2^32
} Mod;

typedef struct {
	u32 size;              // bytes per number
	const char *p, *n, *gx, *gy;
} Curve;

static const Curve curves[] = {
	{ 16, "FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", "FFFFFFFE0000000075A30D1B9038A115",
	  "161FF7528B899B2D0C28607CA52C5B86", "CF5AC8395BAFEB13C02DA292DDED7A83" },
	{ 28, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
	  "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
	  "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
	  "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34" },
};

// --- numbers ---

static void fromBytes(Num x, const u8 *b, u32 len)
{
	memset(x, 0, sizeof(Num));
	for (u32 i = 0; i < len && i < 4 * NL; i++) x[i / 4] |= (u32)b[len - 1 - i] << (8 * (i % 4));
}

static int hexVal(char c)
{
	return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
}

static void fromHex(Num x, const char *h)
{
	u8 b[4 * NL];
	u32 len = strlen(h) / 2;
	for (u32 i = 0; i < len; i++) b[i] = hexVal(h[2 * i]) << 4 | hexVal(h[2 * i + 1]);
	fromBytes(x, b, len);
}

static int cmp(const u32 *a, const u32 *b, int n)
{
	for (int i = n - 1; i >= 0; i--)
		if (a[i] != b[i]) return a[i] > b[i] ? 1 : -1;
	return 0;
}

static bool isZero(const u32 *a, int n)
{
	for (int i = 0; i < n; i++)
		if (a[i]) return false;
	return true;
}

static u32 addN(u32 *r, const u32 *a, const u32 *b, int n)
{
	u64 c = 0;
	for (int i = 0; i < n; i++) c += (u64)a[i] + b[i], r[i] = c, c >>= 32;
	return c;
}

static u32 subN(u32 *r, const u32 *a, const u32 *b, int n)
{
	s64 c = 0;
	for (int i = 0; i < n; i++) c += (s64)a[i] - b[i], r[i] = c, c >>= 32;
	return c ? 1 : 0;
}

// --- Montgomery arithmetic mod m ---

static void mmul(const Mod *M, u32 *r, const u32 *a, const u32 *b)
{
	int n = M->n;
	u32 t[NL + 2] = { 0 };
	for (int i = 0; i < n; i++) {
		u64 c = 0;
		for (int j = 0; j < n; j++) c += (u64)a[j] * b[i] + t[j], t[j] = c, c >>= 32;
		c += t[n], t[n] = c, t[n + 1] = c >> 32;
		u32 q = t[0] * M->inv;
		c = ((u64)q * M->m[0] + t[0]) >> 32;
		for (int j = 1; j < n; j++) c += (u64)q * M->m[j] + t[j], t[j - 1] = c, c >>= 32;
		c += t[n], t[n - 1] = c, t[n] = t[n + 1] + (c >> 32);
	}
	if (t[n] || cmp(t, M->m, n) >= 0) subN(t, t, M->m, n);
	memcpy(r, t, n * 4);
}

static void madd(const Mod *M, u32 *r, const u32 *a, const u32 *b)
{
	if (addN(r, a, b, M->n) || cmp(r, M->m, M->n) >= 0) subN(r, r, M->m, M->n);
}

static void msub(const Mod *M, u32 *r, const u32 *a, const u32 *b)
{
	if (subN(r, a, b, M->n)) addN(r, r, M->m, M->n);
}

static void modInit(Mod *M, const char *hex, int limbs)
{
	memset(M, 0, sizeof(*M));
	M->n = limbs;
	fromHex(M->m, hex);
	u32 x = 1; // m^-1 mod 2^32 by Newton, then negated
	for (int i = 0; i < 5; i++) x *= 2 - M->m[0] * x;
	M->inv = -x;
	// R^2 mod m: 1 doubled 2 * 32 n times
	Num r = { 1 };
	for (int i = 0; i < 64 * limbs; i++) madd(M, r, r, r);
	memcpy(M->r2, r, sizeof(Num));
}

static void toMont(const Mod *M, u32 *r, const u32 *a)
{
	mmul(M, r, a, M->r2);
}

static void fromMont(const Mod *M, u32 *r, const u32 *a)
{
	Num one = { 1 };
	mmul(M, r, a, one);
}

// a^-1 = a^(m-2) (m prime), Montgomery in and out
static void minv(const Mod *M, u32 *r, const u32 *a)
{
	Num e, two = { 2 }, x, one = { 1 };
	subN(e, M->m, two, M->n);
	toMont(M, x, one);
	for (int i = 32 * M->n - 1; i >= 0; i--) {
		mmul(M, x, x, x);
		if (e[i / 32] >> (i % 32) & 1) mmul(M, x, x, a);
	}
	memcpy(r, x, M->n * 4);
}

// --- points (Jacobian, Montgomery coordinates; Z = 0 is the point at infinity) ---

typedef struct {
	Num x, y, z;
} Pt;

static void dbl(const Mod *F, Pt *r, const Pt *p)
{
	int n = F->n;
	if (isZero(p->z, n) || isZero(p->y, n)) {
		memset(r, 0, sizeof(*r));
		return;
	}
	Num delta, gamma, beta, alpha, t, u;
	mmul(F, delta, p->z, p->z);
	mmul(F, gamma, p->y, p->y);
	mmul(F, beta, p->x, gamma);
	msub(F, t, p->x, delta);
	madd(F, u, p->x, delta);
	mmul(F, alpha, t, u);
	madd(F, t, alpha, alpha);
	madd(F, alpha, t, alpha); // 3 (x - delta)(x + delta)
	Pt q;
	// Z3 = (Y + Z)^2 - gamma - delta
	madd(F, t, p->y, p->z);
	mmul(F, t, t, t);
	msub(F, t, t, gamma);
	msub(F, q.z, t, delta);
	// X3 = alpha^2 - 8 beta
	madd(F, u, beta, beta);
	madd(F, u, u, u);         // 4 beta
	madd(F, t, u, u);         // 8 beta
	mmul(F, q.x, alpha, alpha);
	msub(F, q.x, q.x, t);
	// Y3 = alpha (4 beta - X3) - 8 gamma^2
	msub(F, u, u, q.x);
	mmul(F, q.y, alpha, u);
	mmul(F, t, gamma, gamma);
	madd(F, t, t, t);
	madd(F, t, t, t);
	madd(F, t, t, t);
	msub(F, q.y, q.y, t);
	*r = q;
}

static void add(const Mod *F, Pt *r, const Pt *p, const Pt *q)
{
	int n = F->n;
	if (isZero(p->z, n)) {
		*r = *q;
		return;
	}
	if (isZero(q->z, n)) {
		*r = *p;
		return;
	}
	Num z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t;
	mmul(F, z1z1, p->z, p->z);
	mmul(F, z2z2, q->z, q->z);
	mmul(F, u1, p->x, z2z2);
	mmul(F, u2, q->x, z1z1);
	mmul(F, s1, p->y, q->z);
	mmul(F, s1, s1, z2z2);
	mmul(F, s2, q->y, p->z);
	mmul(F, s2, s2, z1z1);
	msub(F, h, u2, u1);
	msub(F, rr, s2, s1);
	if (isZero(h, n)) {
		if (isZero(rr, n)) dbl(F, r, p);
		else memset(r, 0, sizeof(*r));
		return;
	}
	Pt o;
	madd(F, i, h, h);
	mmul(F, i, i, i);         // (2h)^2
	mmul(F, j, h, i);
	madd(F, rr, rr, rr);      // 2 (s2 - s1)
	mmul(F, v, u1, i);
	// X3 = r^2 - J - 2V
	mmul(F, o.x, rr, rr);
	msub(F, o.x, o.x, j);
	msub(F, o.x, o.x, v);
	msub(F, o.x, o.x, v);
	// Y3 = r (V - X3) - 2 S1 J
	msub(F, t, v, o.x);
	mmul(F, o.y, rr, t);
	mmul(F, t, s1, j);
	madd(F, t, t, t);
	msub(F, o.y, o.y, t);
	// Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) H
	madd(F, t, p->z, q->z);
	mmul(F, t, t, t);
	msub(F, t, t, z1z1);
	msub(F, t, t, z2z2);
	mmul(F, o.z, t, h);
	*r = o;
}

// --- ECDSA ---

bool ecdsaVerify(u32 size, const u8 *pub, const u8 *data, u32 len, const u8 *sig)
{
	const Curve *c = size == 16 ? &curves[0] : size == 28 ? &curves[1] : NULL;
	if (!c || pub[0] != 0x04) return false;
	int limbs = (size + 3) / 4;
	Mod F, N;
	modInit(&F, c->p, limbs);
	modInit(&N, c->n, limbs);
	Num r, s, e;
	fromBytes(r, sig, size);
	fromBytes(s, sig + size, size);
	if (isZero(r, limbs) || isZero(s, limbs) || cmp(r, N.m, limbs) >= 0 || cmp(s, N.m, limbs) >= 0) return false;
	fromBytes(e, data, len < size ? len : size); // longer data: its leading bytes (n's bit length = 8 * size here)
	if (cmp(e, N.m, limbs) >= 0) subN(e, e, N.m, limbs);
	// w = s^-1, u1 = e w, u2 = r w (mod n)
	Num w, u1, u2, t;
	toMont(&N, t, s);
	minv(&N, w, t);           // Montgomery
	mmul(&N, u1, e, w);       // e w R^-1 R = e w: plain
	mmul(&N, u2, r, w);
	// u1 G + u2 Q, both bits at a time (Shamir)
	Pt G, Q, GQ, X;
	Num one = { 1 };
	fromHex(t, c->gx), toMont(&F, G.x, t);
	fromHex(t, c->gy), toMont(&F, G.y, t);
	fromBytes(t, pub + 1, size), toMont(&F, Q.x, t);
	fromBytes(t, pub + 1 + size, size), toMont(&F, Q.y, t);
	toMont(&F, G.z, one);
	memcpy(Q.z, G.z, sizeof(Num));
	add(&F, &GQ, &G, &Q);
	memset(&X, 0, sizeof(X));
	for (int b = 32 * limbs - 1; b >= 0; b--) {
		dbl(&F, &X, &X);
		bool b1 = u1[b / 32] >> (b % 32) & 1, b2 = u2[b / 32] >> (b % 32) & 1;
		if (b1 && b2) add(&F, &X, &X, &GQ);
		else if (b1) add(&F, &X, &X, &G);
		else if (b2) add(&F, &X, &X, &Q);
	}
	if (isZero(X.z, limbs)) return false;
	// affine x = X / Z^2, then mod n
	Num zi, x;
	minv(&F, zi, X.z);
	mmul(&F, zi, zi, zi);
	mmul(&F, x, X.x, zi);
	fromMont(&F, x, x);
	if (cmp(x, N.m, limbs) >= 0) subN(x, x, N.m, limbs);
	return !cmp(x, r, limbs);
}

// --- NXP keys (pm3 originality.c) ---

static const struct {
	int family;
	const char *name, *key; // 04 || X || Y
} keys[] = {
	{ SIG_MFU, "NXP Ultralight EV1", "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8" },
	{ SIG_MFU, "NXP NTAG21x", "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61" },
	{ SIG_MFU, "NXP (TagInfo key)", "04A748B6A632FBEE2C0897702B33BEA1C074998E17B84ACA04FF267E5D2C91F6DC" },
	{ SIG_DESFIRE, "DESFire EV3", "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743" },
	{ SIG_DESFIRE, "DESFire EV2 / NTAG 424 DNA", "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A" },
	{ SIG_DESFIRE, "DESFire EV2 / NTAG 424 DNA (AN12196)", "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410" },
	{ SIG_DESFIRE, "DESFire EV2 XL", "04CD5D45E50B1502F0BA4656FF37669597E7E183251150F9574CC8DA56BF01C7ABE019E29FEA48F9CE22C3EA4029A765E1BC95A89543BAD1BC" },
	{ SIG_DESFIRE, "DESFire EV1 / NTAG 413 DNA", "04BB5D514F7050025C7D0F397310360EEC91EAF792E96FC7E0F496CB4E669D414F877B7B27901FE67C2E3B33CD39D1C797715189AC951C2ADD" },
	{ SIG_DESFIRE, "DESFire Light", "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D" },
};

const char *nxpSigCheck(int family, const u8 *uid, u32 uidLen, const u8 *sig, u32 sigLen)
{
	u32 size = sigLen / 2;
	bool zero = true;
	for (u32 i = 0; i < sigLen; i++) zero &= !sig[i];
	if (zero || (size != 16 && size != 28)) return NULL;
	for (u32 k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
		if (keys[k].family != family) continue;
		u8 pub[57];
		u32 len = strlen(keys[k].key) / 2;
		if (len != 1 + 2 * size) continue;
		for (u32 i = 0; i < len; i++) pub[i] = hexVal(keys[k].key[2 * i]) << 4 | hexVal(keys[k].key[2 * i + 1]);
		if (ecdsaVerify(size, pub, uid, uidLen, sig)) return keys[k].name;
	}
	return NULL;
}
