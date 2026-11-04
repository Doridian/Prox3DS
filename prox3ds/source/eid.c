// ID documents: EF.CardAccess and friends, PACE, secure messaging; see eid.h. Checked against the German ID
// card and tools/exp/eid/pace.py (the same protocol in Python over a Proxmark3).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ecc.h"
#include "eid.h"
#include "iso7816.h"
#include "probe.h"
#include "sha1.h"
#include "ui.h"

static char why[96];

const char *eidWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

// bsi-de 0.4.0.127.0.7, then 2.2.x (protocols) as DER contents
static const u8 bsiProto[] = { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02 };

// --- EF.CardAccess: SecurityInfos (a SET of SEQUENCE { OID, INTEGER version, ... }) ---

static int derInt(const Tlv *t)
{
	if (t->tag != 0x02 || !t->len || t->len > 3) return -1;
	int v = 0;
	for (u32 i = 0; i < t->len; i++) v = v << 8 | t->v[i];
	return v;
}

static void parseInfos(EidCard *e, const u8 *p, u32 len, bool privileged, int depth)
{
	const u8 *end = p + len;
	Tlv s;
	while (tlvNext(&p, end, &s) && e->ninfo < EID_MAX_INFO) {
		if (s.tag != 0x30) continue;
		const u8 *q = s.v, *qe = s.v + s.len;
		Tlv oid, a, b;
		if (!tlvNext(&q, qe, &oid) || oid.tag != 0x06 || oid.len > 16) continue;
		bool bsi = oid.len >= 8 && !memcmp(oid.v, bsiProto, sizeof(bsiProto));
		u8 proto = bsi ? oid.v[7] : 0;
		if (bsi && proto == 8 && depth == 0) { // PrivilegedTerminalInfo: a SET of SecurityInfos inside
			if (tlvNext(&q, qe, &a) && a.tag == 0x31) parseInfos(e, a.v, a.len, true, depth + 1);
			continue;
		}
		EidInfo *i = &e->info[e->ninfo++];
		memset(i, 0, sizeof(*i));
		i->privileged = privileged;
		i->oidLen = oid.len;
		memcpy(i->oid, oid.v, oid.len);
		i->version = i->param = i->keyId = -1;
		i->kind = !bsi ? EI_OTHER : proto == 4 ? EI_PACE : proto == 3 ? EI_CA : proto == 2 ? EI_TA :
			proto == 5 ? EI_RI : proto == 6 ? EI_CARDINFO : proto == 7 ? EI_EIDSEC : EI_OTHER;
		if (!tlvNext(&q, qe, &a)) continue;
		if (i->kind == EI_CARDINFO) {
			if (a.tag == 0x16) snprintf(i->url, sizeof(i->url), "%.*s", (int)a.len, (const char *)a.v);
			continue;
		}
		if (a.tag == 0x30) {
			// a DomainParameterInfo: { AlgorithmIdentifier { OID, standardized id }, keyId }
			if (i->kind == EI_PACE) i->kind = EI_PACE_DP;
			if (i->kind == EI_CA) i->kind = EI_CA_DP;
			const u8 *r = a.v, *re = a.v + a.len;
			Tlv x;
			if (tlvNext(&r, re, &x) && x.tag == 0x06 && tlvNext(&r, re, &x)) i->param = derInt(&x);
			if (tlvNext(&q, qe, &b)) i->keyId = derInt(&b);
			continue;
		}
		i->version = derInt(&a);
		if (!tlvNext(&q, qe, &b)) continue;
		// PACEInfo: parameterId; ChipAuthenticationInfo: keyId; others: protocol-specific
		if (i->kind == EI_PACE) i->param = derInt(&b);
		else if (i->kind == EI_CA) i->keyId = derInt(&b);
	}
}

// --- curves (standardized domain parameters, TR-03110 part 3 A.2.1.1) ---

typedef struct {
	int id;
	const char *name, *p, *a, *b, *gx, *gy, *n;
} CurveDef;

static const CurveDef curves[] = {
	{ 12, "NIST P-256",
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
		"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
		"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
		"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
		"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
		"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551" },
	{ 13, "brainpoolP256r1",
		"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
		"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
		"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
		"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
		"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
		"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7" },
};

static const char *const paramNames[] = {
	[0] = "1024-bit MODP", [1] = "2048-bit MODP (224)", [2] = "2048-bit MODP (256)",
	[8] = "NIST P-192", [9] = "brainpoolP192r1", [10] = "NIST P-224", [11] = "brainpoolP224r1",
	[12] = "NIST P-256", [13] = "brainpoolP256r1", [14] = "brainpoolP320r1", [15] = "NIST P-384",
	[16] = "brainpoolP384r1", [17] = "brainpoolP512r1", [18] = "NIST P-521",
};

const char *eidParamName(int param)
{
	if (param < 0 || param >= (int)(sizeof(paramNames) / sizeof(*paramNames))) return NULL;
	return paramNames[param];
}

static const CurveDef *curveFor(int param)
{
	for (u32 i = 0; i < sizeof(curves) / sizeof(*curves); i++)
		if (curves[i].id == param) return &curves[i];
	return NULL;
}

static bool curveInit(EcCurve *c, const CurveDef *d)
{
	u8 p[32], a[32], b[32], g[65], n[32];
	scUnhex(d->p, p, 32), scUnhex(d->a, a, 32), scUnhex(d->b, b, 32), scUnhex(d->n, n, 32);
	g[0] = 4;
	scUnhex(d->gx, g + 1, 32), scUnhex(d->gy, g + 33, 32);
	return ecCurveInit(c, p, 32, a, 32, b, 32, g, 65, n, 32);
}

// PACE-ECDH-GM with AES: id-PACE 4.2.{2,3,4} = AES-128 / 192 / 256. Its key length, 0 = not one we do.
static u32 paceKeyLen(const EidInfo *i)
{
	if (i->kind != EI_PACE || i->oidLen != 10 || i->oid[8] != 2) return 0;
	if (!curveFor(i->param)) return 0;
	return i->oid[9] == 2 ? 16 : i->oid[9] == 3 ? 24 : i->oid[9] == 4 ? 32 : 0;
}

// --- plain file reads ---

// READ BINARY of a short EF by SFI, whole (its length from the first TLV). Length, -1 lost, -2 monitor;
// *sw the card's answer when it refused.
static int readSfi(u8 sfi, u8 *out, u32 max, u16 *sw)
{
	int n = scCmd(0x00, 0xB0, 0x80 | sfi, 0, NULL, 0, true, out, max, sw);
	if (n < 0) return n == -2 ? -2 : -1;
	if (*sw != 0x9000) return 0;
	u32 total = n;
	if (n >= 2) {
		// the length from the header, even when the value is cut off
		u32 h = (out[0] & 0x1F) == 0x1F ? 2 : 1, l = out[h];
		total = l < 0x80 ? h + 1 + l : l == 0x81 ? h + 2 + out[h + 1] : l == 0x82 ? h + 3 + (out[h + 1] << 8 | out[h + 2]) : (u32)n;
	}
	if (total > max) total = max;
	if ((u32)n > total) n = total; // a whole-file read brings padding after the TLV
	while ((u32)n < total) {
		u8 buf[256];
		int k = scCmd(0x00, 0xB0, n >> 8, n & 0xFF, NULL, 0, true, buf, sizeof(buf), sw);
		if (k < 0) return k == -2 ? -2 : -1;
		if (*sw != 0x9000 || !k) break;
		if ((u32)k > total - n) k = total - n;
		memcpy(out + n, buf, k);
		n += k;
	}
	*sw = 0x9000;
	return n;
}

// SELECT EF by file id (P2 0C: no answer data) and READ BINARY. Length, 0 refused, -1 lost, -2 monitor.
static int readFid(u16 fid, u8 *out, u32 max)
{
	u8 f[2] = { fid >> 8, fid & 0xFF };
	u16 sw;
	int n = scCmd(0x00, 0xA4, 0x02, 0x0C, f, 2, false, out, max, &sw);
	if (n < 0) return n;
	if (sw != 0x9000) return 0;
	n = scCmd(0x00, 0xB0, 0, 0, NULL, 0, true, out, max, &sw);
	if (n < 0) return n;
	return sw == 0x9000 ? n : 0;
}

static int mseSetAt(const EidInfo *pace, u8 ref, u16 *sw)
{
	u8 d[2 + 16 + 3], b[64];
	u32 n = 0;
	d[n++] = 0x80, d[n++] = pace->oidLen;
	memcpy(d + n, pace->oid, pace->oidLen), n += pace->oidLen;
	d[n++] = 0x83, d[n++] = 1, d[n++] = ref;
	return scCmd(0x00, 0x22, 0xC1, 0xA4, d, n, false, b, sizeof(b), sw);
}

bool eidParseAccess(EidCard *e, const u8 *p, u32 len)
{
	e->accessLen = e->ninfo = 0;
	e->pace = -1;
	if (len > sizeof(e->access) || !len || p[0] != 0x31) return false;
	memmove(e->access, p, len);
	e->accessLen = len;
	Tlv set;
	const u8 *q = e->access;
	if (tlvNext(&q, e->access + len, &set)) parseInfos(e, set.v, set.len, false, 0);
	for (int i = 0; i < e->ninfo; i++)
		if (e->pace < 0 && paceKeyLen(&e->info[i])) e->pace = i;
	return true;
}

int eidRead(EidCard *e)
{
	static u8 buf[1024];
	memset(e, 0, sizeof(*e));
	e->pace = -1;
	*why = 0;
	int r = scActivate(e->ats, sizeof(e->ats));
	if (r <= 0) FAIL(r, "ISO-DEP: %s", scWhy());
	e->atsLen = e->ats[0] < sizeof(e->ats) ? e->ats[0] : sizeof(e->ats);
#define LOST(n) do { if ((n) == -2) FAIL(-1, "monitor"); if ((n) < 0) FAIL(0, "card lost: %s", scWhy()); } while (0)

	u16 sw;
	int n = readSfi(0x1C, e->access, sizeof(e->access), &sw);
	LOST(n);
	logp("EF.CardAccess: %d bytes, %04X\n", n, sw);
	if (n > 0) eidParseAccess(e, e->access, n);

	// EF.DIR (2F00): 61 { 4F AID } records
	n = readFid(0x2F00, buf, sizeof(buf));
	LOST(n);
	const u8 *p = buf;
	Tlv t, a;
	while (n > 0 && tlvNext(&p, buf + n, &t) && e->napps < EID_MAX_APPS)
		if (t.tag == 0x61 && tlvFind(t.v, t.len, 0x4F, &a) && a.len <= 16) {
			e->app[e->napps].aidLen = a.len;
			memcpy(e->app[e->napps].aid, a.v, a.len);
			Tlv l;
			if (tlvFind(t.v, t.len, 0x50, &l))
				snprintf(e->app[e->napps].label, sizeof(e->app[0].label), "%.*s", (int)l.len, (const char *)l.v);
			e->napps++;
		}
	// EF.ATR/INFO (2F01): 7F66 extended length info { 02 max command, 02 max answer }
	n = readFid(0x2F01, buf, sizeof(buf));
	LOST(n);
	if (n > 0 && tlvFind(buf, n, 0x7F66, &t)) {
		const u8 *q = t.v;
		Tlv x;
		if (tlvNext(&q, t.v + t.len, &x)) e->extIn = derInt(&x) < 0 ? 0 : derInt(&x);
		if (tlvNext(&q, t.v + t.len, &x)) e->extOut = derInt(&x) < 0 ? 0 : derInt(&x);
	}

	// the eID PIN's state: MSE:Set AT with it answers 9000 / 63Cx / 6283, no try used
	if (e->pace >= 0) {
		n = mseSetAt(&e->info[e->pace], EID_PIN, &sw);
		LOST(n);
		e->pinSw = sw;
		logp("PIN state (MSE:Set AT): %04X\n", sw);
	}
	return 1;
#undef LOST
}

// --- PACE ---

static void rnd(u8 *p, u32 n)
{
	if (R_FAILED(psInit()) || R_FAILED(PS_GenerateRandomBytes(p, n)))
		for (u32 i = 0; i < n; i++) p[i] = rand();
	psExit();
}

// KDF (TR-03110 part 3 A.2.3): SHA-1 for 3DES / AES-128, SHA-256 for AES-192 / 256
static void kdf(const u8 *s, u32 len, u32 ctr, u32 keyLen, u8 *out)
{
	u8 c[4] = { ctr >> 24, ctr >> 16, ctr >> 8, ctr }, h[32];
	if (keyLen == 16) {
		Sha1 x;
		sha1Init(&x), sha1Add(&x, s, len), sha1Add(&x, c, 4), sha1Done(&x, h);
	} else {
		Sha256 x;
		sha256Init(&x), sha256Add(&x, s, len), sha256Add(&x, c, 4), sha256Done(&x, h);
	}
	memcpy(out, h, keyLen);
}

static u8 aesType(u32 keyLen)
{
	return keyLen == 16 ? DF_AES : keyLen == 24 ? DF_AES192 : DF_AES256;
}

static void cmac8(const DfCipher *c, const u8 *p, u32 len, u8 *mac)
{
	u8 iv[16] = { 0 }, m[16];
	dfCmac(c, iv, p, len, m);
	memcpy(mac, m, 8);
}

// General Authenticate, one step: 7C { inner }; the answer's 7C contents into out. Length, -1 lost,
// -2 monitor; *sw the card's status.
static int ga(bool last, const u8 *inner, u32 len, u8 *out, u32 max, u16 *sw)
{
	u8 d[160], a[200];
	d[0] = 0x7C, d[1] = len;
	memcpy(d + 2, inner, len);
	int n = scCmd(last ? 0x00 : 0x10, 0x86, 0, 0, d, len + 2, true, a, sizeof(a), sw);
	if (n < 0) return n;
	if (*sw != 0x9000) return 0;
	Tlv t;
	if (!tlvFind(a, n, 0x7C, &t) || t.len > max) return 0;
	memcpy(out, t.v, t.len);
	return t.len;
}

// a point: 86 / 81 / 83 tag, 04 x y
static u32 dataObj(u8 *out, u8 tag, const u8 *v, u32 len)
{
	out[0] = tag, out[1] = len;
	memcpy(out + 2, v, len);
	return len + 2;
}

static bool getObj(const u8 *p, u32 len, u8 tag, u8 *out, u32 want)
{
	Tlv t;
	if (!tlvFind(p, len, tag, &t) || t.len != want) return false;
	memcpy(out, t.v, want);
	return true;
}

// the authentication token: CMAC over 7F49 { 06 OID, 86 the other side's point }
static void token(const DfCipher *mac, const EidInfo *pi, const u8 *pt, u32 ptLen, u8 *out)
{
	u8 d[160];
	u32 n = 0, inner = 2 + pi->oidLen + 2 + ptLen;
	d[n++] = 0x7F, d[n++] = 0x49, d[n++] = inner;
	d[n++] = 0x06, d[n++] = pi->oidLen;
	memcpy(d + n, pi->oid, pi->oidLen), n += pi->oidLen;
	n += dataObj(d + n, 0x86, pt, ptLen);
	cmac8(mac, d, n, out);
}

int eidPace(const EidCard *e, u8 ref, const char *pwd, EidSm *sm)
{
	static EcCurve c;
	static Bn s, sk;
	static u8 ans[160], pt[65], pkc[65], gm[65], pk2[65], k[32], d[80];
	*why = 0;
	if (e->pace < 0) FAIL(0, "no PACE variant this app does (ECDH generic mapping, AES)");
	const EidInfo *pi = &e->info[e->pace];
	u32 kl = paceKeyLen(pi);
	if (!curveInit(&c, curveFor(pi->param))) FAIL(0, "curve setup");
	u32 pl = 1 + 2 * c.len;

	u8 ats[32];
	int r = scActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "ISO-DEP: %s", scWhy());
#define LOST(n) do { if ((n) == -2) FAIL(-1, "monitor"); if ((n) < 0) FAIL(0, "card lost: %s", scWhy()); } while (0)
#define STEP(name, n, sw) do { LOST(n); if (!(n)) FAIL(0, "%s: %04X %s", name, sw, scSwName(sw)); } while (0)
	u16 sw;
	int n = mseSetAt(pi, ref, &sw);
	LOST(n);
	if (sw != 0x9000 && (sw & 0xFFF0) != 0x63C0) FAIL(0, "MSE:Set AT: %04X %s", sw, scSwName(sw));

	// 1. the encrypted nonce, decrypted with K(pi)
	n = ga(false, NULL, 0, ans, sizeof(ans), &sw);
	STEP("nonce", n, sw);
	u8 z[32], kpi[32], iv[16] = { 0 };
	if (!getObj(ans, n, 0x80, z, 16)) FAIL(0, "nonce: no 16-byte 80");
	kdf((const u8 *)pwd, strlen(pwd), 3, kl, kpi);
	DfCipher kc;
	dfCipherInit(&kc, aesType(kl), kpi);
	dfCbc(&kc, iv, z, 16, false);
	bnFromBytes(&s, z, 16);

	// 2. mapping: H = sk1 * PKc1, G' = s G + H
	ecRandomScalar(&c, &sk, rnd);
	ecPublic(&c, &sk, pt);
	n = ga(false, d, dataObj(d, 0x81, pt, pl), ans, sizeof(ans), &sw);
	STEP("mapping", n, sw);
	if (!getObj(ans, n, 0x82, pkc, pl)) FAIL(0, "mapping: no point from the card");
	if (!ecdh(&c, &sk, pkc, pl, pt, true)) FAIL(0, "mapping: the card's point is not on the curve");
	if (!ecPaceGm(&c, &s, pt, pl, gm)) FAIL(0, "mapping: G' at infinity");

	// 3. key agreement on G': PK2 = sk2 G', K = x(sk2 PKc2)
	ecRandomScalar(&c, &sk, rnd);
	if (!ecdh(&c, &sk, gm, pl, pk2, true)) FAIL(0, "key agreement: G'");
	n = ga(false, d, dataObj(d, 0x83, pk2, pl), ans, sizeof(ans), &sw);
	STEP("key agreement", n, sw);
	if (!getObj(ans, n, 0x84, pkc, pl)) FAIL(0, "key agreement: no point from the card");
	if (!memcmp(pkc, pk2, pl)) FAIL(0, "key agreement: the card sent our own point back");
	if (!ecdh(&c, &sk, pkc, pl, k, false)) FAIL(0, "key agreement: the card's point is not on the curve");
	u8 ke[32], km[32];
	kdf(k, c.len, 1, kl, ke);
	kdf(k, c.len, 2, kl, km);
	memset(sm, 0, sizeof(*sm));
	dfCipherInit(&sm->enc, aesType(kl), ke);
	dfCipherInit(&sm->mac, aesType(kl), km);

	// 4. mutual authentication: tokens over the other side's point
	u8 t[8], tc[8];
	token(&sm->mac, pi, pkc, pl, t);
	n = ga(true, d, dataObj(d, 0x85, t, 8), ans, sizeof(ans), &sw);
	LOST(n);
	if (sw == 0x6300 || (sw & 0xFFF0) == 0x63C0) FAIL(2, "the card refused our token (%04X): wrong password", sw);
	STEP("mutual authentication", n, sw);
	token(&sm->mac, pi, pk2, pl, t);
	if (!getObj(ans, n, 0x86, tc, 8) || memcmp(t, tc, 8)) FAIL(2, "the card's token is wrong");
	logp("PACE done (%s, AES-%lu)\n", eidParamName(pi->param), kl * 8);
	return 1;
#undef STEP
#undef LOST
}

// --- secure messaging (ICAO 9303-11 9.8, AES: SSC 16 bytes, IV = E(KEnc, SSC)) ---

static void sscInc(EidSm *sm)
{
	for (int i = 15; i >= 0 && !++sm->ssc[i]; i--);
}

static u32 pad16(u8 *p, u32 n)
{
	p[n++] = 0x80;
	while (n % 16) p[n++] = 0;
	return n;
}

static u32 putLen(u8 *p, u32 len)
{
	if (len < 0x80) return p[0] = len, 1;
	if (len < 0x100) return p[0] = 0x81, p[1] = len, 2;
	return p[0] = 0x82, p[1] = len >> 8, p[2] = len, 3;
}

int eidSmCmd(EidSm *sm, u8 ins, u8 p1, u8 p2, const u8 *data, u32 lc, bool le, u8 *out, u32 max, u16 *sw)
{
	static u8 c[300], m[320], a[SC_MAX_ANS];
	if (lc > 200) FAIL(-1, "SM: %lu bytes of data", lc);
	u8 hdr[4] = { 0x0C, ins, p1, p2 }, iv[16];
	sscInc(sm);
	u32 dl = 0;
	u8 dos[260];
	if (lc) {
		u8 enc[224];
		memcpy(enc, data, lc);
		u32 el = pad16(enc, lc);
		memcpy(iv, sm->ssc, 16);
		dfBlock(&sm->enc, iv, true);
		dfCbc(&sm->enc, iv, enc, el, true);
		dos[dl++] = 0x87;
		dl += putLen(dos + dl, el + 1);
		dos[dl++] = 0x01;
		memcpy(dos + dl, enc, el), dl += el;
	}
	if (le) dos[dl++] = 0x97, dos[dl++] = 1, dos[dl++] = 0;
	// MAC over SSC || pad(header) || pad(DOs)
	u32 ml = 0;
	memcpy(m, sm->ssc, 16), ml = 16;
	memcpy(m + ml, hdr, 4), ml = pad16(m, ml + 4);
	if (dl) memcpy(m + ml, dos, dl), ml = pad16(m, ml + dl);
	u32 cl = 0;
	memcpy(c, hdr, 4), cl = 4;
	c[cl++] = dl + 10;
	memcpy(c + cl, dos, dl), cl += dl;
	c[cl++] = 0x8E, c[cl++] = 8;
	cmac8(&sm->mac, m, ml, c + cl), cl += 8;
	c[cl++] = 0;
	int n = scApdu(c, cl, a, sizeof(a), sw);
	if (n < 0) FAIL(n == -2 ? -2 : -1, "%s", n == -2 ? "monitor" : scWhy());
	sscInc(sm);
	if (!n) return 0; // a plain error status: the card dropped the session
	// the answer: [87 01 enc] 99 SW 8E MAC
	Tlv t87 = { 0 }, t99 = { 0 }, t8e = { 0 }, t;
	const u8 *p = a, *pe = a + n, *macEnd = a;
	while (tlvNext(&p, pe, &t)) {
		if (t.tag == 0x87) t87 = t, macEnd = p;
		else if (t.tag == 0x99) t99 = t, macEnd = p;
		else if (t.tag == 0x8E) t8e = t;
	}
	if (!t99.v || t99.len != 2 || !t8e.v || t8e.len != 8) FAIL(-1, "SM answer without 99 / 8E");
	static u8 mm[SC_MAX_ANS + 48];
	u32 mml = 16;
	memcpy(mm, sm->ssc, 16);
	memcpy(mm + mml, a, macEnd - a), mml = pad16(mm, mml + (macEnd - a));
	u8 mac[8];
	cmac8(&sm->mac, mm, mml, mac);
	if (memcmp(mac, t8e.v, 8)) FAIL(-1, "SM answer: wrong MAC");
	*sw = t99.v[0] << 8 | t99.v[1];
	if (!t87.v) return 0;
	if (t87.len < 17 || t87.v[0] != 0x01 || (t87.len - 1) % 16) FAIL(-1, "SM answer: bad 87");
	u32 el = t87.len - 1;
	static u8 dec[SC_MAX_ANS];
	memcpy(dec, t87.v + 1, el);
	memcpy(iv, sm->ssc, 16);
	dfBlock(&sm->enc, iv, true);
	dfCbc(&sm->enc, iv, dec, el, false);
	while (el && !dec[el - 1]) el--;
	if (!el || dec[el - 1] != 0x80) FAIL(-1, "SM answer: bad padding");
	el--;
	u32 k = el < max ? el : max;
	memcpy(out, dec, k);
	return k;
}

// --- in words ---

const char *eidAppName(const u8 *aid, u32 len)
{
	static const struct {
		const char *hex, *name;
	} apps[] = {
		{ "E80704007F00070302", "eID" },
		{ "A0000002471001", "ePass" },
		{ "A000000167455349474E", "eSign" },
		{ "A0000002472001", "ICAO LDS2" },
	};
	for (u32 i = 0; i < sizeof(apps) / sizeof(*apps); i++) {
		u8 b[16];
		int n = scUnhex(apps[i].hex, b, sizeof(b));
		if ((u32)n == len && !memcmp(b, aid, len)) return apps[i].name;
	}
	return NULL;
}

static const char *aesName(u8 v)
{
	return v == 1 ? "3DES" : v == 2 ? "AES-128" : v == 3 ? "AES-192" : v == 4 ? "AES-256" : "?";
}

void eidInfoText(const EidInfo *i, char *out, u32 max)
{
	char p[48] = "", v[16] = "";
	const char *pn = eidParamName(i->param);
	if (pn) snprintf(p, sizeof(p), ", %s", pn);
	else if (i->param >= 0) snprintf(p, sizeof(p), ", parameters %d", i->param);
	if (i->version >= 0) snprintf(v, sizeof(v), " v%d", i->version);
	u8 a = i->oidLen > 8 ? i->oid[8] : 0, b = i->oidLen > 9 ? i->oid[9] : 0;
	switch (i->kind) {
	case EI_PACE: {
		static const char *const map[] = { "?", "DH generic mapping", "ECDH generic mapping", "DH integrated mapping",
			"ECDH integrated mapping", "?", "ECDH chip authentication mapping" };
		snprintf(out, max, "PACE%s: %s, %s%s", v, a < 7 ? map[a] : "?", aesName(b), p);
		break;
	}
	case EI_PACE_DP: snprintf(out, max, "PACE domain parameters%s%s", *p ? ":" : "", p + (*p ? 1 : 0)); break;
	case EI_CA:
		snprintf(out, max, "Chip authentication%s: %s, %s", v, a == 1 ? "DH" : a == 2 ? "ECDH" : "?", aesName(b));
		if (i->keyId >= 0) snprintf(out + strlen(out), max - strlen(out), ", key %d", i->keyId);
		break;
	case EI_CA_DP:
		snprintf(out, max, "Chip authentication key%s%s", *p ? ":" : "", p + (*p ? 1 : 0));
		if (i->keyId >= 0) snprintf(out + strlen(out), max - strlen(out), ", key %d", i->keyId);
		break;
	case EI_TA: snprintf(out, max, "Terminal authentication%s", v); break;
	case EI_RI: snprintf(out, max, "Restricted identification%s", v); break;
	case EI_CARDINFO: snprintf(out, max, "Card info: %s", i->url); break;
	case EI_EIDSEC: snprintf(out, max, "eID security info"); break;
	default: {
		char h[33];
		scHex(h, i->oid, i->oidLen);
		snprintf(out, max, "OID %s", h);
	}
	}
	if (i->privileged) {
		char t[96];
		snprintf(t, sizeof(t), "%s", out);
		snprintf(out, max, "%s (privileged)", t);
	}
}

const char *eidPinText(u16 sw, u32 *col)
{
	switch (sw) {
	case 0x9000: *col = COL_OK; return "eID PIN: 3 tries left";
	case 0x63C2: *col = COL_WARN; return "eID PIN: 2 tries left";
	case 0x63C1: *col = COL_WARN; return "eID PIN: suspended (1 try left, the CAN first)";
	case 0x63C0: *col = COL_ERR; return "eID PIN: blocked (needs the PUK)";
	case 0x6283: *col = COL_DIM; return "eID function switched off";
	}
	return NULL;
}

bool eidIsGermanId(const EidCard *e)
{
	for (int i = 0; i < e->ninfo; i++)
		if (e->info[i].kind == EI_CARDINFO && strstr(e->info[i].url, "bsi.bund.de/cif/npa")) return true;
	return false;
}
