// eMRTD reading and passive authentication, see emrtd.h. Checked against a German passport, pm3 `hf emrtd
// dump` and tools/exp/eid/sod.py.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "app.h"
#include "ecc.h"
#include "emrtd.h"
#include "iso7816.h"
#include "jccrypto.h"
#include "probe.h"
#include "scard.h"
#include "sha1.h"

static char why[96];

const char *mrtdWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

static const u8 lds1[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

static const u8 dgTags[17] = { 0x60, 0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
	0x6E, 0x6F, 0x70 }; // EF.COM, DG1..DG16

const char *mrtdDgName(int dg)
{
	static const char *const n[17] = { "COM", "MRZ", "face", "fingerprints", "iris", "portrait", "", "signature",
		"", "", "", "personal details", "document details", "", "chip authentication", "active authentication",
		"contacts" };
	return dg >= 0 && dg <= 16 ? n[dg] : "";
}

void mrtdFree(MrtdDoc *d)
{
	for (int i = 0; i < MRTD_FILES; i++) free(d->f[i].data);
	memset(d, 0, sizeof(*d));
}

// --- reading ---

// A whole EF by SFI under SM, 223 bytes a READ BINARY (the answer fits a short APDU with SM around it).
// 1 = read, 0 = refused (f->sw), -1 SM / card lost, -2 monitor.
static int readFile(EidSm *sm, u8 sfi, MrtdFile *f)
{
	static u8 b[256];
	u16 sw = 0;
	int n = eidSmCmd(sm, 0xB0, 0x80 | sfi, 0, NULL, 0, 8, b, sizeof(b), &sw);
	if (n < 0) return n;
	f->sw = sw;
	if (sw == 0x6987 || sw == 0x6988) return -1; // SM broken: the chip ended the session
	if ((sw != 0x9000 && sw != 0x6282) || n < 2) return 0;
	u32 l = b[1], h = 2;
	if (l == 0x81) l = b[2], h = 3;
	else if (l == 0x82) l = b[2] << 8 | b[3], h = 4;
	else if (l > 0x80) return 0;
	u32 total = h + l;
	if (total > MRTD_MAX_FILE) FAIL(-1, "file %02X: %lu bytes", sfi, total);
	f->data = malloc(total);
	if (!f->data) FAIL(-1, "out of memory");
	f->len = 0;
	while (f->len < total) {
		u32 want = total - f->len > 0xDF ? 0xDF : total - f->len;
		n = eidSmCmd(sm, 0xB0, f->len >> 8, f->len & 0xFF, NULL, 0, want, b, sizeof(b), &sw);
		if (n < 0) return n;
		if ((sw != 0x9000 && sw != 0x6282) || !n) FAIL(-1, "file %02X at %lu: %04X", sfi, f->len, sw);
		if ((u32)n > total - f->len) n = total - f->len;
		memcpy(f->data + f->len, b, n);
		f->len += n;
	}
	f->sw = 0x9000;
	return 1;
}

// The face image in DG2: a JPEG 2000 file / codestream or a JPEG, to the end of the file (as pm3 cuts it)
static void findPhoto(MrtdDoc *d)
{
	static const u8 jp2[] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20 }, j2k[] = { 0xFF, 0x4F, 0xFF, 0x51 },
		jpg[] = { 0xFF, 0xD8, 0xFF };
	const MrtdFile *f = &d->f[2];
	d->photoLen = 0;
	for (u32 i = 0; f->data && i + 8 < f->len; i++) {
		bool a = !memcmp(f->data + i, jp2, 8), b = !memcmp(f->data + i, j2k, 4), c = !memcmp(f->data + i, jpg, 3);
		if (a || b || c) {
			d->photoOff = i, d->photoLen = f->len - i, d->photoJp2 = a || b;
			return;
		}
	}
}

int mrtdRead(const EidCard *e, u8 how, const u8 *secret, u32 len, MrtdDoc *d)
{
	static EidSm sm;
	static u8 b[64];
	mrtdFree(d);
	*why = 0;
	int r;
	u16 sw;
	if (e->pace >= 0) {
		r = eidPace(e, how, secret, len, &sm);
		if (r != 1) FAIL(r, "%s", eidWhy());
		snprintf(d->access, sizeof(d->access), "PACE (%s)", how == EID_CAN ? "CAN" : "MRZ");
		int n = eidSmCmd(&sm, 0xA4, 0x04, 0x0C, lds1, sizeof(lds1), -1, b, sizeof(b), &sw);
		if (n < 0) FAIL(n == -2 ? -1 : 0, "SELECT LDS1: %s", eidWhy());
		if (sw != 0x9000) FAIL(0, "SELECT LDS1 after PACE: %04X %s", sw, scSwName(sw));
	} else {
		if (how != EID_MRZ) FAIL(0, "no PACE on this chip: it takes the MRZ (BAC)");
		u8 ats[32];
		r = scActivate(ats, sizeof(ats));
		if (r <= 0) FAIL(r, "ISO-DEP: %s", scWhy());
		int n = scCmd(0x00, 0xA4, 0x04, 0x0C, lds1, sizeof(lds1), false, b, sizeof(b), &sw);
		if (n == -2) FAIL(-1, "monitor");
		if (n < 0) FAIL(0, "card lost: %s", scWhy());
		if (sw != 0x9000) FAIL(0, "SELECT LDS1: %04X %s", sw, scSwName(sw));
		r = eidBac(secret, &sm);
		if (r != 1) FAIL(r, "%s", eidWhy());
		snprintf(d->access, sizeof(d->access), "BAC");
	}

	// EF.COM (its 5C: the DGs there), EF.SOD (its hash list), then every DG either names
	u32 want = 0;
	r = readFile(&sm, 0x1E, &d->f[MRTD_COM]);
	if (r < 0) FAIL(r == -2 ? -1 : 0, "EF.COM: %s", eidWhy());
	Tlv t;
	if (r && tlvFind(d->f[MRTD_COM].data, d->f[MRTD_COM].len, 0x5C, &t))
		for (u32 i = 0; i < t.len; i++)
			for (int g = 1; g <= 16; g++)
				if (dgTags[g] == t.v[i]) want |= 1u << g;
	r = readFile(&sm, 0x1D, &d->f[MRTD_SOD]);
	if (r < 0) FAIL(r == -2 ? -1 : 0, "EF.SOD: %s", eidWhy());
	mrtdVerify(d); // only for the list of DGs, so far
	want |= d->listed;
	if (!want) want = 1u << 1 | 1u << 2 | 1u << 14; // nothing tells: DG1, DG2, DG14
	for (int g = 1; g <= 16; g++) {
		if (!(want & 1u << g)) continue;
		r = readFile(&sm, g, &d->f[g]);
		logp("DG%d: %s, %lu bytes\n", g, r > 0 ? "read" : "refused", d->f[g].len);
		if (r < 0) FAIL(r == -2 ? -1 : 0, "DG%d: %s", g, eidWhy());
		if (!r && !d->f[g].sw) d->f[g].sw = 0x6F00;
	}
	mrtdParseDg1(d);
	findPhoto(d);
	mrtdVerify(d);
	return 1;
}

// --- DG1 ---

static void field(char *out, u32 max, const char *s, u32 n)
{
	u32 k = 0;
	for (u32 i = 0; i < n && s[i] && k + 1 < max; i++) out[k++] = s[i] == '<' ? ' ' : s[i];
	while (k && out[k - 1] == ' ') k--;
	out[k] = 0;
}

static void names(MrtdDoc *d, const char *s, u32 n)
{
	const char *sep = NULL;
	for (u32 i = 0; i + 1 < n; i++)
		if (s[i] == '<' && s[i + 1] == '<') {
			sep = s + i;
			break;
		}
	u32 sn = sep ? (u32)(sep - s) : n;
	field(d->surname, sizeof(d->surname), s, sn);
	if (sep) field(d->given, sizeof(d->given), sep + 2, n - sn - 2);
}

void mrtdParseDg1(MrtdDoc *d)
{
	const MrtdFile *f = &d->f[1];
	Tlv t;
	d->mrzLines = 0;
	if (!f->data || !tlvFind(f->data, f->len, 0x5F1F, &t) || t.len >= sizeof(d->mrz)) return;
	const char *m = (const char *)t.v;
	memcpy(d->mrz, m, t.len);
	d->mrz[t.len] = 0;
	field(d->docType, sizeof(d->docType), m, 2);
	field(d->issuer, sizeof(d->issuer), m + 2, 3);
	if (t.len == 90) { // TD1: 3 x 30
		d->mrzLines = 3;
		field(d->number, sizeof(d->number), m + 5, 9);
		memcpy(d->birth, m + 30, 6), d->sex = m[37], memcpy(d->expiry, m + 38, 6);
		field(d->nationality, sizeof(d->nationality), m + 45, 3);
		names(d, m + 60, 30);
	} else if (t.len == 88 || t.len == 72) { // TD3 2 x 44, TD2 2 x 36
		u32 w = t.len / 2;
		d->mrzLines = 2;
		names(d, m + 5, w - 5);
		const char *l = m + w;
		field(d->number, sizeof(d->number), l, 9);
		field(d->nationality, sizeof(d->nationality), l + 10, 3);
		memcpy(d->birth, l + 13, 6), d->sex = l[20], memcpy(d->expiry, l + 21, 6);
	}
	d->birth[6] = d->expiry[6] = 0;
	if (d->sex == '<') d->sex = 'X';
}

// --- passive authentication ---

// The idx-th TLV inside a constructed value; start (if given) gets where its tag begins.
static bool child(const u8 *p, u32 len, int idx, Tlv *t, const u8 **start)
{
	const u8 *q = p, *end = p + len;
	for (int i = 0; i <= idx; i++) {
		if (start) *start = q;
		if (!tlvNext(&q, end, t)) return false;
	}
	return true;
}

static bool oidIs(const Tlv *t, const char *hex)
{
	u8 b[16];
	int n = scUnhex(hex, b, sizeof(b));
	return t->tag == 0x06 && (u32)n == t->len && !memcmp(b, t->v, n);
}

static bool oidStarts(const Tlv *t, const char *hex)
{
	u8 b[16];
	int n = scUnhex(hex, b, sizeof(b));
	return t->tag == 0x06 && (u32)n <= t->len && !memcmp(b, t->v, n);
}

static u8 hashOid(const Tlv *t)
{
	if (oidIs(t, "2B0E03021A")) return 20;
	if (oidIs(t, "608648016503040201")) return 32;
	if (oidIs(t, "608648016503040202")) return 48;
	if (oidIs(t, "608648016503040203")) return 64;
	if (oidIs(t, "608648016503040204")) return 28;
	return 0;
}

static void hashBy(u8 hl, const u8 *m, u32 len, u8 *out)
{
	static Sha256 s2;
	static Sha512 s5;
	if (hl == 20) {
		sha1(m, len, out);
	} else if (hl == 28 || hl == 32) {
		if (hl == 28) sha224Init(&s2);
		else sha256Init(&s2);
		sha256Add(&s2, m, len);
		u8 h[32];
		sha256Done(&s2, h);
		memcpy(out, h, hl);
	} else {
		if (hl == 48) sha384Init(&s5);
		else sha512Init(&s5);
		sha512Add(&s5, m, len);
		sha512Done(&s5, out, hl);
	}
}

// "CN, O, C" of an X.501 name
static void nameText(const Tlv *name, char *out, u32 max)
{
	static const char *const want[3] = { "550403", "55040A", "550406" };
	*out = 0;
	for (int w = 0; w < 3; w++) {
		Tlv set, seq, oid, v;
		for (int i = 0; child(name->v, name->len, i, &set, NULL); i++)
			if (child(set.v, set.len, 0, &seq, NULL) && child(seq.v, seq.len, 0, &oid, NULL) &&
				oidIs(&oid, want[w]) && child(seq.v, seq.len, 1, &v, NULL)) {
				u32 k = strlen(out);
				snprintf(out + k, max - k, "%s%.*s", k ? ", " : "", (int)v.len, (const char *)v.v);
				break;
			}
	}
}

static void timeText(const Tlv *t, char *out)
{
	const char *s = (const char *)t->v;
	if (t->tag == 0x17 && t->len >= 6)
		sprintf(out, "%s%.2s-%.2s-%.2s", (s[0] - '0') * 10 + s[1] - '0' < 50 ? "20" : "19", s, s + 2, s + 4);
	else if (t->tag == 0x18 && t->len >= 8)
		sprintf(out, "%.4s-%.2s-%.2s", s, s + 4, s + 6);
	else
		*out = 0;
}

// The DS signature over h with the certificate's key. PA_*; d->sigAlg named.
static int verifySig(MrtdDoc *d, const Tlv *cert, const Tlv *sigAlg, const u8 *sig, u32 sigLen, const u8 *h, u8 hl)
{
	static EcCurve c;
	static Bn r, s;
	Tlv tbs, x, spki, alg, aoid, params, bits;
	if (!child(cert->v, cert->len, 0, &tbs, NULL)) return PA_UNSUPPORTED;
	int o = child(tbs.v, tbs.len, 0, &x, NULL) && x.tag == 0xA0 ? 1 : 0; // [0] version
	Tlv issuer, validity, subject;
	if (!child(tbs.v, tbs.len, o + 2, &issuer, NULL) || !child(tbs.v, tbs.len, o + 3, &validity, NULL) ||
		!child(tbs.v, tbs.len, o + 4, &subject, NULL) || !child(tbs.v, tbs.len, o + 5, &spki, NULL))
		return PA_UNSUPPORTED;
	nameText(&subject, d->dsSubject, sizeof(d->dsSubject));
	nameText(&issuer, d->dsIssuer, sizeof(d->dsIssuer));
	if (child(validity.v, validity.len, 0, &x, NULL)) timeText(&x, d->dsFrom);
	if (child(validity.v, validity.len, 1, &x, NULL)) timeText(&x, d->dsTo);
	if (!child(spki.v, spki.len, 0, &alg, NULL) || !child(spki.v, spki.len, 1, &bits, NULL) || bits.tag != 0x03 ||
		bits.len < 2 || !child(alg.v, alg.len, 0, &aoid, NULL))
		return PA_UNSUPPORTED;
	const u8 *key = bits.v + 1;
	u32 keyLen = bits.len - 1;
	Tlv so;
	if (!child(sigAlg->v, sigAlg->len, 0, &so, NULL)) return PA_UNSUPPORTED;

	if (oidStarts(&so, "2A8648CE3D04")) { // ecdsa-with-SHA*
		if (!oidIs(&aoid, "2A8648CE3D0201") || !child(alg.v, alg.len, 1, &params, NULL)) return PA_UNSUPPORTED;
		if (params.tag == 0x06) {
			int id = eidCurveFor(params.v, params.len);
			snprintf(d->sigAlg, sizeof(d->sigAlg), "ECDSA %s", id >= 0 ? eidParamName(id) : "(named curve)");
			if (id < 0 || !eidCurve(id, &c)) return snprintf(d->paWhy, sizeof(d->paWhy), "unknown named curve"), PA_UNSUPPORTED;
		} else {
			// ECParameters: version, fieldID { prime-field, p }, curve { a, b }, base, order
			Tlv fid, p, cv, a, b, g, n;
			if (!child(params.v, params.len, 1, &fid, NULL) || !child(fid.v, fid.len, 1, &p, NULL) ||
				!child(params.v, params.len, 2, &cv, NULL) || !child(cv.v, cv.len, 0, &a, NULL) ||
				!child(cv.v, cv.len, 1, &b, NULL) || !child(params.v, params.len, 3, &g, NULL) ||
				!child(params.v, params.len, 4, &n, NULL) ||
				!ecCurveInit(&c, p.v, p.len, a.v, a.len, b.v, b.len, g.v, g.len, n.v, n.len))
				return snprintf(d->paWhy, sizeof(d->paWhy), "curve parameters not usable"), PA_UNSUPPORTED;
			// name it when it is one we know
			const char *nm = NULL;
			for (int id = 12; id <= 13 && !nm; id++) {
				static EcCurve k;
				if (eidCurve(id, &k) && !bnCmp(&k.p.m, &c.p.m) && !bnCmp(&k.n.m, &c.n.m)) nm = eidParamName(id);
			}
			if (nm) snprintf(d->sigAlg, sizeof(d->sigAlg), "ECDSA %s", nm);
			else snprintf(d->sigAlg, sizeof(d->sigAlg), "ECDSA %d-bit curve", bnBits(&c.p.m));
		}
		Tlv rt, st, seq;
		const u8 *q = sig;
		if (!tlvNext(&q, sig + sigLen, &seq) || !child(seq.v, seq.len, 0, &rt, NULL) ||
			!child(seq.v, seq.len, 1, &st, NULL) || rt.len > 67 || st.len > 67)
			return PA_BAD;
		bnFromBytes(&r, rt.v, rt.len);
		bnFromBytes(&s, st.v, st.len);
		return ecVerify(&c, key, keyLen, h, hl, &r, &s) ? PA_OK : PA_BAD;
	}
	if (oidStarts(&so, "2A864886F70D0101")) { // RSA: PKCS#1 v1.5, or PSS (01 0A)
		bool pss = so.v[so.len - 1] == 0x0A;
		Tlv seq, n, e;
		const u8 *q = key;
		if (!tlvNext(&q, key + keyLen, &seq) || !child(seq.v, seq.len, 0, &n, NULL) || !child(seq.v, seq.len, 1, &e, NULL))
			return PA_UNSUPPORTED;
		u32 nl = n.len - (n.len && !n.v[0]);
		snprintf(d->sigAlg, sizeof(d->sigAlg), "RSA%s %lu", pss ? "-PSS" : "", nl * 8);
		if (nl > 256) return snprintf(d->paWhy, sizeof(d->paWhy), "RSA key too big for the app"), PA_UNSUPPORTED;
		return rsaVerifyDigest(n.v, n.len, e.v, e.len, h, hl, sig, sigLen, pss) ? PA_OK : PA_BAD;
	}
	snprintf(d->sigAlg, sizeof(d->sigAlg), "unknown");
	return PA_UNSUPPORTED;
}

void mrtdVerify(MrtdDoc *d)
{
	static u8 h[64], attrs[1024];
	d->hashLen = 0, d->listed = d->ok = d->bad = 0, d->attrs = d->sig = PA_NONE;
	*d->paWhy = 0;
	const MrtdFile *f = &d->f[MRTD_SOD];
	Tlv sod, ci, x, sd, eci, ec, lso, alg, list;
	// 77 { ContentInfo { OID, [0] { SignedData { version, digestAlgs, encap, [0] certs, [1] crls?, signerInfos } } } }
	if (!f->data || !tlvFind(f->data, f->len, 0x77, &sod) || !child(sod.v, sod.len, 0, &ci, NULL) ||
		!child(ci.v, ci.len, 1, &x, NULL) || !child(x.v, x.len, 0, &sd, NULL) || !child(sd.v, sd.len, 2, &eci, NULL) ||
		!child(eci.v, eci.len, 1, &x, NULL) || !child(x.v, x.len, 0, &ec, NULL) || ec.tag != 0x04) {
		if (f->data) snprintf(d->paWhy, sizeof(d->paWhy), "EF.SOD not understood");
		return;
	}
	// LDSSecurityObject { version, hashAlgorithm { OID }, dataGroupHashValues { { dg, hash } ... } }
	Tlv ho;
	if (!child(ec.v, ec.len, 0, &lso, NULL) || !child(lso.v, lso.len, 1, &alg, NULL) ||
		!child(alg.v, alg.len, 0, &ho, NULL) || !child(lso.v, lso.len, 2, &list, NULL) || !(d->hashLen = hashOid(&ho))) {
		snprintf(d->paWhy, sizeof(d->paWhy), "LDS security object not understood");
		return;
	}
	Tlv e, n, hv;
	for (int i = 0; child(list.v, list.len, i, &e, NULL); i++) {
		if (!child(e.v, e.len, 0, &n, NULL) || !child(e.v, e.len, 1, &hv, NULL) || n.len != 1 || n.v[0] > 16) continue;
		int g = n.v[0];
		d->listed |= 1u << g;
		if (!d->f[g].data) continue;
		hashBy(d->hashLen, d->f[g].data, d->f[g].len, h);
		if (hv.len == d->hashLen && !memcmp(h, hv.v, hv.len)) d->ok |= 1u << g;
		else d->bad |= 1u << g;
	}

	// the signer: SignerInfo { version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature }
	Tlv certs, sis, si, da, dao, sa, sga, sig, cert;
	const u8 *saStart;
	int k = 3;
	if (!child(sd.v, sd.len, k, &certs, NULL) || certs.tag != 0xA0) {
		snprintf(d->paWhy, sizeof(d->paWhy), "no document signer certificate in EF.SOD");
		return;
	}
	while (child(sd.v, sd.len, k + 1, &sis, NULL) && sis.tag != 0x31) k++;
	if (sis.tag != 0x31 || !child(sis.v, sis.len, 0, &si, NULL) || !child(si.v, si.len, 2, &da, NULL) ||
		!child(da.v, da.len, 0, &dao, NULL) || !child(si.v, si.len, 3, &sa, &saStart) || sa.tag != 0xA0 ||
		!child(si.v, si.len, 4, &sga, NULL) || !child(si.v, si.len, 5, &sig, NULL) || sig.tag != 0x04 ||
		!child(certs.v, certs.len, 0, &cert, NULL)) {
		snprintf(d->paWhy, sizeof(d->paWhy), "signer info not understood");
		return;
	}
	u8 hl = hashOid(&dao);
	if (!hl) {
		snprintf(d->paWhy, sizeof(d->paWhy), "unknown digest algorithm");
		return;
	}
	// signedAttrs: the messageDigest attribute = hash(eContent); hashed whole with a SET tag for [0]
	d->attrs = PA_BAD;
	Tlv at, ao, av, md;
	for (int i = 0; child(sa.v, sa.len, i, &at, NULL); i++)
		if (child(at.v, at.len, 0, &ao, NULL) && oidIs(&ao, "2A864886F70D010904") && child(at.v, at.len, 1, &av, NULL) &&
			child(av.v, av.len, 0, &md, NULL)) {
			hashBy(hl, ec.v, ec.len, h);
			if (md.len == hl && !memcmp(md.v, h, hl)) d->attrs = PA_OK;
		}
	u32 aLen = sa.v + sa.len - saStart;
	if (aLen > sizeof(attrs)) {
		snprintf(d->paWhy, sizeof(d->paWhy), "signed attributes too long");
		return;
	}
	memcpy(attrs, saStart, aLen);
	attrs[0] = 0x31;
	hashBy(hl, attrs, aLen, h);
	d->sig = verifySig(d, &cert, &sga, sig.v, sig.len, h, hl);
	logp("passive authentication: DGs ok %lX bad %lX, attrs %d, signature %d (%s)\n", d->ok, d->bad, d->attrs, d->sig,
		d->sigAlg);
}

// --- saving ---

static bool writeFile(const char *path, const u8 *p, u32 len)
{
	FILE *f = fopen(path, "wb");
	if (!f) return false;
	bool ok = fwrite(p, 1, len, f) == len;
	return fclose(f) == 0 && ok;
}

bool mrtdSave(const MrtdDoc *d, char *path, u32 max)
{
	char id[16], p[160];
	snprintf(id, sizeof(id), "%s", *d->number ? d->number : "unknown");
	for (char *q = id; *q; q++)
		if (!((*q >= '0' && *q <= '9') || (*q >= 'A' && *q <= 'Z'))) *q = '_';
	mkdir(APP_DIR, 0777);
	mkdir(SC_DIR, 0777);
	struct stat st;
	for (int i = 1;; i++) {
		if (i == 1) snprintf(path, max, SC_DIR "/emrtd-%s", id);
		else snprintf(path, max, SC_DIR "/emrtd-%s-%d", id, i);
		if (stat(path, &st)) break;
		if (i > 99) return false;
	}
	if (mkdir(path, 0777)) return false;
	for (int i = 0; i < MRTD_FILES; i++) {
		if (!d->f[i].data) continue;
		if (i == MRTD_COM) snprintf(p, sizeof(p), "%s/EF_COM.bin", path);
		else if (i == MRTD_SOD) snprintf(p, sizeof(p), "%s/EF_SOD.bin", path);
		else snprintf(p, sizeof(p), "%s/EF_DG%d.bin", path, i);
		if (!writeFile(p, d->f[i].data, d->f[i].len)) return false;
	}
	if (d->photoLen) {
		snprintf(p, sizeof(p), "%s/EF_DG2.%s", path, d->photoJp2 ? "jp2" : "jpg");
		if (!writeFile(p, d->f[2].data + d->photoOff, d->photoLen)) return false;
	}
	return true;
}
