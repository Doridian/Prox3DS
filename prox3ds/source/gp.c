// GlobalPlatform: security domain data, SCP03, GET STATUS / DELETE / INSTALL, CAP files. See gp.h.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "dfcrypto.h"
#include "gp.h"
#include "iso7816.h"
#include "probe.h"
#include "zip.h"

static char why[96];

const char *gpWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

const GpKeys gpDefaultKeys = {
	{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
	{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
	{ 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F },
};

static u32 rng;

static void rnd(u8 *p, u32 n)
{
	if (!rng) rng = (u32)osGetTime() * 2654435761u | 1;
	while (n--) {
		rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5;
		*p++ = rng >> 24;
	}
}

void gpAidHex(char *out, const u8 *aid, u32 len)
{
	scHex(out, aid, len);
}

// a SELECT / GET DATA through scApdu: -1 lost card, -2 monitor -> FAIL
#define SC(expr) ({ \
	int r_ = (expr); \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ < 0) FAIL(0, "%s", scWhy()); \
	r_; })

// GET DATA (80 CA): the value of tag, cut at max; length, 0 = refused / absent.
static int getData(u16 tag, u8 *out, u32 max, int *err)
{
	u8 buf[260];
	u16 sw;
	int n = scCmd(0x80, 0xCA, tag >> 8, tag, NULL, 0, true, buf, sizeof(buf), &sw);
	if (n < 0) {
		*err = n;
		return 0;
	}
	Tlv t;
	if (sw != 0x9000 || !tlvFind(buf, n, tag, &t)) return 0;
	u32 k = t.len < max ? t.len : max;
	memcpy(out, t.v, k);
	return k;
}

int gpOpen(GpCard *g)
{
	u8 ats[32];
	int r = scActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", scWhy());
	return gpSelect(g);
}

int gpSelect(GpCard *g)
{
	static const u8 isds[][8] = {
		{ 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00 }, // GlobalPlatform
		{ 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 }, // Visa / Open Platform
	};
	memset(g, 0, sizeof(*g));
	u8 buf[260];
	u16 sw;
	for (int i = 0; i < 2 && !g->isdLen; i++) {
		SC(scSelect(isds[i], 8, buf, sizeof(buf), &sw));
		if (sw == 0x9000) memcpy(g->isd, isds[i], 8), g->isdLen = 8;
	}
	if (!g->isdLen) {
		// the default application (usually the ISD): its AID from the FCI
		u8 c[5] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
		int n = SC(scApdu(c, 5, buf, sizeof(buf), &sw));
		Tlv t;
		if (sw != 0x9000 || !tlvFind(buf, n, 0x84, &t) || !t.len || t.len > 16) FAIL(0, "no security domain answers SELECT");
		memcpy(g->isd, t.v, t.len), g->isdLen = t.len;
	}
	int err = 0;
	g->cplcLen = getData(0x9F7F, g->cplc, sizeof(g->cplc), &err);
	if (!err) g->crdLen = getData(0x0066, g->crd, sizeof(g->crd), &err);
	if (!err) g->kinfoLen = getData(0x00E0, g->kinfo, sizeof(g->kinfo), &err);
	u8 seq[4];
	int n = err ? 0 : getData(0x00C1, seq, sizeof(seq), &err);
	if (err == -2) FAIL(-1, "monitor");
	if (err) FAIL(0, "%s", scWhy());
	if (n) {
		g->hasSeq = true;
		for (int i = 0; i < n; i++) g->seq = g->seq << 8 | seq[i];
	}
	char aid[40];
	gpAidHex(aid, g->isd, g->isdLen);
	logp("GP: ISD %s, CPLC %d bytes, CRD %d bytes\n", aid, g->cplcLen, g->crdLen);
	return 1;
}

// --- SCP03 ---

static struct {
	bool on;
	u8 smacKey[16];
	DfCipher smac;
	u8 chain[16]; // the MAC chaining value
	u8 ctx[16];   // host challenge || card challenge
} ses;

// SCP03's KDF (NIST SP 800-108 counter mode, AES-CMAC): one block is all it takes (64 / 128 bits).
static void kdf(const u8 *key, u8 konst, const u8 *ctx, u32 bits, u8 *out)
{
	DfCipher c;
	u8 d[32] = { 0 }, iv[16] = { 0 }, mac[16];
	d[11] = konst, d[13] = bits >> 8, d[14] = bits, d[15] = 1;
	memcpy(d + 16, ctx, 16);
	dfCipherInit(&c, DF_AES, key);
	dfCmac(&c, iv, d, 32, mac);
	memcpy(out, mac, bits / 8);
}

int gpCheck(GpCard *g, const GpKeys *k)
{
	u8 hc[8], buf[64];
	u16 sw;
	ses.on = false;
	rnd(hc, 8);
	int n = SC(scCmd(0x80, 0x50, 0x00, 0x00, hc, 8, true, buf, sizeof(buf), &sw));
	if (sw != 0x9000) FAIL(0, "INITIALIZE UPDATE: SW %04X %s", sw, scSwName(sw));
	if (n < 29) FAIL(0, "INITIALIZE UPDATE: %d bytes", n);
	memcpy(g->div, buf, 10), g->divLen = 10;
	g->kvn = buf[10], g->scp = buf[11], g->scpI = buf[12];
	if (g->scp != 3) FAIL(0, "SCP%02X: only SCP03 so far", g->scp);
	if (n >= 32) g->hasSeq = true, g->seq = buf[29] << 16 | buf[30] << 8 | buf[31];
	memcpy(ses.ctx, hc, 8);
	memcpy(ses.ctx + 8, buf + 13, 8);
	u8 crypt[8];
	kdf(k->mac, 0x06, ses.ctx, 128, ses.smacKey);
	kdf(ses.smacKey, 0x00, ses.ctx, 64, crypt);
	if (memcmp(crypt, buf + 21, 8)) FAIL(0, "not these keys: the card cryptogram doesn't match (no try used)");
	dfCipherInit(&ses.smac, DF_AES, ses.smacKey);
	memset(ses.chain, 0, 16);
	return 1;
}

// CLA 84, the C-MAC over the chaining value, the header (Lc with the MAC) and the data.
static int scpSend(u8 ins, u8 p1, u8 p2, const u8 *data, u32 len, bool le, u8 *out, u32 max, u16 *sw)
{
	if (len > 255 - 8) FAIL(-1, "command too long");
	u8 m[16 + 5 + 255], c[5 + 255 + 1], iv[16] = { 0 };
	u8 hdr[5] = { 0x84, ins, p1, p2, len + 8 };
	memcpy(m, ses.chain, 16);
	memcpy(m + 16, hdr, 5);
	memcpy(m + 21, data, len);
	dfCmac(&ses.smac, iv, m, 21 + len, ses.chain);
	memcpy(c, hdr, 5);
	memcpy(c + 5, data, len);
	memcpy(c + 5 + len, ses.chain, 8);
	u32 l = 13 + len;
	if (le) c[l++] = 0;
	int n = scApdu(c, l, out, max, sw);
	if (n < 0) FAIL(n, "%s", scWhy());
	return n;
}

int gpAuth(GpCard *g, const GpKeys *k)
{
	int r = gpCheck(g, k);
	if (r <= 0) return r;
	u8 host[8], buf[16];
	u16 sw;
	kdf(ses.smacKey, 0x01, ses.ctx, 64, host);
	int n = scpSend(0x82, 0x01, 0x00, host, 8, false, buf, sizeof(buf), &sw); // security level 01: C-MAC
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) return 0;
	if (sw != 0x9000) FAIL(0, "EXTERNAL AUTHENTICATE: SW %04X %s", sw, scSwName(sw));
	ses.on = true;
	logp("GP: authenticated, key version %02X, SCP03 i=%02X\n", g->kvn, g->scpI);
	return 1;
}

int gpSend(u8 ins, u8 p1, u8 p2, const u8 *data, u32 len, u8 *out, u32 max, u16 *sw)
{
	if (!ses.on) FAIL(-1, "no secure channel");
	return scpSend(ins, p1, p2, data, len, true, out, max, sw);
}

#define GPSEND(ins, p1, p2, d, l, out, max) ({ \
	int r_ = gpSend(ins, p1, p2, d, l, out, max, &sw); \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ < 0) return 0; \
	r_; })

// --- GET STATUS ---

static void addEntry(GpCard *g, const GpEntry *e)
{
	if (g->nent < GP_MAX_ENT) g->ent[g->nent++] = *e;
}

static void copyAid(u8 *dst, u8 *dstLen, const u8 *v, u32 len)
{
	*dstLen = len < 16 ? len : 16;
	memcpy(dst, v, *dstLen);
}

// The tag format (P2 02): an E3 per entry.
static void parseTlv(GpCard *g, u8 kind, const u8 *p, u32 n)
{
	const u8 *end = p + n;
	Tlv e;
	while (tlvNext(&p, end, &e)) {
		if (e.tag != 0xE3) continue;
		GpEntry x = { kind };
		const u8 *q = e.v;
		Tlv t;
		while (tlvNext(&q, e.v + e.len, &t)) {
			if (t.tag == 0x4F) copyAid(x.aid, &x.aidLen, t.v, t.len);
			else if (t.tag == 0x9F70 && t.len) x.state = t.v[0];
			else if (t.tag == 0xC5 && t.len) x.priv = t.v[0];
			else if (t.tag == 0xC4) copyAid(x.pkg, &x.pkgLen, t.v, t.len);
			else if (t.tag == 0xCE && t.len >= 2 && !x.pkgLen) x.pkg[0] = t.v[0], x.pkg[1] = t.v[1];
			else if (t.tag == 0x84 && x.nmods < 6) {
				copyAid(x.mods[x.nmods], &x.modLen[x.nmods], t.v, t.len);
				x.nmods++;
			}
		}
		addEntry(g, &x);
	}
}

// The old format (P2 00): AID length, AID, state, privileges [, modules: count, then length + AID each].
static void parseLegacy(GpCard *g, u8 kind, bool mods, const u8 *p, u32 n)
{
	u32 o = 0;
	while (o < n) {
		GpEntry x = { kind };
		u32 l = p[o];
		if (o + 1 + l + 2 > n) return;
		copyAid(x.aid, &x.aidLen, p + o + 1, l);
		o += 1 + l;
		x.state = p[o], x.priv = p[o + 1];
		o += 2;
		if (mods && o < n) {
			int k = p[o++];
			for (int i = 0; i < k && o < n; i++) {
				u32 ml = p[o];
				if (o + 1 + ml > n) return;
				if (x.nmods < 6) copyAid(x.mods[x.nmods], &x.modLen[x.nmods], p + o + 1, ml), x.nmods++;
				o += 1 + ml;
			}
		}
		addEntry(g, &x);
	}
}

static int status(GpCard *g, u8 kind, u8 p1, bool *refused)
{
	static u8 buf[SC_MAX_ANS];
	u16 sw;
	u8 p2 = 0x02, crit[2] = { 0x4F, 0x00 };
	*refused = false;
	for (int more = 0; more < 32; more++) {
		int n = GPSEND(0xF2, p1, p2 | (more ? 1 : 0), crit, 2, buf, sizeof(buf));
		if (!more && p2 == 0x02 && (sw == 0x6A86 || sw == 0x6D00)) { // no tag format: the old one
			p2 = 0x00;
			more = -1;
			continue;
		}
		if (sw == 0x6A88) return 1; // none of these
		if (sw != 0x9000 && sw != 0x6310) {
			*refused = true;
			FAIL(0, "GET STATUS %02X: SW %04X %s", p1, sw, scSwName(sw));
		}
		if (p2 == 0x02) parseTlv(g, kind, buf, n);
		else parseLegacy(g, kind, p1 == 0x10, buf, n);
		if (sw == 0x9000) return 1;
	}
	return 1;
}

int gpList(GpCard *g)
{
	bool refused;
	g->nent = 0, g->listed = false;
	int r = status(g, GP_ISD, 0x80, &refused);
	if (r <= 0) return r;
	if ((r = status(g, GP_APP, 0x40, &refused)) <= 0) return r;
	// packages with their applet classes (GP 2.2), else just the packages
	int keep = g->nent;
	r = status(g, GP_PKG, 0x10, &refused);
	if (!r && refused) g->nent = keep, r = status(g, GP_PKG, 0x20, &refused);
	if (r <= 0) return r;
	g->listed = true;
	logp("GP: %d entries\n", g->nent);
	return 1;
}

int gpDelete(const u8 *aid, u32 len, bool related, u16 *swOut)
{
	u8 d[18] = { 0x4F, len }, buf[16];
	u16 sw;
	memcpy(d + 2, aid, len);
	GPSEND(0xE4, 0x00, related ? 0x80 : 0x00, d, 2 + len, buf, sizeof(buf));
	*swOut = sw;
	char h[40];
	gpAidHex(h, aid, len);
	logp("GP: DELETE %s: %04X\n", h, sw);
	if (sw != 0x9000) FAIL(0, "DELETE: SW %04X %s", sw, scSwName(sw));
	return 1;
}

int gpInstall(const GpCap *c)
{
	u8 d[64], buf[32];
	u16 sw;
	char h[40];
	u32 n = 0;
	d[n++] = c->pkgLen, memcpy(d + n, c->pkg, c->pkgLen), n += c->pkgLen;
	d[n++] = 0, d[n++] = 0, d[n++] = 0, d[n++] = 0; // security domain (the ISD), hash, parameters, token
	progOp("INSTALL [for load]");
	GPSEND(0xE6, 0x02, 0x00, d, n, buf, sizeof(buf));
	if (sw != 0x9000) FAIL(0, "INSTALL [for load]: SW %04X %s", sw, scSwName(sw));
	const u32 blk = 240;
	progOp("LOAD, %lu bytes", c->lfLen);
	for (u32 o = 0, i = 0; o < c->lfLen; o += blk, i++) {
		u32 k = c->lfLen - o < blk ? c->lfLen - o : blk;
		progStep(o, c->lfLen);
		GPSEND(0xE8, o + k >= c->lfLen ? 0x80 : 0x00, i, c->lf + o, k, buf, sizeof(buf));
		if (sw != 0x9000) FAIL(0, "LOAD block %lu: SW %04X %s", i, sw, scSwName(sw));
	}
	progStep(c->lfLen, c->lfLen);
	logp("GP: loaded %lu bytes\n", c->lfLen);
	for (int a = 0; a < c->napplets; a++) {
		const u8 *aid = c->apps[a];
		u8 l = c->appLen[a];
		gpAidHex(h, aid, l);
		progOp("INSTALL %s", h);
		n = 0;
		d[n++] = c->pkgLen, memcpy(d + n, c->pkg, c->pkgLen), n += c->pkgLen;
		d[n++] = l, memcpy(d + n, aid, l), n += l; // the class
		d[n++] = l, memcpy(d + n, aid, l), n += l; // the instance: the same AID
		d[n++] = 1, d[n++] = 0;                    // privileges
		d[n++] = 2, d[n++] = 0xC9, d[n++] = 0;     // install parameters: none for the applet
		d[n++] = 0;                                // token
		GPSEND(0xE6, 0x0C, 0x00, d, n, buf, sizeof(buf));
		if (sw != 0x9000) FAIL(0, "INSTALL %s: SW %04X %s", h, sw, scSwName(sw));
		logp("GP: installed %s\n", h);
	}
	return 1;
}

// --- CAP files ---

typedef struct {
	const u8 *zip;
	u32 len;
	u8 *comp[13];
	u32 compLen[13];
	bool bad;
} CapScan;

static bool capEntry(const ZipEntry *e, void *ctx)
{
	CapScan *s = ctx;
	u32 l = strlen(e->name);
	if (l < 4 || strcasecmp(e->name + l - 4, ".cap") || !e->size || e->size > 0x40000) return true;
	u8 *b = malloc(e->size);
	if (!b) return s->bad = true, false;
	if (!zipExtract(s->zip, s->len, e, b) || b[0] < 1 || b[0] > 12 || s->comp[b[0]]) {
		free(b);
		s->bad = true;
		return false;
	}
	s->comp[b[0]] = b, s->compLen[b[0]] = e->size;
	return true;
}

bool gpCapLoad(const char *path, GpCap *c)
{
	memset(c, 0, sizeof(*c));
	const char *base = strrchr(path, '/');
	snprintf(c->name, sizeof(c->name), "%s", base ? base + 1 : path);
	struct stat st;
	if (stat(path, &st) || st.st_size < 22 || st.st_size > 0x80000) FAIL(false, "not a CAP file (size)");
	FILE *f = fopen(path, "rb");
	u8 *zip = malloc(st.st_size);
	bool ok = f && zip && fread(zip, 1, st.st_size, f) == (size_t)st.st_size;
	if (f) fclose(f);
	CapScan s = { zip, st.st_size };
	if (ok && zipList(zip, st.st_size, capEntry, &s) < 0) s.bad = true;
	free(zip);
	// load order: Header, Directory, Import, Applet, Class, Method, StaticField, Export, ConstantPool,
	// RefLocation, Descriptor (not Debug)
	static const u8 order[] = { 1, 2, 4, 3, 6, 7, 8, 10, 5, 9, 11 };
	const u8 *hdr = s.comp[1];
	if (!ok) snprintf(why, sizeof(why), "could not read the file");
	else if (s.bad) snprintf(why, sizeof(why), "not a CAP file (zip / components)");
	else if (!hdr || s.compLen[1] < 14 || hdr[3] != 0xDE || hdr[4] != 0xCA || hdr[5] != 0xFF || hdr[6] != 0xED ||
		!s.comp[2] || !s.comp[6] || !s.comp[7])
		snprintf(why, sizeof(why), "not a CAP file (no Header / Directory / Class / Method)");
	else ok = true, *why = 0;
	if (ok && !*why) {
		c->pkgMinor = hdr[10], c->pkgMajor = hdr[11];
		copyAid(c->pkg, &c->pkgLen, hdr + 13, hdr[12]);
		const u8 *a = s.comp[3];
		if (a && s.compLen[3] >= 4) {
			u32 o = 4;
			for (int i = 0; i < a[3] && c->napplets < 8 && o < s.compLen[3]; i++) {
				copyAid(c->apps[c->napplets], &c->appLen[c->napplets], a + o + 1, a[o]);
				c->napplets++;
				o += 1 + a[o] + 2;
			}
		}
		u32 total = 0;
		for (u32 i = 0; i < sizeof(order); i++) total += s.compLen[order[i]];
		c->lf = malloc(total + 4);
		if (!c->lf) {
			ok = false;
			snprintf(why, sizeof(why), "out of memory");
		} else {
			u32 n = 0;
			c->lf[n++] = 0xC4;
			if (total >= 0x100) c->lf[n++] = 0x82, c->lf[n++] = total >> 8;
			else if (total >= 0x80) c->lf[n++] = 0x81;
			c->lf[n++] = total;
			for (u32 i = 0; i < sizeof(order); i++)
				if (s.comp[order[i]]) memcpy(c->lf + n, s.comp[order[i]], s.compLen[order[i]]), n += s.compLen[order[i]];
			c->lfLen = n;
		}
	} else {
		ok = false;
	}
	for (int i = 0; i < 13; i++) free(s.comp[i]);
	return ok;
}

void gpCapFree(GpCap *c)
{
	free(c->lf);
	c->lf = NULL;
}

// --- keys ---

int gpKeyList(GpKeys *out, int max)
{
	int n = 0;
	if (n < max) out[n++] = gpDefaultKeys;
	FILE *f = fopen(GP_KEYS, "r");
	char line[160];
	while (f && n < max && fgets(line, sizeof(line), f)) {
		char *h = strchr(line, '#');
		if (h) *h = 0;
		u8 b[48];
		for (char *e = line + strlen(line); e > line && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '); ) *--e = 0;
		int l = scUnhex(line, b, sizeof(b));
		if (l != 16 && l != 48) continue;
		GpKeys k;
		memcpy(k.enc, b, 16);
		memcpy(k.mac, l == 48 ? b + 16 : b, 16);
		memcpy(k.dek, l == 48 ? b + 32 : b, 16);
		bool dup = false;
		for (int i = 0; i < n && !dup; i++) dup = !memcmp(&out[i], &k, sizeof(k));
		if (!dup) out[n++] = k;
	}
	if (f) fclose(f);
	return n;
}

bool gpRememberKey(const GpKeys *k)
{
	static GpKeys list[64];
	int n = gpKeyList(list, 64);
	for (int i = 0; i < n; i++)
		if (!memcmp(&list[i], k, sizeof(*k))) return true;
	mkdir(APP_DIR, 0777);
	mkdir(GP_DIR, 0777);
	FILE *f = fopen(GP_KEYS, "a");
	if (!f) return false;
	char e[40], m[40], d[40];
	scHex(e, k->enc, 16), scHex(m, k->mac, 16), scHex(d, k->dek, 16);
	if (!strcmp(e, m) && !strcmp(e, d)) fprintf(f, "%s\n", e);
	else fprintf(f, "%s %s %s\n", e, m, d);
	fclose(f);
	return true;
}

// --- in words ---

const char *gpStateName(u8 kind, u8 state)
{
	static char s[24];
	if (kind == GP_ISD) {
		switch (state) {
		case 0x01: return "OP_READY";
		case 0x07: return "INITIALIZED";
		case 0x0F: return "SECURED";
		case 0x7F: return "CARD_LOCKED";
		case 0xFF: return "TERMINATED";
		}
	} else if (kind == GP_PKG) {
		if (state == 0x01) return "LOADED";
	} else {
		if ((state & 0x83) == 0x83) return "LOCKED";
		switch (state) {
		case 0x03: return "INSTALLED";
		case 0x07: return "SELECTABLE";
		case 0x0F: return "PERSONALIZED";
		}
		if ((state & 0x87) == 0x07) {
			snprintf(s, sizeof(s), "SELECTABLE (%02X)", state);
			return s;
		}
	}
	snprintf(s, sizeof(s), "state %02X", state);
	return s;
}

static const char *fabName(u16 id)
{
	switch (id) {
	case 0x2050: return "Philips";
	case 0x3060: return "Renesas";
	case 0x4090: return "Infineon";
	case 0x4180: return "Atmel";
	case 0x4250: return "Samsung";
	case 0x4790: return "NXP";
	}
	return NULL;
}

#define ADD(...) (o += snprintf(out + o, o < max ? max - o : 0, __VA_ARGS__))

void gpCplcDesc(const GpCard *g, char *out, u32 max)
{
	u32 o = 0;
	*out = 0;
	if (g->cplcLen < 18) {
		ADD("No CPLC");
		return;
	}
	const u8 *c = g->cplc;
	u16 fab = c[0] << 8 | c[1];
	const char *fn = fabName(fab);
	ADD("IC %s%s%04X, type %02X%02X, OS %02X%02X (release %02X%02X, level %02X%02X)\n", fn ? fn : "", fn ? " " : "", fab,
		c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9]);
	ADD("IC fabricated %02X%02X, serial %02X%02X%02X%02X, batch %02X%02X", c[10], c[11], c[12], c[13], c[14], c[15],
		c[16], c[17]);
}

// An OID's arcs after GP's 1.2.840.114283 (2A864886FC6B), as "a.b.c"; NULL = not GP's.
static const u8 gpOid[] = { 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B };

static bool oidAfter(const Tlv *t, const u8 *pre, u32 preLen, u8 *arcs, int *n)
{
	Tlv o;
	if (!tlvFind(t->v, t->len, 0x06, &o) || o.len < preLen || memcmp(o.v, pre, preLen)) return false;
	*n = 0;
	for (u32 i = preLen; i < o.len && *n < 6; i++) arcs[(*n)++] = o.v[i];
	return true;
}

void gpCrdDesc(const GpCard *g, char *out, u32 max)
{
	u32 o = 0;
	*out = 0;
	Tlv r, t;
	if (!g->crdLen || !tlvFind(g->crd, g->crdLen, 0x73, &r)) {
		ADD("No card recognition data");
		return;
	}
	u8 a[6];
	int n;
	if (tlvFind(r.v, r.len, 0x60, &t) && oidAfter(&t, gpOid, 6, a, &n) && n >= 2 && a[0] == 2) {
		ADD("GlobalPlatform %d", a[1]);
		for (int i = 2; i < n; i++) ADD(".%d", a[i]);
	}
	if (tlvFind(r.v, r.len, 0x64, &t) && oidAfter(&t, gpOid, 6, a, &n) && n >= 3 && a[0] == 4)
		ADD("%sSCP%02X i=%02X", o ? ", " : "", a[1], a[2]);
	static const u8 jc[] = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x6E, 0x01 }; // 1.3.6.1.4.1.42.2.110.1
	if (tlvFind(r.v, r.len, 0x66, &t) && oidAfter(&t, jc, sizeof(jc), a, &n) && n >= 1)
		ADD("%sJava Card %d", o ? ", " : "", a[0]);
	if (!o) ADD("Card recognition data without GP OIDs");
}
