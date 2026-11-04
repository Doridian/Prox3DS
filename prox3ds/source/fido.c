// FIDO security keys (U2F / CTAP2) over NFC, read only: see fido.h.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "app.h"
#include "fido.h"
#include "probe.h"

static char why[96];
#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

static u8 ans[SC_MAX_ANS];
static const u8 fidoAid[] = { 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01 };

const char *fidoWhy(void)
{
	return why;
}

// --- CBOR (RFC 8949), what getInfo uses: definite lengths only ---

typedef struct {
	const u8 *p, *end;
	bool bad;
} Cb;

// The next item's head: major type, its argument (the value, a length or a count).
static bool cbHead(Cb *c, int *major, u64 *val)
{
	if (c->bad || c->p >= c->end) return c->bad = true, false;
	u8 b = *c->p++;
	int ai = b & 31, n = ai < 24 ? 0 : ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : -1;
	if (n < 0 || c->end - c->p < n) return c->bad = true, false;
	*major = b >> 5;
	*val = ai < 24 ? ai : 0;
	for (int i = 0; i < n; i++) *val = *val << 8 | *c->p++;
	return true;
}

static void cbSkip(Cb *c)
{
	int m;
	u64 v;
	if (!cbHead(c, &m, &v)) return;
	if (m == 2 || m == 3) {
		if ((u64)(c->end - c->p) < v) c->bad = true;
		else c->p += v;
	} else if (m == 4 || m == 5) {
		for (u64 i = 0; i < (m == 5 ? 2 * v : v) && !c->bad; i++) cbSkip(c);
	} else if (m == 6) {
		cbSkip(c);
	}
}

// An integer (major 0 or 1); anything else is skipped and false.
static bool cbInt(Cb *c, int *out)
{
	const u8 *at = c->p;
	int m;
	u64 v;
	if (!cbHead(c, &m, &v)) return false;
	if (m == 0 || m == 1) {
		*out = m ? -1 - (int)v : (int)v;
		return true;
	}
	c->p = at;
	cbSkip(c);
	return false;
}

// A text string, cut to fit; anything else is skipped and false.
static bool cbText(Cb *c, char *out, u32 max)
{
	const u8 *at = c->p;
	int m;
	u64 v;
	if (!cbHead(c, &m, &v) || m != 3 || (u64)(c->end - c->p) < v) {
		if (!c->bad) c->p = at, cbSkip(c);
		return false;
	}
	u32 n = v < max - 1 ? v : max - 1;
	memcpy(out, c->p, n);
	out[n] = 0;
	c->p += v;
	return true;
}

static bool cbBool(Cb *c, bool *out)
{
	const u8 *at = c->p;
	int m;
	u64 v;
	if (cbHead(c, &m, &v) && m == 7 && (v == 20 || v == 21)) {
		*out = v == 21;
		return true;
	}
	if (!c->bad) c->p = at, cbSkip(c);
	return false;
}

// An array of text strings into strs (as many as fit).
static void cbTextArray(Cb *c, char *strs, u32 size, int max, int *n)
{
	int m;
	u64 v;
	const u8 *at = c->p;
	if (!cbHead(c, &m, &v)) return;
	if (m != 4) {
		c->p = at, cbSkip(c);
		return;
	}
	for (u64 i = 0; i < v && !c->bad; i++) {
		if (*n < max && cbText(c, strs + *n * size, size)) ++*n;
		else if (*n >= max) cbSkip(c);
	}
}

bool fidoParseInfo(FidoInfo *f, const u8 *p, u32 len)
{
	Cb c = { p, p + len, false };
	int m;
	u64 n;
	if (!cbHead(&c, &m, &n) || m != 5) return false;
	for (u64 i = 0; i < n && !c.bad; i++) {
		int key, x;
		u64 k;
		if (!cbInt(&c, &key)) {
			cbSkip(&c);
			continue;
		}
		switch (key) {
		case 1: cbTextArray(&c, f->ver[0], sizeof(f->ver[0]), FIDO_MAX_STR, &f->nver); break;
		case 2: cbTextArray(&c, f->ext[0], sizeof(f->ext[0]), FIDO_MAX_STR, &f->next); break;
		case 9: cbTextArray(&c, f->trans[0], sizeof(f->trans[0]), FIDO_MAX_STR, &f->ntrans); break;
		case 3: {
			const u8 *at = c.p;
			if (cbHead(&c, &m, &k) && m == 2 && k == 16 && c.end - c.p >= 16) {
				memcpy(f->aaguid, c.p, 16);
				f->hasAaguid = true;
				c.p += 16;
			} else if (!c.bad) {
				c.p = at, cbSkip(&c);
			}
			break;
		}
		case 4: // options: text -> bool
			if (!cbHead(&c, &m, &k) || m != 5) {
				c.bad = true;
				break;
			}
			for (u64 j = 0; j < k && !c.bad; j++) {
				FidoOpt o;
				if (!cbText(&c, o.name, sizeof(o.name))) {
					cbSkip(&c);
					continue;
				}
				if (cbBool(&c, &o.on) && f->nopt < (int)(sizeof(f->opt) / sizeof(f->opt[0]))) f->opt[f->nopt++] = o;
			}
			break;
		case 6: // PIN / UV auth protocols
			if (!cbHead(&c, &m, &k) || m != 4) {
				c.bad = true;
				break;
			}
			for (u64 j = 0; j < k && !c.bad; j++)
				if (cbInt(&c, &x) && f->npin < 4) f->pinProto[f->npin++] = x;
			break;
		case 10: // algorithms: [{ "alg": -7, "type": "public-key" }, ...]
			if (!cbHead(&c, &m, &k) || m != 4) {
				c.bad = true;
				break;
			}
			for (u64 j = 0; j < k && !c.bad; j++) {
				u64 e;
				if (!cbHead(&c, &m, &e) || m != 5) {
					c.bad = true;
					break;
				}
				for (u64 q = 0; q < e && !c.bad; q++) {
					char name[8];
					if (cbText(&c, name, sizeof(name)) && !strcmp(name, "alg")) {
						if (cbInt(&c, &x) && f->nalg < FIDO_MAX_STR) f->alg[f->nalg++] = x;
					} else {
						cbSkip(&c);
					}
				}
			}
			break;
		case 12: cbBool(&c, &f->forcePinChange); break;
		case 5: cbInt(&c, &f->maxMsg); break;
		case 7: cbInt(&c, &f->maxCredList); break;
		case 8: cbInt(&c, &f->maxCredIdLen); break;
		case 13: cbInt(&c, &f->minPin); break;
		case 14: cbInt(&c, &f->firmware); break;
		case 20: cbInt(&c, &f->remainingRk); break;
		default: cbSkip(&c);
		}
	}
	return !c.bad;
}

int fidoOpt(const FidoInfo *f, const char *name)
{
	for (int i = 0; i < f->nopt; i++)
		if (!strcmp(f->opt[i].name, name)) return f->opt[i].on;
	return -1;
}

// --- the card ---

static void clear(FidoInfo *f)
{
	memset(f, 0, sizeof(*f));
	f->maxMsg = f->maxCredList = f->maxCredIdLen = f->minPin = f->firmware = f->remainingRk = f->pinRetries = -1;
}

int fidoRead(FidoInfo *f)
{
	clear(f);
	u8 ats[32];
	int r = scActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", scWhy());
	u16 sw;
	int n = scSelect(fidoAid, sizeof(fidoAid), ans, sizeof(ans), &sw);
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) FAIL(0, "%s", scWhy());
	if (sw != 0x9000) FAIL(0, "No FIDO applet (SELECT: %04X %s).", sw, scSwName(sw));
	for (int i = 0; i < n && i < (int)sizeof(f->u2f) - 1 && ans[i] >= 0x20 && ans[i] < 0x7F; i++) f->u2f[i] = ans[i];

	// authenticatorGetInfo (0x04) in NFCCTAP_MSG
	static const u8 getInfo = 0x04;
	n = scCmd(0x80, 0x10, 0x00, 0x00, &getInfo, 1, true, ans, sizeof(ans), &sw);
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) FAIL(0, "%s", scWhy());
	f->infoSw = sw;
	if (sw == 0x9000 && n >= 1) {
		f->infoStatus = ans[0];
		if (!ans[0]) {
			f->rawLen = n - 1 < FIDO_RAW ? n - 1 : FIDO_RAW;
			memcpy(f->raw, ans + 1, f->rawLen);
			f->ctap2 = fidoParseInfo(f, ans + 1, n - 1);
		}
	}

	// authenticatorClientPIN getPINRetries ({1: protocol, 2: 1}): only says something with a PIN set
	if (f->ctap2 && fidoOpt(f, "clientPin") == 1) {
		u8 cmd[] = { 0x06, 0xA2, 0x01, f->npin ? f->pinProto[0] : 1, 0x02, 0x01 };
		n = scCmd(0x80, 0x10, 0x00, 0x00, cmd, sizeof(cmd), true, ans, sizeof(ans), &sw);
		if (n == -2) FAIL(-1, "monitor");
		if (n < 0) FAIL(0, "%s", scWhy());
		if (sw == 0x9000 && n > 1 && !ans[0]) {
			Cb c = { ans + 1, ans + n, false };
			int m, key;
			u64 k;
			if (cbHead(&c, &m, &k) && m == 5)
				for (u64 i = 0; i < k && !c.bad; i++) {
					if (cbInt(&c, &key) && key == 3) cbInt(&c, &f->pinRetries);
					else cbSkip(&c);
				}
		}
	}
	char g[37] = "-";
	if (f->hasAaguid) fidoAaguidText(f->aaguid, g);
	logp("FIDO: %s, getInfo %04X/%02X, %d versions, AAGUID %s\n", *f->u2f ? f->u2f : "-", f->infoSw, f->infoStatus,
		f->nver, g);
	return 1;
}

// --- names ---

static const struct {
	const char *aaguid, *name;
} models[] = {
	// from the FIDO Metadata Service
	{ "b50d5e0a7f8149599b12f45407407503", "Thales IDPrime 3940 FIDO" },
	{ "cb69481e8ff7403993ec0a2729a154a8", "YubiKey 5 (5.1)" },
	{ "fa2b99dc9e3942578f924a30d23c4118", "YubiKey 5 NFC (5.1)" },
	{ "ee882879721c491397753dfcce97072a", "YubiKey 5 (5.2 / 5.4)" },
	{ "2fc0579f811347eab116bb5a8db9202a", "YubiKey 5 NFC (5.2 / 5.4)" },
	{ "a25342c03cdc44148e46f4807fca511c", "YubiKey 5 NFC (5.7)" },
	{ "149a20218ef6413396b881f8d5b7f1f5", "Security Key NFC by Yubico" },
};

const char *fidoModel(const u8 aaguid[16])
{
	for (u32 i = 0; i < sizeof(models) / sizeof(models[0]); i++) {
		u8 g[16];
		if (scUnhex(models[i].aaguid, g, sizeof(g)) == 16 && !memcmp(g, aaguid, 16)) return models[i].name;
	}
	return NULL;
}

const char *fidoAlgName(int cose)
{
	switch (cose) {
	case -7: return "ES256";
	case -8: return "EdDSA";
	case -35: return "ES384";
	case -36: return "ES512";
	case -37: return "PS256";
	case -47: return "ES256K";
	case -257: return "RS256";
	case -65535: return "RS1";
	}
	return NULL;
}

void fidoAaguidText(const u8 g[16], char *out)
{
	for (int i = 0; i < 16; i++) out += sprintf(out, "%s%02x", i == 4 || i == 6 || i == 8 || i == 10 ? "-" : "", g[i]);
}

// --- the save file ---

bool fidoSave(const FidoInfo *f, char *path, u32 max)
{
	char g[37] = "key", h[2 * FIDO_RAW + 1];
	if (f->hasAaguid) fidoAaguidText(f->aaguid, g), g[8] = 0;
	mkdir(APP_DIR, 0777);
	mkdir(SC_DIR, 0777);
	struct stat st;
	for (int i = 1; i < 1000; i++) {
		if (i == 1) snprintf(path, max, SC_DIR "/fido-%s.txt", g);
		else snprintf(path, max, SC_DIR "/fido-%s-%d.txt", g, i);
		if (stat(path, &st)) break;
	}
	FILE *o = fopen(path, "w");
	if (!o) return false;
	fprintf(o, "FIDO security key\nSELECT           %s\n", *f->u2f ? f->u2f : "(no version string)");
	if (!f->ctap2) {
		fprintf(o, "getInfo          %04X %02X: U2F only\n", f->infoSw, f->infoStatus);
		fclose(o);
		return true;
	}
	if (f->hasAaguid) {
		fidoAaguidText(f->aaguid, g);
		fprintf(o, "AAGUID           %s %s\n", g, fidoModel(f->aaguid) ?: "");
	}
	fprintf(o, "Versions        ");
	for (int i = 0; i < f->nver; i++) fprintf(o, " %s", f->ver[i]);
	fprintf(o, "\nExtensions      ");
	for (int i = 0; i < f->next; i++) fprintf(o, " %s", f->ext[i]);
	fprintf(o, "\nOptions         ");
	for (int i = 0; i < f->nopt; i++) fprintf(o, " %s=%s", f->opt[i].name, f->opt[i].on ? "true" : "false");
	fprintf(o, "\nPIN protocols   ");
	for (int i = 0; i < f->npin; i++) fprintf(o, " %d", f->pinProto[i]);
	fprintf(o, "\nAlgorithms      ");
	for (int i = 0; i < f->nalg; i++) fprintf(o, " %d %s", f->alg[i], fidoAlgName(f->alg[i]) ?: "");
	fprintf(o, "\nTransports      ");
	for (int i = 0; i < f->ntrans; i++) fprintf(o, " %s", f->trans[i]);
	fprintf(o, "\n");
	if (f->maxMsg >= 0) fprintf(o, "Max message      %d\n", f->maxMsg);
	if (f->maxCredList >= 0) fprintf(o, "Max creds/list   %d\n", f->maxCredList);
	if (f->maxCredIdLen >= 0) fprintf(o, "Max cred ID      %d\n", f->maxCredIdLen);
	if (f->minPin >= 0) fprintf(o, "Min PIN length   %d\n", f->minPin);
	if (f->firmware >= 0) fprintf(o, "Firmware         %d (%06X)\n", f->firmware, f->firmware);
	if (f->remainingRk >= 0) fprintf(o, "Passkeys left    %d\n", f->remainingRk);
	if (f->forcePinChange) fprintf(o, "Force PIN change true\n");
	if (f->pinRetries >= 0) fprintf(o, "PIN tries left   %d\n", f->pinRetries);
	scHex(h, f->raw, f->rawLen);
	fprintf(o, "getInfo CBOR     %s\n", h);
	fclose(o);
	return true;
}
