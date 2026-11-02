// YubiKey OATH, see oath.h. The protocol as in Yubico's yubikey-manager (oath.py) and ykneo-oath.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iso7816.h"
#include "mfckeys.h"
#include "oath.h"
#include "probe.h"
#include "sha1.h"

static char why[96];

const char *oathWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

enum { T_NAME = 0x71, T_NAME_LIST = 0x72, T_KEY = 0x73, T_CHAL = 0x74, T_RESP = 0x75, T_TRUNC = 0x76, T_HOTP = 0x77,
	T_PROP = 0x78, T_VERSION = 0x79, T_IMF = 0x7A, T_ALG = 0x7B, T_TOUCH = 0x7C };

static u32 rng;

static void rnd(u8 *p, u32 n)
{
	if (!rng) rng = (u32)osGetTime() * 2654435761u | 1;
	while (n--) {
		rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5;
		*p++ = rng >> 24;
	}
}

static u8 ans[SC_MAX_ANS];

// One command; SEND REMAINING for the rest. Answer length, FAIL on a lost card / monitor / SW not 9000.
#define CMD(ins, p1, p2, d, l) ({ \
	u16 sw_; \
	scMoreIns = 0xA5; \
	int r_ = scCmd(0x00, ins, p1, p2, d, l, true, ans, sizeof(ans), &sw_); \
	scMoreIns = 0xC0; \
	if (r_ == -2) FAIL(-1, "monitor"); \
	if (r_ < 0) FAIL(0, "%s", scWhy()); \
	if (sw_ == 0x6982) FAIL(0, "locked: the password first"); \
	if (sw_ != 0x9000) FAIL(0, "SW %04X %s", sw_, scSwName(sw_)); \
	r_; })

static u32 put(u8 *d, u32 o, u8 tag, const void *v, u32 len)
{
	d[o++] = tag;
	d[o++] = len;
	memcpy(d + o, v, len);
	return o + len;
}

int oathSelect(OathInfo *o)
{
	memset(o, 0, sizeof(*o));
	u8 ats[32], aid[8];
	int r = scActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", scWhy());
	u32 al = scUnhex(OATH_AID, aid, sizeof(aid));
	u16 sw;
	int n = scSelect(aid, al, ans, sizeof(ans), &sw);
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) FAIL(0, "%s", scWhy());
	if (sw != 0x9000) FAIL(0, "no OATH applet (SELECT: SW %04X)", sw);
	const u8 *p = ans, *end = ans + n;
	Tlv t;
	while (tlvNext(&p, end, &t)) {
		if (t.tag == T_VERSION && t.len >= 3) memcpy(o->ver, t.v, 3);
		else if (t.tag == T_NAME && t.len <= 8) memcpy(o->id, t.v, t.len), o->idLen = t.len;
		else if (t.tag == T_CHAL && t.len == 8) memcpy(o->chal, t.v, 8), o->locked = true;
		else if (t.tag == T_ALG && t.len) o->alg = t.v[0];
	}
	logp("OATH %d.%d.%d%s\n", o->ver[0], o->ver[1], o->ver[2], o->locked ? ", password set" : "");
	return 1;
}

void oathKey(const char *pw, const OathInfo *o, u8 key[16])
{
	pbkdf2Sha1((const u8 *)pw, strlen(pw), o->id, o->idLen, 1000, key, 16);
}

// The HMAC the applet's algorithm uses; length.
static int hmac(u8 alg, const u8 *key, u32 klen, const u8 *m, u32 len, u8 *out)
{
	if (alg == OATH_SHA256) {
		hmacSha256(key, klen, m, len, NULL, 0, out);
		return 32;
	}
	hmacSha1(key, klen, m, len, out);
	return 20;
}

int oathValidate(OathInfo *o, const u8 key[16])
{
	if (o->alg && o->alg != OATH_SHA1 && o->alg != OATH_SHA256) FAIL(0, "password algorithm %s", oathAlgName(o->alg));
	u8 d[80], resp[32], mine[8], expect[32];
	int rl = hmac(o->alg, key, 16, o->chal, 8, resp);
	rnd(mine, 8);
	u32 l = put(d, 0, T_RESP, resp, rl);
	l = put(d, l, T_CHAL, mine, 8);
	u16 sw;
	scMoreIns = 0xA5;
	int n = scCmd(0x00, 0xA3, 0x00, 0x00, d, l, true, ans, sizeof(ans), &sw);
	scMoreIns = 0xC0;
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) FAIL(0, "%s", scWhy());
	if (sw != 0x9000) FAIL(0, "wrong password");
	Tlv t;
	const u8 *p = ans;
	hmac(o->alg, key, 16, mine, 8, expect);
	if (!tlvNext(&p, ans + n, &t) || t.tag != T_RESP || (int)t.len != rl || memcmp(t.v, expect, rl))
		FAIL(0, "the card's answer doesn't check out");
	o->locked = false;
	return 1;
}

static u16 periodOf(const char *name)
{
	int v = 0, i = 0;
	while (name[i] >= '0' && name[i] <= '9' && i < 5) v = v * 10 + name[i++] - '0';
	return i && name[i] == '/' && v > 0 ? v : 30;
}

static int find(OathInfo *o, const u8 *name, u32 len)
{
	for (int i = 0; i < o->n; i++)
		if (strlen(o->c[i].name) == len && !memcmp(o->c[i].name, name, len)) return i;
	return -1;
}

static void chal(u8 *c, u64 step)
{
	for (int i = 0; i < 8; i++) c[i] = step >> (56 - 8 * i);
}

static void code(OathCred *c, const u8 *v, u32 len)
{
	if (len < 5) return;
	c->digits = v[0];
	u32 x = (v[1] << 24 | v[2] << 16 | v[3] << 8 | v[4]) & 0x7FFFFFFF;
	u32 m = 1;
	for (int i = 0; i < c->digits && i < 9; i++) m *= 10;
	c->code = x % m;
	c->hasCode = true;
}

static int cmpCred(const void *a, const void *b)
{
	const OathCred *x = a, *y = b;
	const char *p = strchr(x->name, '/'), *q = strchr(y->name, '/');
	return strcasecmp(x->period != 30 && p ? p + 1 : x->name, y->period != 30 && q ? q + 1 : y->name);
}

int oathCalc(OathInfo *o, int i, u64 t)
{
	OathCred *c = &o->c[i];
	u8 d[96], ch[8];
	u32 l = put(d, 0, T_NAME, c->name, strlen(c->name));
	c->step = t / c->period;
	chal(ch, c->step);
	l = put(d, l, T_CHAL, ch, c->type == OATH_HOTP ? 0 : 8);
	int n = CMD(0xA2, 0x00, 0x01, d, l);
	Tlv x;
	const u8 *p = ans;
	if (!tlvNext(&p, ans + n, &x) || x.tag != T_TRUNC) FAIL(0, "no code in the answer");
	code(c, x.v, x.len);
	return 1;
}

int oathList(OathInfo *o, u64 t)
{
	o->n = 0;
	int n = CMD(0xA1, 0x00, 0x00, NULL, 0);
	const u8 *p = ans, *end = ans + n;
	Tlv x;
	while (tlvNext(&p, end, &x) && o->n < OATH_MAX) {
		if (x.tag != T_NAME_LIST || !x.len) continue;
		OathCred *c = &o->c[o->n++];
		memset(c, 0, sizeof(*c));
		c->type = x.v[0] & 0xF0, c->alg = x.v[0] & 0x0F;
		u32 k = x.len - 1 < 64 ? x.len - 1 : 64;
		memcpy(c->name, x.v + 1, k);
		c->name[k] = 0;
		c->period = periodOf(c->name);
	}
	// CALCULATE ALL: every 30 s TOTP (the rest get a code too, for the wrong step: done again below)
	u8 d[12], ch[8];
	chal(ch, t / 30);
	u32 l = put(d, 0, T_CHAL, ch, 8);
	n = CMD(0xA4, 0x00, 0x01, d, l);
	p = ans, end = ans + n;
	int cur = -1;
	while (tlvNext(&p, end, &x)) {
		if (x.tag == T_NAME) {
			cur = find(o, x.v, x.len);
			continue;
		}
		if (cur < 0) continue;
		OathCred *c = &o->c[cur];
		if (x.tag == T_TRUNC && c->period == 30) code(c, x.v, x.len), c->step = t / 30;
		else if (x.tag == T_TOUCH) c->touch = true;
		if (x.len) c->digits = x.v[0];
		cur = -1;
	}
	for (int i = 0; i < o->n; i++) {
		OathCred *c = &o->c[i];
		if (c->type == OATH_TOTP && c->period != 30 && !c->touch) {
			int r = oathCalc(o, i, t);
			if (r < 0) return r;
		}
	}
	qsort(o->c, o->n, sizeof(o->c[0]), cmpCred);
	logp("OATH: %d account%s\n", o->n, o->n == 1 ? "" : "s");
	return 1;
}

int oathPut(const char *name, u8 type, u8 alg, u8 digits, const u8 *secret, u32 len, bool touch, u32 counter)
{
	u8 d[200], k[66];
	u32 nl = strlen(name);
	if (!nl || nl > 64) FAIL(0, "the name takes 1-64 bytes");
	if (len > 64) {
		if (alg != OATH_SHA1) FAIL(0, "secret longer than 64 bytes");
		sha1(secret, len, k + 2), len = 20; // HMAC does the same with a long key
	} else {
		memcpy(k + 2, secret, len);
	}
	while (len < 14) k[2 + len++] = 0; // the applet wants 14 or more; HMAC pads with zeros anyway
	k[0] = type | alg, k[1] = digits;
	u32 l = put(d, 0, T_NAME, name, nl);
	l = put(d, l, T_KEY, k, 2 + len);
	if (touch) d[l++] = T_PROP, d[l++] = 0x02; // property: require touch (no length byte)
	if (type == OATH_HOTP && counter) {
		u8 c[4] = { counter >> 24, counter >> 16, counter >> 8, counter };
		l = put(d, l, T_IMF, c, 4);
	}
	CMD(0x01, 0x00, 0x00, d, l);
	logp("OATH: added %s\n", name);
	return 1;
}

int oathDelete(const char *name)
{
	u8 d[70];
	u32 l = put(d, 0, T_NAME, name, strlen(name));
	CMD(0x02, 0x00, 0x00, d, l);
	logp("OATH: deleted %s\n", name);
	return 1;
}

int oathSetCode(const u8 *key)
{
	u8 d[80], kk[17] = { OATH_TOTP | OATH_SHA1 }, ch[8], resp[20];
	u32 l;
	if (!key) {
		l = put(d, 0, T_KEY, kk, 0);
	} else {
		memcpy(kk + 1, key, 16);
		rnd(ch, 8);
		hmacSha1(key, 16, ch, 8, resp);
		l = put(d, 0, T_KEY, kk, 17);
		l = put(d, l, T_CHAL, ch, 8);
		l = put(d, l, T_RESP, resp, 20);
	}
	CMD(0x03, 0x00, 0x00, d, l);
	logp("OATH: password %s\n", key ? "set" : "removed");
	return 1;
}

void oathFormat(const OathCred *c, char *out)
{
	sprintf(out, "%0*lu", c->digits < 10 ? c->digits : 9, c->code);
}

const char *oathAlgName(u8 alg)
{
	return alg == OATH_SHA1 ? "SHA-1" : alg == OATH_SHA256 ? "SHA-256" : alg == OATH_SHA512 ? "SHA-512" : "?";
}

int base32Decode(const char *s, u8 *out, u32 max)
{
	u32 n = 0, buf = 0;
	int bits = 0;
	for (; *s; s++) {
		char ch = *s;
		if (ch == ' ' || ch == '-' || ch == '=') continue;
		int v = ch >= 'A' && ch <= 'Z' ? ch - 'A' : ch >= 'a' && ch <= 'z' ? ch - 'a' : ch >= '2' && ch <= '7' ? ch - '2' + 26 : -1;
		if (v < 0) return -1;
		buf = buf << 5 | v;
		bits += 5;
		if (bits >= 8) {
			if (n == max) return -1;
			out[n++] = buf >> (bits - 8);
			bits -= 8;
		}
	}
	return n;
}
