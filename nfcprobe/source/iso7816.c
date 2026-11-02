// ISO 7816-4 over ISO-DEP, see iso7816.h.

#include <stdio.h>
#include <string.h>

#include "iso7816.h"
#include "isodep.h"

static char why[80];
u8 scMoreIns = 0xC0;

const char *scWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

int scActivate(u8 *ats, u32 max)
{
	int r = isoDepActivate(ats, max);
	if (r <= 0) FAIL(r, "%s", isoDepWhy());
	return 1;
}

int scApdu(const u8 *apdu, u32 len, u8 *out, u32 max, u16 *sw)
{
	static u8 a[SC_MAX_ANS + 2];
	u8 c[300];
	if (len < 4 || len > sizeof(c) - 1) FAIL(-1, "APDU of %lu bytes", len);
	memcpy(c, apdu, len);
	u32 got = 0, n6c = 0;
	for (;;) {
		int n = isoDepTx(c, len, a + got, sizeof(a) - got);
		if (n < 0) FAIL(-2, "monitor");
		if (n < 2) FAIL(-1, "lost the card: %s", isoDepWhy());
		got += n - 2;
		u16 s = a[got] << 8 | a[got + 1];
		if ((s >> 8) == 0x6C && !n6c++) {
			// wrong Le: the same command again with the one the card wants (case 2 / 4: Le is the last byte)
			if (len == 4 || (len > 5 && len == 5u + c[4])) c[len++] = s;
			else c[len - 1] = s;
			continue;
		}
		if ((s >> 8) == 0x61 && got < SC_MAX_ANS) {
			// more to come: GET RESPONSE (or the applet's own) for up to xx bytes (00 = 256)
			c[0] = 0x00, c[1] = scMoreIns, c[2] = c[3] = 0, c[4] = s, len = 5;
			continue;
		}
		*sw = s;
		u32 k = got < max ? got : max;
		memcpy(out, a, k);
		return k;
	}
}

int scCmd(u8 cla, u8 ins, u8 p1, u8 p2, const u8 *data, u32 lc, bool le, u8 *out, u32 max, u16 *sw)
{
	u8 c[262] = { cla, ins, p1, p2 };
	u32 len = 4;
	if (lc > 255) FAIL(-1, "data of %lu bytes", lc);
	if (lc) c[len++] = lc, memcpy(c + len, data, lc), len += lc;
	if (le) c[len++] = 0;
	return scApdu(c, len, out, max, sw);
}

int scSelect(const u8 *aid, u32 len, u8 *out, u32 max, u16 *sw)
{
	u8 c[262] = { 0x00, 0xA4, 0x04, 0x00, len };
	memcpy(c + 5, aid, len);
	c[5 + len] = 0;
	return scApdu(c, 6 + len, out, max, sw);
}

const char *scSwName(u16 sw)
{
	if ((sw & 0xFFF0) == 0x63C0) return "verify failed, tries left in low nibble";
	switch (sw) {
	case 0x9000: return "ok";
	case 0x6283: return "selected file deactivated / locked";
	case 0x6310: return "more data (GET STATUS)";
	case 0x6400: return "execution error";
	case 0x6581: return "memory failure";
	case 0x6700: return "wrong length";
	case 0x6881: return "logical channel not supported";
	case 0x6882: return "secure messaging not supported";
	case 0x6982: return "security status not satisfied";
	case 0x6983: return "authentication method blocked";
	case 0x6984: return "reference data not usable";
	case 0x6985: return "conditions of use not satisfied";
	case 0x6986: return "command not allowed";
	case 0x6988: return "secure messaging data wrong";
	case 0x6999: return "applet selection failed";
	case 0x6A80: return "wrong data";
	case 0x6A81: return "function not supported";
	case 0x6A82: return "file / applet not found";
	case 0x6A83: return "record not found";
	case 0x6A84: return "not enough memory";
	case 0x6A86: return "wrong P1 / P2";
	case 0x6A88: return "referenced data not found";
	case 0x6B00: return "wrong P1 / P2";
	case 0x6D00: return "instruction not supported";
	case 0x6E00: return "class not supported";
	case 0x6F00: return "no precise diagnosis";
	}
	return "error";
}

bool tlvNext(const u8 **pp, const u8 *end, Tlv *t)
{
	const u8 *p = *pp;
	while (p < end && (*p == 0x00 || *p == 0xFF)) p++;
	if (p >= end) return false;
	t->constructed = *p & 0x20;
	t->tag = *p;
	if ((*p++ & 0x1F) == 0x1F) {
		for (int i = 0; i < 2; i++) {
			if (p >= end) return false;
			t->tag = t->tag << 8 | *p;
			if (!(*p++ & 0x80)) break;
		}
	}
	if (p >= end) return false;
	u32 len = *p++;
	if (len == 0x81 || len == 0x82) {
		int k = len & 3;
		if (end - p < k) return false;
		len = k == 1 ? p[0] : p[0] << 8 | p[1];
		p += k;
	} else if (len > 0x80) {
		return false;
	}
	if ((u32)(end - p) < len) return false;
	t->v = p, t->len = len;
	*pp = p + len;
	return true;
}

static bool find(const u8 *p, const u8 *end, u32 tag, Tlv *t, int depth)
{
	Tlv x;
	while (tlvNext(&p, end, &x)) {
		if (x.tag == tag) {
			*t = x;
			return true;
		}
		if (x.constructed && depth < 6 && find(x.v, x.v + x.len, tag, t, depth + 1)) return true;
	}
	return false;
}

bool tlvFind(const u8 *p, u32 len, u32 tag, Tlv *t)
{
	return find(p, p + len, tag, t, 0);
}

void scHex(char *out, const u8 *p, u32 n)
{
	for (u32 i = 0; i < n; i++) sprintf(out + 2 * i, "%02X", p[i]);
	if (!n) *out = 0;
}

int scUnhex(const char *s, u8 *out, u32 max)
{
	u32 n = 0;
	int half = -1;
	for (; *s; s++) {
		int v = *s >= '0' && *s <= '9' ? *s - '0' : (*s | 0x20) >= 'a' && (*s | 0x20) <= 'f' ? (*s | 0x20) - 'a' + 10 : -1;
		if (*s == ' ' || *s == ':') continue;
		if (v < 0) return -1;
		if (half < 0) {
			half = v;
			continue;
		}
		if (n == max) return -1;
		out[n++] = half << 4 | v;
		half = -1;
	}
	return half < 0 ? (int)n : -1;
}

#define ADD(...) (o += snprintf(out + o, o < max ? max - o : 0, __VA_ARGS__))

void scAtsDesc(const u8 *ats, u32 len, char *out, u32 max)
{
	static const u16 fsc[] = { 16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024, 2048, 4096 };
	u32 o = 0, i = 2;
	*out = 0;
	if (len < 2) {
		ADD("ATS without T0: FSC 32, FWI 4, CID");
		return;
	}
	u8 t0 = ats[1];
	ADD("Card frames up to %d bytes (FSCI %d)\n", (t0 & 15) < 13 ? fsc[t0 & 15] : 4096, t0 & 15);
	if ((t0 & 0x10) && i < len) {
		u8 ta = ats[i++];
		char up[32] = "", dn[32] = "";
		static const char *const r[] = { "212", "424", "848" };
		for (int b = 0; b < 3; b++) {
			if (ta & (1 << b)) sprintf(up + strlen(up), "%s%s", *up ? "/" : "", r[b]);
			if (ta & (0x10 << b)) sprintf(dn + strlen(dn), "%s%s", *dn ? "/" : "", r[b]);
		}
		ADD("Bit rates: 106%s%s kbit/s to the card, 106%s%s back%s\n", *up ? "/" : "", up, *dn ? "/" : "", dn,
			ta & 0x80 ? " (same both ways)" : "");
	}
	if ((t0 & 0x20) && i < len) {
		u8 tb = ats[i++];
		u32 fwt = 302u << (tb >> 4); // 256 * 16 / fc * 2^FWI, in us
		ADD("Frame waiting time %lu.%lu ms (FWI %d), start-up guard SFGI %d\n", fwt / 1000, fwt % 1000 / 100, tb >> 4,
			tb & 15);
	}
	if ((t0 & 0x40) && i < len) {
		u8 tc = ats[i++];
		ADD("CID %s, NAD %s\n", tc & 2 ? "supported" : "no", tc & 1 ? "supported" : "no");
	}
	if (i >= len) {
		ADD("No historical bytes");
		return;
	}
	char hex[64], asc[32];
	u32 n = len - i < 30 ? len - i : 30, k = 0;
	scHex(hex, ats + i, n);
	for (u32 j = 0; j < n; j++) asc[k++] = ats[i + j] >= 32 && ats[i + j] < 127 ? ats[i + j] : '.';
	asc[k] = 0;
	ADD("Historical bytes %s \"%s\"", hex, asc);
}
