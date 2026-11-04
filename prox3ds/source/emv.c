// EMV contactless payment cards, read only, see emv.h. Terminal behaviour as in pm3's client/src/emv
// (cmdemv.c `emv reader`: its PDOL defaults, AFL walk, log read).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "app.h"
#include "emv.h"
#include "probe.h"

static char why[96];

const char *emvWhy(void)
{
	return why;
}

#define FAIL(ret, ...) ({ snprintf(why, sizeof(why), __VA_ARGS__); return (ret); })

static u8 ans[SC_MAX_ANS];
static int lost; // an APDU lost the card (-1) or the monitor (-2), 0 = fine

// One command; the answer in ans, its length (0 on a lost card: lost says which), *sw its status.
static int cmd(u8 cla, u8 ins, u8 p1, u8 p2, const u8 *d, u32 lc, u16 *sw)
{
	if (lost) return 0;
	int n = scCmd(cla, ins, p1, p2, d, lc, true, ans, sizeof(ans), sw);
	if (n < 0) {
		lost = n;
		*sw = 0;
		return 0;
	}
	return n;
}

static void raw(EmvApp *a, u8 kind, u8 p1, u8 p2, const u8 *d, u32 len)
{
	if (a->rawLen + 5u + len > sizeof(a->raw)) return;
	u8 *p = a->raw + a->rawLen;
	p[0] = kind, p[1] = p1, p[2] = p2, p[3] = len, p[4] = len >> 8;
	memcpy(p + 5, d, len);
	a->rawLen += 5 + len;
}

// --- brands, countries, currencies ---

static const struct { const char *rid, *name; } brands[] = {
	{ "A000000003", "Visa" }, { "A000000004", "Mastercard" }, { "A000000025", "American Express" },
	{ "A000000065", "JCB" }, { "A000000152", "Discover" }, { "A000000324", "Discover" },
	{ "A000000333", "UnionPay" }, { "A000000277", "Interac" }, { "A000000359", "girocard" },
	{ "A000000042", "CB" }, { "A000000658", "Mir" }, { "A000000384", "eftpos" }, { "A000000524", "RuPay" },
	{ "A000000098", "Visa (US debit)" }, { "A000000172", "Banricompras" },
};

// When the PPSE doesn't answer: these, one by one
static const char *const knownAids[] = {
	"A0000000031010", "A0000000032010", "A0000000032020", "A0000000041010", "A0000000043060",
	"A00000002501", "A0000000651010", "A0000001523010", "A000000333010101", "A000000333010102",
	"A0000002771010", "A0000003591010028001", "A0000000421010", "A0000006581010",
};

const char *emvBrand(const u8 *aid, u32 len)
{
	for (u32 i = 0; i < sizeof(brands) / sizeof(brands[0]); i++) {
		u8 r[5];
		scUnhex(brands[i].rid, r, 5);
		if (len >= 5 && !memcmp(aid, r, 5)) {
			// Maestro, Visa Electron, V Pay: the PIX tells them apart
			if (!memcmp(r, "\xA0\x00\x00\x00\x04", 5) && len >= 7 && aid[5] == 0x30 && aid[6] == 0x60) return "Maestro";
			if (!memcmp(r, "\xA0\x00\x00\x00\x03", 5) && len >= 7 && aid[5] == 0x20 && aid[6] == 0x10) return "Visa Electron";
			if (!memcmp(r, "\xA0\x00\x00\x00\x03", 5) && len >= 7 && aid[5] == 0x20 && aid[6] == 0x20) return "V Pay";
			return brands[i].name;
		}
	}
	return "";
}

static const struct { u16 code; const char *name; } countries[] = {
	{ 0x0036, "Australia" }, { 0x0040, "Austria" }, { 0x0056, "Belgium" }, { 0x0076, "Brazil" },
	{ 0x0124, "Canada" }, { 0x0156, "China" }, { 0x0203, "Czechia" }, { 0x0208, "Denmark" },
	{ 0x0246, "Finland" }, { 0x0250, "France" }, { 0x0276, "Germany" }, { 0x0300, "Greece" },
	{ 0x0344, "Hong Kong" }, { 0x0348, "Hungary" }, { 0x0352, "Iceland" }, { 0x0356, "India" },
	{ 0x0372, "Ireland" }, { 0x0376, "Israel" }, { 0x0380, "Italy" }, { 0x0392, "Japan" },
	{ 0x0410, "South Korea" }, { 0x0442, "Luxembourg" }, { 0x0484, "Mexico" }, { 0x0528, "Netherlands" },
	{ 0x0554, "New Zealand" }, { 0x0578, "Norway" }, { 0x0616, "Poland" }, { 0x0620, "Portugal" },
	{ 0x0642, "Romania" }, { 0x0643, "Russia" }, { 0x0702, "Singapore" }, { 0x0710, "South Africa" },
	{ 0x0724, "Spain" }, { 0x0752, "Sweden" }, { 0x0756, "Switzerland" }, { 0x0784, "UAE" },
	{ 0x0792, "Turkey" }, { 0x0804, "Ukraine" }, { 0x0826, "United Kingdom" }, { 0x0840, "USA" },
};

const char *emvCountry(u16 code)
{
	for (u32 i = 0; i < sizeof(countries) / sizeof(countries[0]); i++)
		if (countries[i].code == code) return countries[i].name;
	return NULL;
}

static const struct { u16 code; const char *name; u8 digits; } currencies[] = {
	{ 0x0036, "AUD", 2 }, { 0x0124, "CAD", 2 }, { 0x0156, "CNY", 2 }, { 0x0203, "CZK", 2 }, { 0x0208, "DKK", 2 },
	{ 0x0344, "HKD", 2 }, { 0x0348, "HUF", 2 }, { 0x0352, "ISK", 0 }, { 0x0356, "INR", 2 }, { 0x0376, "ILS", 2 },
	{ 0x0392, "JPY", 0 }, { 0x0410, "KRW", 0 }, { 0x0484, "MXN", 2 }, { 0x0554, "NZD", 2 }, { 0x0578, "NOK", 2 },
	{ 0x0643, "RUB", 2 }, { 0x0702, "SGD", 2 }, { 0x0710, "ZAR", 2 }, { 0x0752, "SEK", 2 }, { 0x0756, "CHF", 2 },
	{ 0x0784, "AED", 2 }, { 0x0826, "GBP", 2 }, { 0x0840, "USD", 2 }, { 0x0946, "RON", 2 }, { 0x0949, "TRY", 2 },
	{ 0x0978, "EUR", 2 }, { 0x0980, "UAH", 2 }, { 0x0985, "PLN", 2 }, { 0x0986, "BRL", 2 },
};

const char *emvCurrency(u16 code, int *digits)
{
	for (u32 i = 0; i < sizeof(currencies) / sizeof(currencies[0]); i++) {
		if (currencies[i].code == code) {
			if (digits) *digits = currencies[i].digits;
			return currencies[i].name;
		}
	}
	if (digits) *digits = 2;
	return NULL;
}

void emvAmount(const u8 bcd[6], u16 currency, char *out)
{
	u64 v = 0;
	for (int i = 0; i < 6; i++) v = v * 100 + (bcd[i] >> 4) * 10 + (bcd[i] & 15);
	int digits;
	const char *c = emvCurrency(currency, &digits);
	char cur[8];
	if (c) snprintf(cur, sizeof(cur), "%s", c);
	else snprintf(cur, sizeof(cur), "(%03X)", currency);
	if (!digits) snprintf(out, 32, "%llu %s", v, cur);
	else snprintf(out, 32, "%llu.%02llu %s", v / 100, v % 100, cur);
}

void emvPanText(const char *pan, bool full, char *out)
{
	int n = strlen(pan), o = 0;
	for (int i = 0; i < n && o < 30; i++) {
		if (i && !(i % 4)) out[o++] = ' ';
		out[o++] = full || i >= n - 4 ? pan[i] : '*';
	}
	out[o] = 0;
}

void emvAuthText(u16 aip, char *out)
{
	int o = 0;
	*out = 0;
	if (aip & 0x4000) o += sprintf(out + o, "SDA ");
	if (aip & 0x2000) o += sprintf(out + o, "DDA ");
	if (aip & 0x0100) o += sprintf(out + o, "CDA ");
	if (!o) o += sprintf(out, "no offline auth ");
	out[--o] = 0;
	if (aip & 0x1000) sprintf(out + o, ", cardholder verification");
}

// --- the TLVs we read ---

static int bcd2(u8 b)
{
	return (b >> 4) * 10 + (b & 15);
}

// Digits of a BCD / track 2 field until the first nibble above 9 (F padding, the D separator)
static int digits(const u8 *v, u32 len, char *out, int max, int *sepAt)
{
	int n = 0;
	for (u32 i = 0; i < 2 * len && n < max; i++) {
		u8 d = i & 1 ? v[i / 2] & 15 : v[i / 2] >> 4;
		if (d > 9) {
			if (sepAt) *sepAt = i;
			break;
		}
		out[n++] = '0' + d;
	}
	out[n] = 0;
	return n;
}

static u8 nib(const u8 *v, u32 i)
{
	return i & 1 ? v[i / 2] & 15 : v[i / 2] >> 4;
}

// Track 2 (57 / 9F6B): PAN D YYMM service code ...
static void track2(EmvApp *a, const u8 *v, u32 len)
{
	char pan[20];
	int sep = -1;
	digits(v, len, pan, 19, &sep);
	if (sep < 0 || nib(v, sep) != 0xD) return;
	if (!*a->pan) snprintf(a->pan, sizeof(a->pan), "%s", pan);
	u32 i = sep + 1;
	if (i + 7 > 2 * len) return;
	if (!a->hasExp) {
		a->exp[0] = nib(v, i) << 4 | nib(v, i + 1), a->exp[1] = nib(v, i + 2) << 4 | nib(v, i + 3), a->exp[2] = 0;
		a->hasExp = true;
	}
	if (a->svc < 0) a->svc = nib(v, i + 4) * 100 + nib(v, i + 5) * 10 + nib(v, i + 6);
}

static u16 num2(const u8 *v)
{
	return v[0] << 8 | v[1];
}

static void absorb(EmvApp *a, const u8 *p, u32 len, int depth)
{
	const u8 *end = p + len;
	Tlv t;
	while (tlvNext(&p, end, &t)) {
		if (t.constructed) {
			if (depth < 6) absorb(a, t.v, t.len, depth + 1);
			continue;
		}
		switch (t.tag) {
		case 0x5A:
			digits(t.v, t.len, a->pan, 19, NULL);
			break;
		case 0x57:
		case 0x9F6B:
			track2(a, t.v, t.len);
			break;
		case 0x5F24:
			if (t.len == 3) memcpy(a->exp, t.v, 3), a->hasExp = true;
			break;
		case 0x5F25:
			if (t.len == 3) memcpy(a->eff, t.v, 3), a->hasEff = true;
			break;
		case 0x5F20: {
			u32 n = t.len < sizeof(a->name) - 1 ? t.len : sizeof(a->name) - 1;
			for (u32 i = 0; i < n; i++) a->name[i] = t.v[i] >= 32 && t.v[i] < 127 ? t.v[i] : ' ';
			a->name[n] = 0;
			while (n && (a->name[n - 1] == ' ' || a->name[n - 1] == '/')) a->name[--n] = 0;
			break;
		}
		case 0x5F28:
			if (t.len == 2) a->country = num2(t.v);
			break;
		case 0x9F42:
			if (t.len == 2) a->currency = num2(t.v);
			break;
		case 0x5F34:
			if (t.len == 1) a->panSeq = bcd2(t.v[0]);
			break;
		case 0x5F30:
			if (t.len == 2) a->svc = (t.v[0] & 15) * 100 + bcd2(t.v[1]);
			break;
		case 0x82:
			if (t.len == 2) a->aip = num2(t.v), a->hasAip = true;
			break;
		case 0x9F36:
			if (t.len == 2) a->atc = num2(t.v);
			break;
		case 0x9F13:
			if (t.len == 2) a->lastOnlineAtc = num2(t.v);
			break;
		case 0x9F17:
			if (t.len == 1) a->pinTries = t.v[0];
			break;
		case 0x9F4D:
			if (t.len == 2) a->logSfi = t.v[0], a->logMax = t.v[1];
			break;
		case 0x87:
			if (t.len == 1) a->prio = t.v[0] & 15;
			break;
		case 0x50:
		case 0x9F12:
			if (t.tag == 0x9F12 || !*a->label) {
				u32 n = t.len < sizeof(a->label) - 1 ? t.len : sizeof(a->label) - 1;
				for (u32 i = 0; i < n; i++) a->label[i] = t.v[i] >= 32 && t.v[i] < 127 ? t.v[i] : '?';
				a->label[n] = 0;
			}
			break;
		}
	}
}

// --- the terminal side: PDOL / log format (a DOL: tag, length; no values) ---

static u32 rng;

static u8 rnd8(void)
{
	if (!rng) rng = (u32)osGetTime() * 2654435761u | 1;
	rng ^= rng << 13, rng ^= rng >> 17, rng ^= rng << 5;
	return rng >> 24;
}

static bool dolNext(const u8 **p, const u8 *end, u32 *tag, u32 *len)
{
	const u8 *q = *p;
	if (q >= end) return false;
	*tag = *q;
	if ((*q++ & 0x1F) == 0x1F) {
		for (int i = 0; i < 2 && q < end; i++) {
			*tag = *tag << 8 | *q;
			if (!(*q++ & 0x80)) break;
		}
	}
	if (q >= end) return false;
	*len = *q++;
	*p = q;
	return true;
}

static u8 bcd(int v)
{
	return (v / 10 % 10) << 4 | v % 10;
}

// One PDOL entry's value: ours where we have one (numbers right aligned, the rest left), zeros otherwise
static void dolValue(u32 tag, u8 *out, u32 len)
{
	u8 v[16];
	u32 n = 0;
	bool numeric = false;
	time_t now = (time_t)unixNow();
	struct tm *tm = gmtime(&now);
	switch (tag) {
	case 0x9F66: memcpy(v, "\x26\x00\x00\x00", n = 4); break; // TTQ: qVSDC, contactless EMV (pm3's)
	case 0x9F02: memcpy(v, "\x00\x00\x00\x00\x01\x00", n = 6), numeric = true; break; // amount 1.00
	case 0x9F1A: case 0x5F2A: memcpy(v, "\x08\x40", n = 2), numeric = true; break; // USA, USD
	case 0x9A: v[0] = bcd(tm->tm_year), v[1] = bcd(tm->tm_mon + 1), v[2] = bcd(tm->tm_mday), n = 3, numeric = true; break;
	case 0x9F21: v[0] = bcd(tm->tm_hour), v[1] = bcd(tm->tm_min), v[2] = bcd(tm->tm_sec), n = 3, numeric = true; break;
	case 0x9C: v[0] = 0, n = 1, numeric = true; break; // purchase
	case 0x9F37: case 0x9F6A: for (n = 0; n < 4; n++) v[n] = rnd8(); break; // unpredictable number
	case 0x9F35: v[0] = 0x22, n = 1; break; // attended, offline with online capability
	case 0x9F4E: memcpy(v, "Prox3DS", n = 7); break;
	}
	memset(out, 0, len);
	if (numeric && n < len) memcpy(out + len - n, v, n);
	else memcpy(out, v, n < len ? n : len);
}

static u32 dolFill(const u8 *dol, u32 dlen, u8 *out, u32 max)
{
	const u8 *p = dol, *end = dol + dlen;
	u32 tag, len, o = 0;
	while (dolNext(&p, end, &tag, &len) && o + len <= max) {
		dolValue(tag, out + o, len);
		o += len;
	}
	return o;
}

static void logEntry(EmvLog *l, const u8 *fmt, u32 flen, const u8 *rec, u32 rlen)
{
	const u8 *p = fmt, *end = fmt + flen;
	u32 tag, len, o = 0;
	memset(l, 0, sizeof(*l));
	while (dolNext(&p, end, &tag, &len) && o + len <= rlen) {
		const u8 *v = rec + o;
		o += len;
		switch (tag) {
		case 0x9A: if (len == 3) memcpy(l->date, v, 3), l->has |= LOG_DATE; break;
		case 0x9F21: if (len == 3) memcpy(l->time, v, 3), l->has |= LOG_TIME; break;
		case 0x9F02: if (len == 6) memcpy(l->amount, v, 6), l->has |= LOG_AMOUNT; break;
		case 0x5F2A: if (len == 2) l->currency = num2(v), l->has |= LOG_CUR; break;
		case 0x9F1A: if (len == 2) l->country = num2(v), l->has |= LOG_COUNTRY; break;
		case 0x9C: if (len == 1) l->type = v[0], l->has |= LOG_TYPE; break;
		case 0x9F36: if (len == 2) l->atc = num2(v), l->has |= LOG_ATC; break;
		case 0x9F4E: {
			u32 n = len < sizeof(l->merchant) - 1 ? len : sizeof(l->merchant) - 1, k = 0;
			for (u32 i = 0; i < n; i++)
				if (v[i] >= 32 && v[i] < 127) l->merchant[k++] = v[i];
			while (k && l->merchant[k - 1] == ' ') k--;
			l->merchant[k] = 0;
			if (k) l->has |= LOG_MERCHANT;
			break;
		}
		}
	}
}

// --- one application ---

static int readRecord(EmvApp *a, u8 sfi, u8 rec, bool absorbIt)
{
	u16 sw;
	int n = cmd(0x00, 0xB2, rec, sfi << 3 | 4, NULL, 0, &sw);
	if (lost || sw != 0x9000) return 0;
	raw(a, absorbIt ? 'R' : 'L', rec, sfi, ans, n);
	if (absorbIt) absorb(a, ans, n, 0), a->nrec++;
	return n;
}

static void getData(EmvApp *a, u16 tag)
{
	u16 sw;
	int n = cmd(0x80, 0xCA, tag >> 8, tag, NULL, 0, &sw);
	if (lost || sw != 0x9000) return;
	raw(a, 'D', tag >> 8, tag, ans, n);
	absorb(a, ans, n, 0);
}

static void readApp(EmvApp *a)
{
	u16 sw;
	static u8 pdol[256], fmt[64];
	u32 pdolLen = 0, fmtLen = 0;
	a->panSeq = a->svc = a->atc = a->lastOnlineAtc = a->pinTries = -1;

	int n = scSelect(a->aid, a->aidLen, ans, sizeof(ans), &sw);
	if (n < 0) {
		lost = n;
		return;
	}
	if (sw != 0x9000) {
		snprintf(a->why, sizeof(a->why), "SELECT: %04X %s", sw, scSwName(sw));
		return;
	}
	a->selected = true;
	raw(a, 'S', 0, 0, ans, n);
	char label[33];
	snprintf(label, sizeof(label), "%s", a->label);
	*a->label = 0;
	absorb(a, ans, n, 0);
	if (!*a->label) snprintf(a->label, sizeof(a->label), "%s", label);
	Tlv t;
	if (tlvFind(ans, n, 0x9F38, &t) && t.len <= sizeof(pdol)) memcpy(pdol, t.v, pdolLen = t.len);

	// GET PROCESSING OPTIONS: 83 + the PDOL's values
	u8 gpo[260];
	u32 dl = dolFill(pdol, pdolLen, gpo + 3, sizeof(gpo) - 3), o;
	if (dl < 0x80) gpo[1] = 0x83, gpo[2] = dl, o = 1;
	else gpo[0] = 0x83, gpo[1] = 0x81, gpo[2] = dl, o = 0;
	n = cmd(0x80, 0xA8, 0x00, 0x00, gpo + o, 3 - o + dl, &sw);
	if (lost) return;
	const u8 *afl = NULL;
	u32 aflLen = 0;
	if (sw == 0x9000) {
		raw(a, 'G', 0, 0, ans, n);
		const u8 *p = ans;
		if (n >= 2 && ans[0] == 0x80 && tlvNext(&p, ans + n, &t) && t.len >= 2) {
			// format 1: AIP, AFL
			a->aip = num2(t.v), a->hasAip = true;
			afl = t.v + 2, aflLen = t.len - 2;
		} else {
			absorb(a, ans, n, 0);
			if (tlvFind(ans, n, 0x94, &t)) afl = t.v, aflLen = t.len;
		}
	} else {
		snprintf(a->why, sizeof(a->why), "GET PROCESSING OPTIONS: %04X %s", sw, scSwName(sw));
	}

	// the records: the AFL's (copied, ans gets overwritten), else every SFI 1-10 the card has
	u8 aflCopy[64];
	aflLen = aflLen > sizeof(aflCopy) ? sizeof(aflCopy) : aflLen & ~3u;
	if (afl) memcpy(aflCopy, afl, aflLen);
	if (afl) {
		for (u32 i = 0; i + 4 <= aflLen && !lost; i += 4)
			for (int r = aflCopy[i + 1]; r <= aflCopy[i + 2] && r && !lost; r++) readRecord(a, aflCopy[i] >> 3, r, true);
	} else {
		for (int sfi = 1; sfi <= 10 && !lost; sfi++)
			for (int r = 1; r <= 16 && readRecord(a, sfi, r, true); r++);
	}
	getData(a, 0x9F36);
	getData(a, 0x9F13);
	getData(a, 0x9F17);
	if (lost || !a->logSfi) return;

	// the transaction log: its format, then up to logMax records
	n = cmd(0x80, 0xCA, 0x9F, 0x4F, NULL, 0, &sw);
	if (lost) return;
	if (sw == 0x9000) {
		raw(a, 'D', 0x9F, 0x4F, ans, n);
		if (tlvFind(ans, n, 0x9F4F, &t) && t.len <= sizeof(fmt)) memcpy(fmt, t.v, fmtLen = t.len);
	}
	if (!fmtLen) {
		if (!*a->why) snprintf(a->why, sizeof(a->why), "No log format (GET DATA 9F4F: %04X)", sw);
		return;
	}
	for (int r = 1; r <= a->logMax && a->nlog < EMV_MAX_LOG && !lost; r++) {
		n = readRecord(a, a->logSfi, r, false);
		if (!n) break;
		logEntry(&a->log[a->nlog++], fmt, fmtLen, ans, n);
	}
}

// --- the card ---

static int byPrio(const void *x, const void *y)
{
	const EmvApp *a = x, *b = y;
	return (a->prio ? a->prio : 16) - (b->prio ? b->prio : 16);
}

int emvRead(EmvCard *e)
{
	memset(e, 0, sizeof(*e));
	lost = 0;
	u8 ats[32];
	int r = scActivate(ats, sizeof(ats));
	if (r <= 0) FAIL(r, "%s", scWhy());
	u16 sw;
	static const u8 ppse[] = "2PAY.SYS.DDF01";
	int n = scSelect(ppse, 14, ans, sizeof(ans), &sw);
	if (n == -2) FAIL(-1, "monitor");
	if (n < 0) FAIL(0, "%s", scWhy());
	if (sw == 0x9000) {
		// the directory: 61 entries (4F AID, 50 label, 87 priority) under BF0C
		const u8 *p = ans, *end = ans + n;
		Tlv t, bf;
		if (tlvFind(ans, n, 0xBF0C, &bf)) p = bf.v, end = bf.v + bf.len;
		while (tlvNext(&p, end, &t) && e->napps < EMV_MAX_APPS) {
			if (t.tag != 0x61) continue;
			Tlv x;
			if (!tlvFind(t.v, t.len, 0x4F, &x) || x.len < 5 || x.len > 16) continue;
			EmvApp *a = &e->app[e->napps++];
			memcpy(a->aid, x.v, a->aidLen = x.len);
			absorb(a, t.v, t.len, 0);
		}
		e->ppse = e->napps > 0;
		qsort(e->app, e->napps, sizeof(e->app[0]), byPrio);
	}
	if (!e->napps) {
		for (u32 i = 0; i < sizeof(knownAids) / sizeof(knownAids[0]) && e->napps < EMV_MAX_APPS; i++) {
			u8 aid[16];
			int al = scUnhex(knownAids[i], aid, sizeof(aid));
			n = scSelect(aid, al, ans, sizeof(ans), &sw);
			if (n == -2) FAIL(-1, "monitor");
			if (n < 0) FAIL(0, "%s", scWhy());
			if (sw != 0x9000) continue;
			EmvApp *a = &e->app[e->napps++];
			memcpy(a->aid, aid, a->aidLen = al);
		}
	}
	if (!e->napps) FAIL(0, "No payment application (no PPSE, none of %d known AIDs)",
		(int)(sizeof(knownAids) / sizeof(knownAids[0])));
	for (int i = 0; i < e->napps && !lost; i++) {
		readApp(&e->app[i]);
		EmvApp *a = &e->app[i];
		char h[40];
		scHex(h, a->aid, a->aidLen);
		logp("EMV %s %s: %d records, %d log entries%s%s\n", h, a->label, a->nrec, a->nlog, *a->why ? "; " : "", a->why);
	}
	if (lost == -2) FAIL(-1, "monitor");
	if (lost) FAIL(0, "%s", scWhy());
	return 1;
}

// --- the save file ---

static void ymd(char *out, const u8 *d, bool day)
{
	if (day) sprintf(out, "20%02X-%02X-%02X", d[0], d[1], d[2]);
	else sprintf(out, "%02X/%02X", d[1], d[0]);
}

bool emvSave(const EmvCard *e, char *path, u32 max)
{
	const char *last4 = "card";
	for (int i = 0; i < e->napps; i++)
		if (strlen(e->app[i].pan) >= 4) {
			last4 = e->app[i].pan + strlen(e->app[i].pan) - 4;
			break;
		}
	mkdir(APP_DIR, 0777);
	mkdir(SC_DIR, 0777);
	struct stat st;
	for (int i = 1; i < 1000; i++) {
		if (i == 1) snprintf(path, max, SC_DIR "/emv-%s.txt", last4);
		else snprintf(path, max, SC_DIR "/emv-%s-%d.txt", last4, i);
		if (stat(path, &st)) break;
	}
	FILE *f = fopen(path, "w");
	if (!f) return false;
	static char h[2 * SC_MAX_ANS + 1];
	fprintf(f, "EMV payment card, %s\n", e->ppse ? "applications from the PPSE" : "no PPSE: known AIDs tried");
	for (int i = 0; i < e->napps; i++) {
		const EmvApp *a = &e->app[i];
		char s[64];
		scHex(h, a->aid, a->aidLen);
		fprintf(f, "\nApplication %s  %s  %s\n", h, a->label, emvBrand(a->aid, a->aidLen));
		if (*a->why) fprintf(f, "  %s\n", a->why);
		if (*a->pan) fprintf(f, "  Card number      %s\n", a->pan);
		if (a->hasExp) ymd(s, a->exp, a->exp[2]), fprintf(f, "  Expires          %s\n", s);
		if (a->hasEff) ymd(s, a->eff, true), fprintf(f, "  Effective        %s\n", s);
		if (*a->name) fprintf(f, "  Cardholder       %s\n", a->name);
		if (a->panSeq >= 0) fprintf(f, "  PAN sequence     %02d\n", a->panSeq);
		if (a->svc >= 0) fprintf(f, "  Service code     %03d\n", a->svc);
		if (a->country) fprintf(f, "  Issuer country   %03X %s\n", a->country, emvCountry(a->country) ?: "");
		if (a->currency) fprintf(f, "  Currency         %03X %s\n", a->currency, emvCurrency(a->currency, NULL) ?: "");
		if (a->hasAip) emvAuthText(a->aip, s), fprintf(f, "  AIP              %04X %s\n", a->aip, s);
		if (a->atc >= 0) fprintf(f, "  ATC              %d\n", a->atc);
		if (a->lastOnlineAtc >= 0) fprintf(f, "  Last online ATC  %d\n", a->lastOnlineAtc);
		if (a->pinTries >= 0) fprintf(f, "  PIN tries left   %d\n", a->pinTries);
		fprintf(f, "  Records read     %d\n", a->nrec);
		if (a->logSfi) fprintf(f, "  Log              SFI %d, up to %d entries, %d read\n", a->logSfi, a->logMax, a->nlog);
		for (int j = 0; j < a->nlog; j++) {
			const EmvLog *l = &a->log[j];
			char d[16] = "", t[16] = "", am[32] = "";
			if (l->has & LOG_DATE) ymd(d, l->date, true);
			if (l->has & LOG_TIME) sprintf(t, "%02X:%02X:%02X", l->time[0], l->time[1], l->time[2]);
			if (l->has & LOG_AMOUNT) emvAmount(l->amount, l->currency, am);
			fprintf(f, "    %2d  %s %s  %s", j + 1, d, t, am);
			if (l->has & LOG_TYPE) fprintf(f, "  type %02X", l->type);
			if (l->has & LOG_COUNTRY) fprintf(f, "  %s", emvCountry(l->country) ?: "?");
			if (l->has & LOG_ATC) fprintf(f, "  ATC %d", l->atc);
			if (l->has & LOG_MERCHANT) fprintf(f, "  %s", l->merchant);
			fprintf(f, "\n");
		}
		fprintf(f, "  Answers:\n");
		for (u32 o = 0; o + 5 <= a->rawLen; ) {
			const u8 *p = a->raw + o;
			u32 len = p[3] | p[4] << 8;
			scHex(h, p + 5, len);
			switch (p[0]) {
			case 'S': fprintf(f, "    SELECT            %s\n", h); break;
			case 'G': fprintf(f, "    GPO               %s\n", h); break;
			case 'R': fprintf(f, "    RECORD SFI %2d #%-2d %s\n", p[2], p[1], h); break;
			case 'L': fprintf(f, "    LOG SFI %2d #%-2d    %s\n", p[2], p[1], h); break;
			case 'D': fprintf(f, "    GET DATA %02X%02X     %s\n", p[1], p[2], h); break;
			}
			o += 5 + len;
		}
	}
	fclose(f);
	return true;
}
