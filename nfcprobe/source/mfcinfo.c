// Classic dump extras: MAD, Saflok, originality signature; see mfcinfo.h. Ported from pm3
// client/src/mifare/mad.c and client/src/cmdhfsaflok.c.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "mfcinfo.h"
#include "nxpsig.h"

// --- MAD ---

static u8 crc8Mad(const u8 *p, int n) // poly 1D, init C7, not reflected
{
	u8 c = 0xC7;
	while (n--) {
		c ^= *p++;
		for (int i = 0; i < 8; i++) c = c & 0x80 ? c << 1 ^ 0x1D : c << 1;
	}
	return c;
}

const char *madAdminName(u16 aid)
{
	static const char *admin[] = { "free", "defect", "reserved", "additional directory info", "card holder info",
		"not applicable" };
	return aid < 6 ? admin[aid] : NULL;
}

// The 32 or 48 directory bytes: CRC, info, AIDs (little endian).
static bool madArea(const MfDump *d, int b0, int nb, u8 *out)
{
	for (int i = 0; i < nb; i++) {
		if (!d->valid[b0 + i]) return false;
		memcpy(out + 16 * i, d->data[b0 + i], 16);
	}
	return true;
}

bool mfcMad(const MfDump *d, Mad *m)
{
	memset(m, 0, sizeof(*m));
	u8 a[48];
	if (!d->valid[3] || !madArea(d, 1, 2, a)) return false;
	m->gpb = d->data[3][9];
	m->version = m->gpb & 3;
	m->multi = m->gpb & 0x40;
	if (!(m->gpb & 0x80) || (m->version != 1 && m->version != 2)) return false; // DA: a directory is there
	m->crcOk = crc8Mad(a + 1, 31) == a[0];
	m->info = a[1] & 0x3F;
	for (int i = 0; i < 15 && i < d->sectors - 1; i++) m->aid[m->n++] = a[2 + 2 * i] | a[3 + 2 * i] << 8;
	if (m->version == 2 && d->sectors > 16 && madArea(d, 64, 3, a)) {
		m->crc2Ok = crc8Mad(a + 1, 47) == a[0];
		m->info2 = a[1] & 0x3F;
		for (int i = 0; i < 23 && 17 + i < d->sectors; i++) m->aid[m->n++] = a[2 + 2 * i] | a[3 + 2 * i] << 8;
	}
	return true;
}

static int madSector(int i)
{
	return i < 15 ? i + 1 : i + 2; // MAD2 starts at sector 17
}

// --- Saflok ---

static const u8 safDec[256] = {
	234, 13, 217, 116, 78, 40, 253, 186, 123, 152, 135, 120, 221, 141, 181, 26, 14, 48, 243, 47, 106, 59, 172, 9,
	185, 32, 110, 91, 43, 182, 33, 170, 23, 68, 90, 84, 87, 190, 10, 82, 103, 201, 80, 53, 245, 65, 160, 148, 96,
	254, 36, 162, 54, 239, 30, 107, 247, 156, 105, 218, 155, 111, 173, 216, 251, 151, 98, 95, 31, 56, 194, 215,
	113, 49, 240, 19, 238, 15, 163, 167, 28, 213, 17, 76, 69, 44, 4, 219, 166, 46, 248, 100, 154, 184, 83, 102,
	220, 122, 93, 3, 7, 128, 55, 255, 252, 6, 188, 38, 192, 149, 74, 241, 81, 45, 34, 24, 1, 121, 94, 118, 29,
	127, 20, 227, 158, 138, 187, 52, 191, 244, 171, 72, 99, 85, 62, 86, 140, 209, 18, 237, 195, 73, 142, 146, 157,
	202, 177, 229, 206, 77, 63, 250, 115, 5, 224, 75, 147, 178, 203, 8, 225, 150, 25, 61, 131, 57, 117, 236, 214,
	60, 208, 112, 129, 22, 41, 21, 108, 199, 231, 226, 246, 183, 232, 37, 109, 58, 230, 200, 153, 70, 176, 133, 2,
	97, 27, 139, 179, 159, 11, 42, 168, 119, 16, 193, 136, 204, 164, 222, 67, 88, 35, 180, 161, 165, 92, 174, 169,
	126, 66, 64, 144, 210, 233, 132, 207, 228, 235, 71, 79, 130, 212, 197, 143, 205, 211, 134, 0, 89, 223, 242,
	12, 124, 198, 189, 249, 125, 196, 145, 39, 137, 50, 114, 51, 101, 104, 175,
};

void safDecrypt(const u8 enc[17], u8 out[17])
{
	for (int i = 0; i < 17; i++) out[i] = safDec[enc[i]] - (i + 1);
	int b = out[10], b2 = b & 1;
	for (int n2 = 17; n2 > 0; n2--) {
		b = out[n2 - 1];
		for (int n3 = 8; n3 > 0; n3--) {
			int n4 = n2 + n3;
			if (n4 > 17) n4 -= 17;
			int b3 = out[n4 - 1], b4 = (b3 & 0x80) >> 7;
			b3 = ((b3 << 1) & 0xFF) | b2;
			b2 = (b & 0x80) >> 7;
			b = ((b << 1) & 0xFF) | b4;
			out[n4 - 1] = b3;
		}
		out[n2 - 1] = b;
	}
}

static u32 bits(const u8 *raw, int start, int n) // MSB first
{
	u32 v = 0;
	for (int i = start; i < start + n; i++) v = v << 1 | (raw[i / 8] >> (7 - i % 8) & 1);
	return v;
}

static int monthDays(int y, int m) // m 1..12
{
	static const u8 days[13] = { 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	return m == 2 && y % 4 == 0 && (y % 100 || y % 400 == 0) ? 29 : days[m];
}

// The expiry = creation + the interval, carried minutes -> hours -> days -> months -> years. pm3
// carries days over before months (so an interval whose months run past December lands a month late
// there); here months go first, then days through the month lengths.
static SafTime addInterval(SafTime t, const u8 iv[5])
{
	int y = t.year + iv[0], mo = t.month - 1 + iv[1], d = t.day + iv[2], h = t.hour + iv[3], mi = t.minute + iv[4];
	h += mi / 60, mi %= 60;
	d += h / 24, h %= 24;
	y += mo / 12, mo %= 12;
	while (d > monthDays(y, mo + 1)) {
		d -= monthDays(y, mo + 1);
		if (++mo == 12) mo = 0, y++;
	}
	return (SafTime){ y, mo + 1, d, h, mi };
}

void safDecode(const u8 raw[17], Saflok *s)
{
	memset(s, 0, sizeof(*s));
	memcpy(s->raw, raw, 17);
	s->level = bits(raw, 0, 4);
	s->type = bits(raw, 4, 4);
	s->cardId = bits(raw, 8, 8);
	s->openingKey = bits(raw, 16, 2);
	s->lockId = bits(raw, 18, 14);
	s->pass = bits(raw, 32, 12);
	s->seqComb = bits(raw, 44, 12);
	s->deadbolt = bits(raw, 56, 1);
	s->restricted = bits(raw, 57, 7);
	s->property = bits(raw, 116, 12);
	s->iv[0] = raw[8] >> 4;
	s->iv[1] = raw[8] & 0xF;
	s->iv[2] = raw[9] >> 3 & 0x1F;
	s->iv[3] = (raw[9] & 7) << 2 | raw[10] >> 6;
	s->iv[4] = raw[10] & 0x3F;
	s->created = (SafTime){ 1980 + ((raw[14] & 0x70) | raw[11] >> 4), raw[11] & 0xF, raw[12] >> 3 & 0x1F,
		(raw[12] & 7) << 2 | raw[13] >> 6, raw[13] & 0x3F };
	s->expires = s->created.month >= 1 && s->created.month <= 12 ? addInterval(s->created, s->iv) : s->created;
	u8 sum = 0;
	for (int i = 0; i < 16; i++) sum += raw[i];
	s->sumOk = (u8)(255 - sum) == raw[16];
}

bool mfcSaflok(const MfDump *d, Saflok *s)
{
	static const u8 sec1Key[6] = { 0x2A, 0x2C, 0x13, 0xCC, 0x24, 0x2A };
	bool saflok = (d->keyFound[1][0] && !memcmp(d->keys[1][0], sec1Key, 6)) || (d->kdf && strstr(d->kdf, "Saflok"));
	if (!saflok || !d->valid[1] || !d->valid[2]) return false;
	u8 enc[17], raw[17];
	memcpy(enc, d->data[1], 16);
	enc[16] = d->data[2][0];
	safDecrypt(enc, raw);
	safDecode(raw, s);
	return s->sumOk;
}

const char *safLevelName(int level)
{
	static const char *names[16] = { "Guest Key", "Connectors", "Suite", "Limited Use", "Failsafe", "Inhibit",
		"Pool/Meeting Master", "Housekeeping", "Floor Key", "Section Key", "Rooms Master", "Grand Master",
		"Emergency", "Electronic Lockout", "Secondary Programming Key (SPK)", "Primary Programming Key (PPK)" };
	return names[level & 15];
}

// --- signature ---

const char *mfcSigCheck(const MfDump *d)
{
	if (!d->sigUidLen || !d->valid[0]) return NULL;
	return nxpSigCheck(SIG_MFC, d->data[0], d->sigUidLen, d->sig, 32);
}

// --- summary + screen ---

static const char *fudanType(const u8 *b0);

void mfcInfoSummary(const MfDump *d, char *out, u32 max)
{
	Saflok s;
	Mad m;
	int n = 0;
	out[0] = 0;
	if (mfcSaflok(d, &s))
		n += snprintf(out + n, max - n, "Saflok %s, lock %u, until %04u-%02u-%02u %02u:%02u.\n", safLevelName(s.level),
			s.lockId, s.expires.year, s.expires.month, s.expires.day, s.expires.hour, s.expires.minute);
	if (n < (int)max && mfcMad(d, &m))
		n += snprintf(out + n, max - n, "MAD v%d%s.\n", m.version, m.crcOk ? "" : " (bad CRC)");
	if (n < (int)max && d->valid[0] && fudanType(d->data[0]))
		n += snprintf(out + n, max - n, "%s %02X%02X.\n", fudanType(d->data[0]), d->data[0][8], d->data[0][15]);
	if (n < (int)max && d->sigUidLen) {
		const char *k = mfcSigCheck(d);
		snprintf(out + n, max - n, "Signature: %s.\n", k ? k : "does NOT verify");
	}
}

#include "app.h"

#define INFO_LINES 96
#define INFO_VIS   14
static char lines[INFO_LINES][96];
static u8 lineCol[INFO_LINES];
static int nlines, infoTop;

static void addLine(int col, const char *fmt, ...)
{
	if (nlines >= INFO_LINES) return;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(lines[nlines], sizeof(lines[0]), fmt, ap);
	va_end(ap);
	lineCol[nlines++] = col;
}

// Fudan's chip ID in block 0 (pm3 fm11rf08s_full.py decodeBlock0): bytes 8 and 15, a check in 9-14.
static const char *fudanType(const u8 *b0)
{
	if (b0[15] == 0x90 && (b0[8] == 0x01 || b0[8] == 0x03 || b0[8] == 0x04)) return "Fudan FM11RF08S";
	if (b0[15] == 0x1D && b0[8] >= 0x01 && b0[8] <= 0x03) return "Fudan FM11RF08";
	if (b0[15] == 0x91 || b0[15] == 0x98) return "Fudan FM11RF08 (never seen in the wild)";
	return NULL;
}

static void buildLines(const MfDump *d)
{
	nlines = 0;
	const char *fudan = d->valid[0] ? fudanType(d->data[0]) : NULL;
	if (fudan) {
		const u8 *b = d->data[0];
		addLine(COL_ACCENT, "Chip");
		addLine(COL_TEXT, "  %s %02X%02X (block 0)", fudan, b[8], b[15]);
		addLine(COL_DIM, "  Fudan check %02X%02X%02X%02X%02X%02X: only Fudan's online service verifies it", b[9], b[10],
			b[11], b[12], b[13], b[14]);
	}
	// signature
	addLine(COL_ACCENT, "Originality signature");
	if (!d->sigUidLen) {
		addLine(COL_DIM, fudan ? "  none: Fudan chips have no ECDSA signature" : "  none read (no MFC EV1 signature sector)");
	} else {
		const char *k = mfcSigCheck(d);
		addLine(k ? COL_OK : COL_ERR, "  %s", k ? k : "does NOT verify with a known key");
		char h[65];
		for (int i = 0; i < 32; i++) sprintf(h + 2 * i, "%02X", d->sig[i]);
		addLine(COL_DIM, "  %.32s", h);
		addLine(COL_DIM, "  %s", h + 32);
	}
	// Saflok
	Saflok s;
	if (mfcSaflok(d, &s)) {
		addLine(COL_ACCENT, "Saflok (pm3 hf saflok)");
		addLine(COL_TEXT, "  Level %u: %s   type %u   card ID %u", s.level, safLevelName(s.level), s.type, s.cardId);
		addLine(COL_TEXT, "  Lock ID %u   property %u   opening key %u", s.lockId, s.property, s.openingKey);
		addLine(COL_TEXT, "  Pass %u   sequence/combination %u   deadbolt override %s", s.pass, s.seqComb,
			s.deadbolt ? "yes" : "no");
		char days[16] = "";
		for (int i = 0; i < 7; i++) days[i] = s.restricted >> (6 - i) & 1 ? '1' : '0';
		addLine(COL_TEXT, "  Restricted days %s", days);
		addLine(COL_TEXT, "  Made     %04u-%02u-%02u %02u:%02u", s.created.year, s.created.month, s.created.day,
			s.created.hour, s.created.minute);
		addLine(COL_TEXT, "  Expires  %04u-%02u-%02u %02u:%02u  (+%uy %um %ud %uh %umin)", s.expires.year, s.expires.month,
			s.expires.day, s.expires.hour, s.expires.minute, s.iv[0], s.iv[1], s.iv[2], s.iv[3], s.iv[4]);
		char h[40];
		for (int i = 0; i < 17; i++) sprintf(h + 2 * i, "%02X", s.raw[i]);
		addLine(COL_DIM, "  Decrypted %s", h);
	}
	// MAD
	Mad m;
	if (!mfcMad(d, &m)) {
		addLine(COL_ACCENT, "MIFARE Application Directory");
		addLine(COL_DIM, d->valid[3] ? "  none (GPB %02X: DA bit clear)" : "  sector 0 not read", d->data[3][9]);
		return;
	}
	addLine(COL_ACCENT, "MIFARE Application Directory v%d (GPB %02X)", m.version, m.gpb);
	addLine(m.crcOk ? COL_TEXT : COL_ERR, "  CRC %s, %s application card%s", m.crcOk ? "ok" : "BAD",
		m.multi ? "multi" : "single", m.version == 2 && d->sectors > 16 ? (m.crc2Ok ? ", MAD2 CRC ok" : ", MAD2 CRC BAD") : "");
	if (m.info) addLine(COL_TEXT, "  Card publisher: sector %d", m.info);
	u16 prev = 0xFFFF;
	for (int i = 0; i < m.n; i++) {
		u16 a = m.aid[i];
		const char *company = NULL, *name = madAdminName(a);
		if (name) {
			addLine(COL_DIM, "  %02d  %04X  %s", madSector(i), a, name);
		} else if (a == prev) {
			addLine(COL_DIM, "  %02d  %04X  (continued)", madSector(i), a);
		} else {
			name = madAidName(a, &company);
			if (name) addLine(COL_TEXT, "  %02d  %04X  %s (%s)", madSector(i), a, name, company);
			else addLine(COL_TEXT, "  %02d  %04X  unknown", madSector(i), a);
		}
		if (!madAdminName(a)) prev = a;
	}
}

static void infoInput(u32 kDown, u32 kRepeat)
{
	if (kDown & KEY_B) {
		appBack();
		return;
	}
	if (kRepeat & KEY_DOWN && infoTop + INFO_VIS < nlines) infoTop++;
	if (kRepeat & KEY_UP && infoTop > 0) infoTop--;
}

static void infoDraw(void)
{
	uiHeader("Card info", nlines > INFO_VIS ? BTN_UD " scroll" : "");
	float y = 30;
	for (int i = infoTop; i < nlines && i < infoTop + INFO_VIS; i++, y += SMALL_H)
		uiText(10, y, S_SMALL, uiCol[lineCol[i]], "%s", lines[i]);
	uiFooter(BTN_B " back");
}

void mfcInfoOpen(const MfDump *d)
{
	static const Screen infoScreen = { NULL, infoInput, infoDraw };
	buildLines(d);
	infoTop = 0;
	appScreen(&infoScreen);
}
