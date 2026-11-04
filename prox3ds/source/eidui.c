// ID documents (eid.h): what the chip offers, the eID PIN's state, a CAN check (PACE + one command under
// secure messaging).

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "eid.h"
#include "emrtd.h"
#include "entry.h"
#include "iso7816.h"
#include "probe.h"
#include "ui.h"

static EidCard ed;
static int readResult;
static char readWhy[96];
static UiList il;

// the last CAN check: 0 none, 1 right, 2 wrong, 3 failed (canWhy)
static int canState, canResult;
static char canWhy[96];
static s64 canValue = -1;
static char canText[8];
static u16 canSmSw;

static const Screen eidScreen;

static void runRead(void)
{
	readResult = 0;
	*readWhy = 0;
	if (!cardWait()) return;
	readResult = eidRead(&ed);
	snprintf(readWhy, sizeof(readWhy), "%s", eidWhy());
	iso14aParity(true);
}

static void doneRead(void)
{
	if (readResult < 0) {
		msgBox("ID document", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!readResult) {
		if (!mfCancel && *readWhy) msgBox("ID document", "%s", readWhy);
		return;
	}
	il = (UiList){ 0 };
	canState = 0;
	appScreen(&eidScreen);
}

void eidOpenTool(void)
{
	jobStart("Reading the ID document", runRead, doneRead, true);
}

// --- CAN check ---

static void runCan(void)
{
	static u8 buf[64];
	static EidSm sm;
	canResult = 0;
	*canWhy = 0;
	canSmSw = 0;
	if (!cardWait()) return;
	canResult = eidPace(&ed, EID_CAN, (const u8 *)canText, strlen(canText), &sm);
	snprintf(canWhy, sizeof(canWhy), "%s", eidWhy());
	if (canResult == 1) {
		// one command under secure messaging: SELECT the ePass application (P2 0C, no answer data)
		static const u8 epass[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
		int n = eidSmCmd(&sm, 0xA4, 0x04, 0x0C, epass, sizeof(epass), -1, buf, sizeof(buf), &canSmSw);
		if (n < 0) {
			snprintf(canWhy, sizeof(canWhy), "secure messaging: %s", eidWhy());
			canSmSw = 0;
		}
	}
	iso14aParity(true);
}

static void doneCan(void)
{
	if (mfCancel) return;
	if (canResult < 0) {
		msgBox("CAN", "The chip stopped answering.\nTry again.");
		return;
	}
	canState = canResult == 1 ? 1 : canResult == 2 ? 2 : 3;
	if (canState == 1)
		toast(canSmSw ? "CAN right: PACE done, secure messaging works" : "CAN right: PACE done");
	else if (canState == 2)
		msgBox("CAN", "Wrong CAN: the card refused PACE with %s.\n(A wrong CAN costs no PIN try.)", canText);
	else
		msgBox("CAN", "PACE failed: %s", canWhy);
}

static void canDone(s64 v)
{
	canValue = v;
	snprintf(canText, sizeof(canText), "%06lld", v);
	jobStart("PACE with the CAN", runCan, doneCan, true);
}

static void checkCan(void)
{
	if (ed.pace < 0) {
		msgBox("CAN", ed.accessLen ? "This chip's PACE variant isn't one the app does yet (ECDH generic "
			"mapping with AES only)." : "No EF.CardAccess: this chip has no PACE (a BAC-only passport).");
		return;
	}
	entryDec("CAN", "The 6-digit card access number, printed on the card (German ID card: bottom right of "
		"the front).", 0, 999999, canValue < 0 ? 0 : canValue, canDone);
}

// --- reading the document (emrtd.h): MRZ (PACE or BAC) or CAN (PACE) ---

static MrtdDoc md;
static int mdResult;
static char mdWhy[96];
static u8 mdHow;
static char mrzDoc[10], mrzBirth[7], mrzExpiry[7]; // this session only, never saved
static const Screen mrtdScreen;

static void runMrtd(void)
{
	static EidCard e;
	mdResult = 0;
	*mdWhy = 0;
	if (!cardWait()) return;
	// a fresh look at the chip first: the document on the reader may not be the one shown
	int r = eidRead(&e);
	if (r == 1) {
		ed = e;
		if (mdHow == EID_MRZ) {
			u8 key[20];
			eidMrzSecret(mrzDoc, mrzBirth, mrzExpiry, key);
			r = mrtdRead(&ed, EID_MRZ, key, 20, &md);
		} else {
			r = mrtdRead(&ed, EID_CAN, (const u8 *)canText, strlen(canText), &md);
		}
		snprintf(mdWhy, sizeof(mdWhy), "%s", mrtdWhy());
	} else {
		snprintf(mdWhy, sizeof(mdWhy), "%s", eidWhy());
	}
	mdResult = r;
	iso14aParity(true);
}

static void doneMrtd(void)
{
	if (mfCancel) return;
	if (mdResult < 0) {
		msgBox("ID document", "The chip stopped answering.\nTry again.");
		return;
	}
	if (mdHow == EID_CAN && (mdResult == 1 || mdResult == 2)) canState = mdResult;
	if (mdResult == 2) {
		msgBox("ID document", mdHow == EID_MRZ ? "The chip refused the MRZ data: check the document number, birth "
			"date and expiry date.\n(%s)" : "Wrong CAN.\n(%s)", mdWhy);
		return;
	}
	if (mdResult != 1) {
		msgBox("ID document", "%s", mdWhy);
		return;
	}
	if (appTop() != &mrtdScreen) appScreen(&mrtdScreen);
}

static void mrtdStart(void)
{
	jobStart(mdHow == EID_MRZ ? "Reading with the MRZ" : "Reading with the CAN", runMrtd, doneMrtd, true);
}

static bool digits6(const char *s)
{
	if (strlen(s) != 6) return false;
	for (int i = 0; i < 6; i++)
		if (s[i] < '0' || s[i] > '9') return false;
	return true;
}

static void fDoc(char *out) { strcpy(out, *mrzDoc ? mrzDoc : "-"); }

static void docDone(const char *s)
{
	char t[10];
	u32 k = 0;
	for (; *s && k < 9; s++)
		if ((*s >= '0' && *s <= '9') || (*s >= 'A' && *s <= 'Z')) t[k++] = *s;
		else if (*s >= 'a' && *s <= 'z') t[k++] = *s - 32;
	t[k] = 0;
	if (*t) strcpy(mrzDoc, t);
}
static void eDoc(void)
{
	entryText("Document number", "As printed (up to 9 letters / digits; the MRZ's second line starts with it).", mrzDoc,
		9, ENTRY_CAPS, docDone);
}
static int curYear(void)
{
	time_t now = unixNow();
	struct tm *t = gmtime(&now);
	return t ? 1900 + t->tm_year : 2026;
}

// YYMMDD <-> a full date (birth: a year after this one's YY is 19YY; expiry: 20YY)
static bool mrzDate(const char *s, bool birth, int *y, int *m, int *d)
{
	if (strlen(s) != 6) return false;
	int yy = (s[0] - '0') * 10 + s[1] - '0';
	*y = (birth && yy > curYear() % 100 ? 1900 : 2000) + yy;
	*m = (s[2] - '0') * 10 + s[3] - '0', *d = (s[4] - '0') * 10 + s[5] - '0';
	return true;
}

static void fDate(char *out, const char *s, bool birth)
{
	int y, m, d;
	if (mrzDate(s, birth, &y, &m, &d)) sprintf(out, "%02d.%02d.%04d", d, m, y);
	else strcpy(out, "-");
}
static void fBirth(char *out) { fDate(out, mrzBirth, true); }
static void fExpiry(char *out) { fDate(out, mrzExpiry, false); }

static void birthDone(int y, int m, int d) { snprintf(mrzBirth, sizeof(mrzBirth), "%02u%02u%02u", (unsigned)y % 100, (unsigned)m % 100, (unsigned)d % 100); }
static void expiryDone(int y, int m, int d) { snprintf(mrzExpiry, sizeof(mrzExpiry), "%02u%02u%02u", (unsigned)y % 100, (unsigned)m % 100, (unsigned)d % 100); }

static void eBirth(void)
{
	int y = 1990, m = 1, d = 1;
	mrzDate(mrzBirth, true, &y, &m, &d);
	entryDate("Date of birth", "As printed on the document (the MRZ has it as YYMMDD).", y, m, d, curYear() - 120,
		curYear(), birthDone);
}

static void eExpiry(void)
{
	int y = curYear(), m = 1, d = 1;
	mrzDate(mrzExpiry, false, &y, &m, &d);
	entryDate("Expiry date", "As printed on the document. An expired one works too: the chip doesn't check.", y, m,
		d, 2000, 2099, expiryDone);
}

static const Field mrzFields[] = {
	{ "Document number", fDoc, eDoc }, { "Date of birth", fBirth, eBirth }, { "Expiry date", fExpiry, eExpiry },
};
static int mrzCount(void) { return 3; }

static void mrzRun(void)
{
	if (!*mrzDoc || !digits6(mrzBirth) || !digits6(mrzExpiry)) {
		msgBox("Read with the MRZ", "It needs all three: document number, date of birth, expiry date.");
		return;
	}
	mdHow = EID_MRZ;
	mrtdStart();
}

static void readMrz(void)
{
	formOpen("Read with the MRZ", "Read", "The chip's key comes from these three (the check digits are worked out "
		"here). PACE when the chip has it, else BAC. Nothing is written; the data stays in the app until you save it.",
		mrzFields, mrzCount, mrzRun);
}

static void canReadDone(s64 v)
{
	canValue = v;
	snprintf(canText, sizeof(canText), "%06lld", v);
	mdHow = EID_CAN;
	mrtdStart();
}

static void readCan(void)
{
	if (ed.pace < 0) {
		msgBox("CAN", "This chip has no PACE (or not one the app does): it takes the MRZ.");
		return;
	}
	entryDec("CAN", "The 6-digit card access number printed on the document.", 0, 999999, canValue < 0 ? 0 : canValue,
		canReadDone);
}

static void eidMenu(void)
{
	static const MenuItem items[] = {
		{ "Read with the MRZ", readMrz }, { "Read with the CAN", readCan }, { "Check the CAN only", checkCan },
	};
	popup("ID document", items, ed.pace >= 0 ? 3 : 1);
}

// --- the document screen ---

static void dateText(char *out, const char *yymmdd, bool birth)
{
	if (strlen(yymmdd) != 6) {
		strcpy(out, "?");
		return;
	}
	int yy = (yymmdd[0] - '0') * 10 + yymmdd[1] - '0';
	time_t now = unixNow();
	struct tm *t = gmtime(&now);
	int cur = t ? t->tm_year % 100 : 26;
	int century = birth ? (yy > cur ? 1900 : 2000) : 2000;
	sprintf(out, "%04d-%.2s-%.2s", century + yy, yymmdd + 2, yymmdd + 4);
}

static bool expired(const char *yymmdd)
{
	char d[16], n[16];
	dateText(d, yymmdd, false);
	time_t now = unixNow();
	struct tm *t = gmtime(&now);
	if (!t) return false;
	strftime(n, sizeof(n), "%Y-%m-%d", t);
	return strcmp(d, n) < 0;
}

static void dgList(char *out, u32 max, u32 bits)
{
	int o = 0;
	*out = 0;
	for (int g = 1; g <= 16; g++)
		if (bits & 1u << g) o += snprintf(out + o, max - o, "%sDG%d", o ? " " : "", g);
}

static void mrtdDraw(void)
{
	char s[200], t[64];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	const char *kind = md.docType[0] == 'P' ? "Passport" : md.docType[0] == 'I' || md.docType[0] == 'A' ||
		md.docType[0] == 'C' ? "ID card" : "Travel document";
	uiHeader(kind, md.access);
	float y = 26;
	if (md.mrzLines) {
		snprintf(s, sizeof(s), "%s%s%s", md.surname, *md.given ? ", " : "", md.given);
		uiText(12, y, S_TITLE, uiCol[COL_ACCENT], "%s", uiFit(s, 300, S_TITLE));
		uiTextRight(UI_W - 12, y + 2, S_SMALL, dim, "%s %s", md.docType, md.issuer);
		y += 18;
		uiText(12, y, S_BODY, txt, "No. %s   Nationality %s   Sex %c", md.number, md.nationality, md.sex ? md.sex : '?');
		y += LINE_H;
		dateText(s, md.birth, true);
		dateText(t, md.expiry, false);
		bool ex = expired(md.expiry);
		uiText(12, y, S_BODY, txt, "Born %s", s);
		uiText(150, y, S_BODY, uiCol[ex ? COL_WARN : COL_TEXT], "Expires %s%s", t, ex ? " (expired)" : "");
		y += LINE_H + 2;
		for (int i = 0; i < md.mrzLines; i++) {
			int w = strlen(md.mrz) / md.mrzLines;
			snprintf(s, sizeof(s), "%.*s", w, md.mrz + i * w);
			uiMono(12, y, dim, s);
			y += SMALL_H;
		}
		y += 3;
	} else {
		uiText(12, y, S_TITLE, uiCol[COL_WARN], "%s", md.f[1].sw == 0x6982 ? "DG1 refused: needs terminal authentication" :
			"No DG1");
		y += 22;
	}

	// passive authentication
	float top = y;
	uiRect(8, y, UI_W - 16, 4 * SMALL_H + 8, uiCol[COL_PANEL]);
	y += 3;
	if (!md.hashLen) {
		uiText(14, y, S_SMALL, md.f[MRTD_SOD].data ? uiCol[COL_WARN] : dim, "%s", md.f[MRTD_SOD].data ? md.paWhy :
			md.f[MRTD_SOD].sw == 0x6982 ? "EF.SOD refused: no passive authentication" : "No EF.SOD");
	} else {
		dgList(s, sizeof(s), md.ok);
		if (md.bad) {
			dgList(t, sizeof(t), md.bad);
			uiText(14, y, S_SMALL, uiCol[COL_ERR], "Hash MISMATCH: %s (data altered or misread)", t);
		} else {
			uiText(14, y, S_SMALL, uiCol[COL_OK], "%s: match EF.SOD (SHA-%d)", *s ? s : "none read", md.hashLen == 20 ? 1 :
				md.hashLen * 8);
		}
		y += SMALL_H;
		static const char *const st[] = { "not checked", "valid", "INVALID", "not checked" };
		u32 col = md.sig == PA_OK && md.attrs == PA_OK ? COL_OK : md.sig == PA_BAD || md.attrs == PA_BAD ? COL_ERR : COL_WARN;
		snprintf(s, sizeof(s), "Signature (%s): %s%s%s", md.sigAlg, md.attrs == PA_BAD ? "digest wrong, " : "", st[md.sig],
			*md.paWhy ? ": " : "");
		if (*md.paWhy) snprintf(s + strlen(s), sizeof(s) - strlen(s), "%s", md.paWhy);
		uiText(14, y, S_SMALL, uiCol[col], "%s", uiFit(s, UI_W - 28, S_SMALL));
		y += SMALL_H;
		snprintf(s, sizeof(s), "Signer: %s", md.dsSubject);
		uiText(14, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
		y += SMALL_H;
		snprintf(s, sizeof(s), "%s to %s, CSCA %s: unchecked", md.dsFrom, md.dsTo, md.dsIssuer);
		uiText(14, y, S_SMALL, dim, "%s", uiFit(s, UI_W - 28, S_SMALL));
	}
	y = top + 4 * SMALL_H + 11;

	// the files
	u32 got = 0, refused = 0;
	for (int g = 1; g <= 16; g++) {
		if (md.f[g].data) got |= 1u << g;
		else if (md.f[g].sw == 0x6982) refused |= 1u << g;
	}
	dgList(s, sizeof(s), got);
	uiText(12, y, S_SMALL, txt, "Read: %s%s%s", md.f[MRTD_COM].data ? "COM " : "", md.f[MRTD_SOD].data ? "SOD " : "",
		*s || md.f[MRTD_COM].data || md.f[MRTD_SOD].data ? s : "nothing");
	y += SMALL_H;
	if (refused) {
		dgList(s, sizeof(s), refused);
		uiText(12, y, S_SMALL, dim, "Refused: %s (needs terminal authentication)", s);
		y += SMALL_H;
	}
	if (md.photoLen) uiText(12, y, S_SMALL, dim, "Photo: %s, %lu bytes (" BTN_Y " saves it)", md.photoJp2 ? "JPEG 2000" :
		"JPEG", md.photoLen);

	uiFooter(BTN_Y " save   " BTN_X " read again   " BTN_B " back");
}

static void mrtdSaveIt(void)
{
	char path[128];
	if (mrtdSave(&md, path, sizeof(path))) toast("Saved %s/", path + strlen(APP_DIR "/"));
	else msgBox("Save", "Could not write to the SD card.");
}

static void mrtdInput(u32 kDown, u32 kRepeat)
{
	(void)kRepeat;
	if (kDown & KEY_Y) mrtdSaveIt();
	if (kDown & KEY_X) mrtdStart();
	if (kDown & KEY_B) appBack();
}

static const Screen mrtdScreen = { NULL, mrtdInput, mrtdDraw };

// --- the screen ---

#define INFO_ROWS 7

static void eidDraw(void)
{
	char s[160];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	bool de = eidIsGermanId(&ed);
	uiHeader("ID document", de ? "TR-03110" : "ICAO 9303");

	float y = 26;
	uiText(12, y, S_TITLE, uiCol[COL_ACCENT], "%s", de ? "German ID card" : ed.accessLen ? "eMRTD with PACE" :
		"eMRTD");
	int o = 0;
	*s = 0;
	for (int i = 0; i < ed.napps; i++) {
		const char *n = eidAppName(ed.app[i].aid, ed.app[i].aidLen);
		char h[33];
		if (!n && *ed.app[i].label) n = ed.app[i].label;
		if (!n) scHex(h, ed.app[i].aid, ed.app[i].aidLen), n = h;
		o += snprintf(s + o, sizeof(s) - o, "%s%s", o ? "  " : "", n);
	}
	if (o) uiTextRight(UI_W - 12, y + 2, S_SMALL, dim, "%s", uiFit(s, 200, S_SMALL));
	y += 18;
	*s = 0;
	if (ed.extIn || ed.extOut) snprintf(s, sizeof(s), "Extended length: %lu bytes in, %lu out", ed.extIn, ed.extOut);
	else snprintf(s, sizeof(s), "No extended length info");
	uiText(12, y, S_SMALL, dim, "%s", s);
	y += SMALL_H + 4;

	u32 col;
	const char *pin = eidPinText(ed.pinSw, &col);
	if (pin) uiText(12, y, S_BODY, uiCol[col], "%s", pin);
	else if (ed.pinSw) uiText(12, y, S_BODY, dim, "No eID PIN (MSE:Set AT: %04X)", ed.pinSw);
	else uiText(12, y, S_BODY, dim, "%s", ed.accessLen ? "No PACE variant the app does" : "No PACE (BAC only)");
	y += LINE_H;
	if (canState == 1)
		uiText(12, y, S_BODY, uiCol[COL_OK], "CAN %s right: PACE done%s", canText,
			canSmSw == 0x9000 ? ", secure messaging works" : canSmSw ? "" : " (secure messaging failed)");
	else if (canState == 2)
		uiText(12, y, S_BODY, uiCol[COL_ERR], "CAN %s wrong", canText);
	else if (canState == 3)
		snprintf(s, sizeof(s), "PACE failed: %s", canWhy), uiText(12, y, S_BODY, uiCol[COL_WARN], "%s", uiFit(s, UI_W - 24, S_BODY));
	else
		uiText(12, y, S_BODY, dim, "%s", ed.pace >= 0 ? "CAN not checked yet" : "");
	y += LINE_H + 4;

	// EF.CardAccess
	float h = INFO_ROWS * SMALL_H + 6;
	uiRect(8, y, UI_W - 16, h + SMALL_H, uiCol[COL_PANEL]);
	if (!ed.accessLen) {
		uiText(14, y + 3, S_SMALL, dim, "No EF.CardAccess");
	} else {
		uiText(14, y + 3, S_SMALL, dim, "EF.CardAccess: %d entr%s (%u bytes)", ed.ninfo, ed.ninfo == 1 ? "y" : "ies",
			ed.accessLen);
		if (ed.ninfo > INFO_ROWS) uiTextRight(UI_W - 14, y + 3, S_SMALL, dim, "%d-%d of %d  " BTN_UD, il.top + 1,
			il.top + INFO_ROWS < ed.ninfo ? il.top + INFO_ROWS : ed.ninfo, ed.ninfo);
		for (int i = 0; i < INFO_ROWS && il.top + i < ed.ninfo; i++) {
			const EidInfo *x = &ed.info[il.top + i];
			eidInfoText(x, s, sizeof(s));
			uiText(14, y + 3 + (i + 1) * SMALL_H, S_SMALL, il.top + i == ed.pace ? uiCol[COL_ACCENT] : txt, "%s",
				uiFit(s, UI_W - 28, S_SMALL));
		}
	}
	y += h + SMALL_H + 2;
	if (de) uiText(12, y, S_SMALL, dim, "%s", "Name, photo, MRZ: only for terminals with a government certificate");

	uiFooter(BTN_A " read / check   " BTN_X " read again   " BTN_B " back");
}

static void eidInput(u32 kDown, u32 kRepeat)
{
	int max = ed.ninfo > INFO_ROWS ? ed.ninfo - INFO_ROWS : 0;
	if (kRepeat & KEY_UP) il.top--;
	if (kRepeat & KEY_DOWN) il.top++;
	il.top = il.top < 0 ? 0 : il.top > max ? max : il.top;
	if (kDown & KEY_A) eidMenu();
	if (kDown & KEY_X) {
		appBack();
		eidOpenTool();
	}
	if (kDown & KEY_B) appBack();
}

static const Screen eidScreen = { NULL, eidInput, eidDraw };
