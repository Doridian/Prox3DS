// MIFARE DESFire family (any ISO14443-4 card gets in, for its ATS): the keyless card screen and an
// application screen with its files. Saves the info as text to the SD card.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "desfire.h"
#include "probe.h"
#include "ui.h"

static Card sc;
static DfInfo di;
static int diResult; // dfReadInfo
static char diWhy[64];
static UiList al;

static const Screen cardScreen, appScreen_;

static int dfProbe(void)
{
	al = (UiList){ 0 };
	diResult = dfReadInfo(&di);
	sc = card; // after our reselect: the ROM's ISO-DEP activation reports ATQA 0000
	snprintf(diWhy, sizeof(diWhy), "%s", dfWhy());
	if (diResult <= 0) logp("DESFire: %s\n", diWhy);
	iso14aParity(true);
	// not a DESFire, but an ATS is worth a screen
	return diResult < 0 ? -1 : diResult || di.atsLen;
}

static int scanResult;

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = dfProbe();
}

static void dfShow(void)
{
	appScreen(&cardScreen);
}

static void doneScan(void)
{
	if (scanResult > 0) dfShow();
	else if (scanResult < 0) msgBox("Scan", "The chip stopped answering.\nTry again.");
	else if (!mfCancel) msgBox("Scan", "No ISO14443-4 answer:\n%s", diWhy);
}

static void startScan(void)
{
	jobStart("Scanning", runScan, doneScan, true);
}

static void save(void)
{
	char path[128];
	if (dfSaveInfo(&di, path, sizeof(path))) toast("Saved %s", path + strlen(MF_DIR "/"));
	else msgBox("Save", "Could not write to the SD card.");
}

static void hexStr(char *out, const u8 *p, int n)
{
	for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02X", p[i]);
	if (n <= 0) *out = 0;
}

// --- card screen ---

#define APP_ROWS 3

static void cardDraw(void)
{
	char hdr[48], s[120];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	snprintf(hdr, sizeof(hdr), "ATQA %02X%02X  SAK %02X", sc.atqa[1], sc.atqa[0], sc.sak);
	uiHeader(diResult > 0 ? "DESFire: card" : "ISO14443-4: card", hdr);
	float y = 28;
	uidHex(&sc, s, " ");
	uiText(12, y, S_SMALL, dim, "UID (%d bytes)", sc.uidLen);
	uiText(12, y + 12, 0.8f, uiCol[COL_ACCENT], "%s", s);
	y += 40;
	const u8 *v = di.ver;
	if (diResult > 0) {
		uiText(12, y, S_BODY, txt, "%s", dfVersionName(&di));
		if (di.hasFree) snprintf(s, sizeof(s), "%lu%s bytes, %lu free", dfStorage(v[5]), v[5] & 1 ? "+" : "", di.freeMem);
		else snprintf(s, sizeof(s), "%lu%s bytes", dfStorage(v[5]), v[5] & 1 ? "+" : "");
		uiTextRight(UI_W - 12, y + 2, S_SMALL, dim, "%s", s);
	} else {
		uiText(12, y, S_BODY, txt, "%s", cardTypeName(&sc));
	}
	y += LINE_H + 4;
	uiRect(8, y, UI_W - 16, 5 * SMALL_H + 6, uiCol[COL_PANEL]);
	y += 3;
	float atsW = UI_W - 28;
	if (diResult > 0 && di.verLen >= 28) {
		char batch[48];
		snprintf(batch, sizeof(batch), "batch %02X%02X%02X%02X%02X, week %X / 20%02X", v[21], v[22], v[23], v[24],
			v[25], v[26], v[27]);
		uiTextRight(UI_W - 14, y, S_SMALL, txt, "%s", batch);
		atsW -= uiTextWidth(S_SMALL, batch) + 12;
	}
	strcpy(s, "ATS ");
	hexStr(s + 4, di.ats, di.atsLen);
	uiText(14, y, S_SMALL, txt, "%s", uiFit(s, atsW, S_SMALL));
	y += SMALL_H;
	if (diResult <= 0) {
		uiText(14, y, S_SMALL, uiCol[COL_WARN], "%s", diWhy);
		uiFooter(BTN_A " scan again   " BTN_B " back");
		return;
	}
	char sw[16];
	hexStr(s, v, 7);
	hexStr(sw, v + 7, 7);
	uiText(14, y, S_SMALL, txt, "Hardware %s   software %s (%X.%X)", s, sw, v[10], v[11]);
	y += SMALL_H;
	if (di.hasSig) {
		uiText(14, y, S_SMALL, txt, "Signature");
		for (int h = 0; h < 2; h++, y += SMALL_H) {
			hexStr(s, di.sig + 28 * h, 28);
			uiMonoS(72, y + 1, 0.34f, 5.6f, txt, s);
		}
	} else {
		uiText(14, y, S_SMALL, dim, "No originality signature");
		y += 2 * SMALL_H;
	}
	if (di.keySt)
		uiText(14, y, S_SMALL, dim, "PICC key settings: %s", dfStatusName(di.keySt));
	else
		uiText(14, y, S_SMALL, txt, "PICC master key: %s, version %02X   AID list %s   create/delete %s", dfKeyType(di.maxKeys),
			di.keyVer, di.keySet & 2 ? "free" : "keyed", di.keySet & 4 ? "free" : "keyed");
	y += SMALL_H + 6;

	int n = di.napps < DF_MAX_APPS ? di.napps : DF_MAX_APPS;
	if (di.appSt) {
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "Application list: %s", dfStatusName(di.appSt));
	} else if (!n) {
		uiText(12, y, S_SMALL, dim, "No applications");
	} else {
		uiText(12, y, S_SMALL, dim, "%d application%s", di.napps, di.napps == 1 ? "" : "s");
		if (n > APP_ROWS) uiTextRight(UI_W - 12, y, S_SMALL, dim, "%d-%d of %d", al.top + 1,
			al.top + APP_ROWS < n ? al.top + APP_ROWS : n, n);
		y += SMALL_H + 1;
		for (int i = 0; i < APP_ROWS && al.top + i < n; i++, y += LINE_H) {
			const DfApp *a = &di.apps[al.top + i];
			if (al.top + i == al.sel) uiRect(8, y - 1, UI_W - 16, LINE_H, uiCol[COL_SEL]);
			uiText(14, y, S_BODY, uiCol[COL_ACCENT], "%06lX", a->aid);
			float x = 80;
			if (a->hasIso) uiText(x, y + 1, S_SMALL, txt, "ISO %04X", a->isoFid);
			x += 60;
			if (a->selSt) {
				uiText(x, y + 1, S_SMALL, uiCol[COL_WARN], "select: %s", dfStatusName(a->selSt));
				continue;
			}
			if (!a->keySt) uiText(x, y + 1, S_SMALL, txt, "%d %s key%s", a->maxKeys & 0xF, dfKeyType(a->maxKeys),
				(a->maxKeys & 0xF) == 1 ? "" : "s");
			if (a->fileSt) uiTextRight(UI_W - 14, y + 1, S_SMALL, dim, "files: %s", dfStatusName(a->fileSt));
			else uiTextRight(UI_W - 14, y + 1, S_SMALL, txt, "%d file%s", a->nfiles, a->nfiles == 1 ? "" : "s");
		}
	}
	uiFooter(n ? BTN_A " application   " BTN_X " scan again   " BTN_Y " save   " BTN_B " back"
	           : BTN_X " scan again   " BTN_Y " save   " BTN_B " back");
}

static UiList fl;

static void cardInput(u32 kDown, u32 kRepeat)
{
	int n = diResult > 0 && !di.appSt ? (di.napps < DF_MAX_APPS ? di.napps : DF_MAX_APPS) : 0;
	uiListNav(&al, n, APP_ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	if (diResult <= 0) {
		if (kDown & KEY_A) startScan();
	} else {
		if ((kDown & KEY_A) && n) {
			fl = (UiList){ 0 };
			appScreen(&appScreen_);
		}
		if (kDown & KEY_X) startScan();
		if (kDown & KEY_Y) save();
	}
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

// --- application screen ---

#define FILE_ROWS 4 // two lines each, under up to four lines of key settings

static void appDraw(void)
{
	const DfApp *a = &di.apps[al.sel];
	char hdr[48], s[120];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	int napps = di.napps < DF_MAX_APPS ? di.napps : DF_MAX_APPS;
	if ((a->aid & 0xF00000) == 0xF00000)
		snprintf(hdr, sizeof(hdr), "MAD AID %04lX   %d of %d", a->aid >> 4 & 0xFFFF, al.sel + 1, napps);
	else
		snprintf(hdr, sizeof(hdr), "%d of %d", al.sel + 1, napps);
	snprintf(s, sizeof(s), "DESFire: application %06lX", a->aid);
	uiHeader(s, hdr);
	float y = 26;
	if (a->hasIso) {
		snprintf(s, sizeof(s), "ISO FID %04X", a->isoFid);
		if (a->nameLen) {
			strcat(s, ", DF name ");
			hexStr(s + strlen(s), a->name, a->nameLen);
		}
	} else {
		snprintf(s, sizeof(s), "No ISO FID / DF name");
	}
	uiText(12, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 24, S_SMALL));
	y += SMALL_H;
	if (a->selSt) {
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "Select: %s", dfStatusName(a->selSt));
		uiFooter(BTN_UD " application   " BTN_B " back");
		return;
	}
	if (a->keySt) {
		uiText(12, y, S_SMALL, dim, "Key settings: %s", dfStatusName(a->keySt));
		y += SMALL_H;
	} else {
		u8 ks = a->keySet, ck = ks >> 4;
		char kv[48] = "?";
		bool same = a->nKeyVer > 0;
		for (int i = 1; i < a->nKeyVer; i++) same &= a->keyVer[i] == a->keyVer[0];
		if (same) snprintf(kv, sizeof(kv), "all %02X", a->keyVer[0]);
		else for (int i = 0, o = 0; i < a->nKeyVer; i++) o += sprintf(kv + o, "%s%02X", i ? " " : "", a->keyVer[i]);
		uiText(12, y, S_SMALL, txt, "%d %s key%s, versions %s   (key settings %02X)", a->maxKeys & 0xF, dfKeyType(a->maxKeys),
			(a->maxKeys & 0xF) == 1 ? "" : "s", kv, ks);
		y += SMALL_H;
		uiText(12, y, S_SMALL, txt, "File list: %s   create/delete: %s   config: %s", ks & 2 ? "free" : "master key",
			ks & 4 ? "free" : "master key", ks & 8 ? "changeable" : "frozen");
		y += SMALL_H;
		char ckey[32];
		if (ck == 0xF) snprintf(ckey, sizeof(ckey), "frozen");
		else if (ck == 0xE) snprintf(ckey, sizeof(ckey), "changed with the same key");
		else snprintf(ckey, sizeof(ckey), "changed with key %X", ck);
		uiText(12, y, S_SMALL, txt, "Master key: %s   other keys: %s", ks & 1 ? "changeable" : "frozen", ckey);
		y += SMALL_H;
	}
	y += 4;
	if (a->fileSt) {
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "File list: %s", dfStatusName(a->fileSt));
	} else if (!a->nfiles) {
		uiText(12, y, S_SMALL, dim, "No files");
	} else {
		if (a->nfiles > FILE_ROWS) uiTextRight(UI_W - 12, y + FILE_ROWS * (2 * SMALL_H + 3), S_SMALL, dim,
			"files %d-%d of %d", fl.top + 1, fl.top + FILE_ROWS < a->nfiles ? fl.top + FILE_ROWS : a->nfiles, a->nfiles);
		for (int i = 0; i < FILE_ROWS && fl.top + i < a->nfiles; i++, y += 2 * SMALL_H + 3) {
			const DfFile *f = &a->files[fl.top + i];
			char desc[96], keys[80], data[32] = "";
			dfFileDesc(f, desc, sizeof(desc));
			dfFileKeys(f, keys, sizeof(keys));
			if (fl.top + i == fl.sel) uiRect(8, y - 1, UI_W - 16, 2 * SMALL_H + 1, uiCol[COL_SEL]);
			uiText(14, y, S_SMALL, uiCol[COL_ACCENT], "%02X", f->fid);
			// what the read got, on the right of whichever line has room for it
			if (f->hasData && f->dataSt) snprintf(data, sizeof(data), "%s", dfStatusName(f->dataSt));
			else if (f->hasData) snprintf(data, sizeof(data), "%d bytes read", f->dataLen);
			float dw = *data ? uiTextWidth(S_SMALL, data) + 10 : 0, room = UI_W - 14 - 34;
			int dl = !*data || 34 + uiTextWidth(S_SMALL, desc) + dw <= UI_W - 14 ? 0 :
				34 + uiTextWidth(S_SMALL, keys) + dw <= UI_W - 14 ? 1 : 0;
			uiText(34, y, S_SMALL, f->st ? uiCol[COL_WARN] : txt, "%s", uiFit(desc, room - (dl ? 0 : dw), S_SMALL));
			uiText(34, y + SMALL_H, S_SMALL, dim, "%s", uiFit(keys, room - (dl ? dw : 0), S_SMALL));
			if (*data) uiTextRight(UI_W - 14, y + dl * SMALL_H, S_SMALL, uiCol[f->dataSt ? COL_WARN : COL_OK], "%s", data);
		}
	}
	const DfFile *f = a->fileSt || !a->nfiles ? NULL : &a->files[fl.sel];
	uiFooter(f && f->hasData && !f->dataSt ? BTN_A " contents   " BTN_UD " files   " BTN_LR " application   " BTN_Y " save   " BTN_B " back"
	                                       : BTN_UD " files   " BTN_LR " application   " BTN_Y " save   " BTN_B " back");
}

// A free-read file's contents: hex + ASCII, as much as fits a message box.
static void showData(const DfApp *a, const DfFile *f)
{
	char msg[480];
	int o = 0, n = f->dataLen < 96 ? f->dataLen : 96;
	for (int r = 0; r < n; r += 8) {
		for (int i = r; i < r + 8; i++)
			o += i < n ? sprintf(msg + o, "%02X ", di.pool[f->dataOff + i]) : sprintf(msg + o, "   ");
		for (int i = r; i < r + 8 && i < n; i++) {
			u8 c = di.pool[f->dataOff + i];
			msg[o++] = c >= 32 && c < 127 ? c : '.';
		}
		msg[o++] = '\n';
	}
	snprintf(msg + o, sizeof(msg) - o, f->dataLen > n ? "(%d more bytes in the saved file)" : "", f->dataLen - n);
	if (o && f->dataLen <= n) msg[o - 1] = 0;
	char title[48];
	snprintf(title, sizeof(title), "%06lX file %02X: %d bytes", a->aid, f->fid, f->dataLen);
	msgBox(title, "%s", msg);
}

static void appInput(u32 kDown, u32 kRepeat)
{
	const DfApp *a = &di.apps[al.sel];
	int n = di.napps < DF_MAX_APPS ? di.napps : DF_MAX_APPS;
	uiListNav(&fl, a->fileSt ? 0 : a->nfiles, FILE_ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	if (kRepeat & (KEY_LEFT | KEY_RIGHT)) {
		al.sel = (al.sel + (kRepeat & KEY_RIGHT ? 1 : n - 1)) % n;
		if (al.sel < al.top) al.top = al.sel;
		if (al.sel >= al.top + APP_ROWS) al.top = al.sel - APP_ROWS + 1;
		fl = (UiList){ 0 };
	}
	if ((kDown & KEY_A) && !a->fileSt && a->nfiles && a->files[fl.sel].hasData && !a->files[fl.sel].dataSt)
		showData(a, &a->files[fl.sel]);
	if (kDown & KEY_Y) save();
	if (kDown & KEY_B) appBack();
}

static const Screen appScreen_ = { NULL, appInput, appDraw };

// --- menu and family ---

static const MenuEntry dfEntries[] = {
	{ "Scan card", "Everything a DESFire tells without a key: version, storage, free memory, originality "
	               "signature, PICC and application key settings, applications and their files. Any other "
	               "ISO14443-4 card shows its ATS.", startScan },
};

static void dfExtra(float y)
{
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "Info files: " DF_DIR " (" BTN_Y " on the card screen)");
	if (sc.uidLen) menuLastCard(y + SMALL_H, &sc, diResult > 0 ? dfVersionName(&di) : cardTypeName(&sc));
}

static Menu dfMenu = { "DESFire", dfEntries, sizeof(dfEntries) / sizeof(dfEntries[0]), dfExtra };

static void dfMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&dfMenu, kDown, kRepeat);
}

static void dfMenuDraw(void)
{
	menuDraw(&dfMenu);
}

static void dfOpenMenu(void)
{
	static const Screen s = { NULL, dfMenuInput, dfMenuDraw };
	appScreen(&s);
}

// ISO14443-4 without Classic (SmartMX Classic emulation goes to the Classic family first).
static bool dfMatch(const Card *c)
{
	return (c->sak & 0x20) && !(c->sak & 0x08);
}

const CardFamily dfFamily = {
	"DESFire",
	"MIFARE DESFire (EV1-EV3, Light) without keys: version, storage, signature, key settings, applications "
	"and files, like pm3 hf mfdes info / lsapp --no-auth. Other ISO14443-4 cards: the ATS.",
	dfMatch, dfProbe, dfShow, dfOpenMenu,
};
