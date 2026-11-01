// MIFARE DESFire family (any ISO14443-4 card gets in, for its ATS): the card screen (keyless or with the key
// dictionary) and an application screen with its files. Saves the info as text to the SD card.

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

static bool withKeys; // the last scan tried the key dictionary

static int probe(bool keys)
{
	al = (UiList){ 0 };
	diResult = dfReadInfo(&di, keys);
	sc = card; // after our reselect: the ROM's ISO-DEP activation reports ATQA 0000
	snprintf(diWhy, sizeof(diWhy), "%s", dfWhy());
	if (diResult <= 0) logp("DESFire: %s\n", diWhy);
	iso14aParity(true);
	// not a DESFire, but an ATS is worth a screen
	return diResult < 0 ? -1 : diResult || di.atsLen;
}

static int dfProbe(void)
{
	return probe(false);
}

static int scanResult;

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = probe(withKeys);
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
	withKeys = false;
	jobStart("Scanning", runScan, doneScan, true);
}

static void startKeyScan(void)
{
	withKeys = true;
	jobStart("Scanning with keys", runScan, doneScan, true);
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
	char hdr[48], s[160];
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
	char pk[64];
	if (di.keyed && di.piccKey.known) {
		char hex[49];
		dfKeyHex(&di.piccKey, hex);
		snprintf(pk, sizeof(pk), "%s %s", dfKeyName(&di.piccKey), hex);
	} else {
		snprintf(pk, sizeof(pk), "%s%s", di.keySt ? "?" : dfKeyType(di.maxKeys), di.keyed ? ", not in the dictionary" : "");
	}
	if (di.keySt)
		snprintf(s, sizeof(s), "PICC master key: %s   key settings: %s", pk, dfStatusName(di.keySt));
	else if (di.keyed && di.piccKey.known) // the key takes the room
		snprintf(s, sizeof(s), "PICC key: %s, v%02X   AID list %s   create %s", pk, di.keyVer,
			di.keySet & 2 ? "free" : "keyed", di.keySet & 4 ? "free" : "keyed");
	else
		snprintf(s, sizeof(s), "PICC master key: %s, version %02X   AID list %s   create/delete %s", pk, di.keyVer,
			di.keySet & 2 ? "free" : "keyed", di.keySet & 4 ? "free" : "keyed");
	uiText(14, y, S_SMALL, di.keySt && !di.piccKey.known ? dim : txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
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
			int nk = a->maxKeys & 0xF, found = 0;
			for (int k = 0; k < nk && k < 14; k++) found += a->keys[k].known;
			if (!a->keySt && di.keyed) uiText(x, y + 1, S_SMALL, txt, "%d %s key%s, %d found", nk, dfKeyType(a->maxKeys),
				nk == 1 ? "" : "s", found);
			else if (!a->keySt) uiText(x, y + 1, S_SMALL, txt, "%d %s key%s", nk, dfKeyType(a->maxKeys), nk == 1 ? "" : "s");
			else if (a->keys[0].known) uiText(x, y + 1, S_SMALL, txt, "key 0 found");
			if (a->fileSt) uiTextRight(UI_W - 14, y + 1, S_SMALL, dim, "files: %s", dfStatusName(a->fileSt));
			else uiTextRight(UI_W - 14, y + 1, S_SMALL, txt, "%d file%s", a->nfiles, a->nfiles == 1 ? "" : "s");
		}
	}
	uiFooter(n ? BTN_A " application   " BTN_X " scan   " BTN_R " with keys   " BTN_Y " save   " BTN_B " back"
	           : BTN_X " scan   " BTN_R " with keys   " BTN_Y " save   " BTN_B " back");
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
		if (kDown & KEY_R) startKeyScan();
		if (kDown & KEY_Y) save();
	}
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

// --- application screen ---

#define FILE_ROWS 4 // two lines each, under up to four lines of key settings

// The dictionary's finds: "Keys: 0 DES 00000000..  1 AES 00112233..  2 ?", the start of each key
static void keysLine(const DfApp *a, float y)
{
	char s[160] = "Keys:";
	int n = a->keySt ? 1 : a->maxKeys & 0xF;
	for (int k = 0, o = 5; k < n && k < 14 && o < (int)sizeof(s) - 24; k++) {
		char hex[49];
		dfKeyHex(&a->keys[k], hex);
		if (a->keys[k].known) o += sprintf(s + o, "  %d %s %.8s..", k, dfKeyName(&a->keys[k]), hex);
		else o += sprintf(s + o, "  %d ?", k);
	}
	uiText(12, y, S_SMALL, uiCol[COL_TEXT], "%s", uiFit(s, UI_W - 24, S_SMALL));
}

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
		if (di.keyed) keysLine(a, y), y += SMALL_H;
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
		if (di.keyed) keysLine(a, y);
		else uiText(12, y, S_SMALL, txt, "Master key: %s   other keys: %s", ks & 1 ? "changeable" : "frozen", ckey);
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
			bool noKey = di.keyed && !f->hasData && !f->st && !dfFreeRead(f);
			if (f->hasData && f->dataSt) snprintf(data, sizeof(data), "%s", dfStatusName(f->dataSt));
			else if (f->hasData && f->dataKey != 0xE) snprintf(data, sizeof(data), "%d bytes, key %X", f->dataLen, f->dataKey);
			else if (f->hasData) snprintf(data, sizeof(data), "%d bytes read", f->dataLen);
			else if (noKey) snprintf(data, sizeof(data), "no key");
			float dw = *data ? uiTextWidth(S_SMALL, data) + 10 : 0, room = UI_W - 14 - 34;
			int dl = !*data || 34 + uiTextWidth(S_SMALL, desc) + dw <= UI_W - 14 ? 0 :
				34 + uiTextWidth(S_SMALL, keys) + dw <= UI_W - 14 ? 1 : 0;
			uiText(34, y, S_SMALL, f->st ? uiCol[COL_WARN] : txt, "%s", uiFit(desc, room - (dl ? 0 : dw), S_SMALL));
			uiText(34, y + SMALL_H, S_SMALL, dim, "%s", uiFit(keys, room - (dl ? dw : 0), S_SMALL));
			if (*data) uiTextRight(UI_W - 14, y + dl * SMALL_H, S_SMALL, noKey ? dim : uiCol[f->dataSt ? COL_WARN : COL_OK], "%s", data);
		}
	}
	const DfFile *f = a->fileSt || !a->nfiles ? NULL : &a->files[fl.sel];
	uiFooter(f && f->hasData && !f->dataSt ? BTN_A " contents   " BTN_UD " files   " BTN_LR " application   " BTN_Y " save   " BTN_B " back"
	                                       : BTN_UD " files   " BTN_LR " application   " BTN_Y " save   " BTN_B " back");
}

// --- file contents: a hex + ASCII grid on the dump editor's layout (editor.c) ---

#define DATA_Y    39
#define DATA_ROWS 13
#define HEX_X     26
#define BYTE_W    16.5f
#define ASCII_X   300
#define ASCII_W   5.8f
#define S_ASCII   0.34f

static const DfFile *df_;
static int dtop;

static float byteX(int i)
{
	return HEX_X + i * BYTE_W + (i >= 8 ? 3 : 0);
}

static void dataDraw(void)
{
	const DfApp *a = &di.apps[al.sel];
	const DfFile *f = df_;
	const u8 *p = di.pool + f->dataOff;
	char t[48], h[32];
	snprintf(t, sizeof(t), "DESFire: %06lX file %02X", a->aid, f->fid);
	if (f->dataKey == 0xE) snprintf(h, sizeof(h), "%d bytes, free read", f->dataLen);
	else snprintf(h, sizeof(h), "%d bytes, key %X", f->dataLen, f->dataKey);
	uiHeader(t, h);
	for (int i = 0; i < 16; i++) {
		char c[2] = { "0123456789ABCDEF"[i], 0 };
		uiMono(byteX(i) + MONO_W / 2, DATA_Y - 9, uiCol[COL_DIM], c);
	}
	int rows = (f->dataLen + 15) / 16;
	for (int r = dtop; r < rows && r < dtop + DATA_ROWS; r++) {
		float y = DATA_Y + 2 + (r - dtop) * 13;
		char s[17];
		snprintf(s, sizeof(s), "%03X", r * 16);
		uiMonoS(0, y, S_MONO, 7, uiCol[COL_DIM], s);
		int n = f->dataLen - r * 16 < 16 ? f->dataLen - r * 16 : 16;
		for (int i = 0; i < n; i++) {
			u8 c = p[r * 16 + i];
			snprintf(s, sizeof(s), "%02X", c);
			uiMono(byteX(i), y, uiCol[COL_TEXT], s);
		}
		for (int i = 0; i < n; i++) s[i] = p[r * 16 + i] >= 32 && p[r * 16 + i] < 127 ? p[r * 16 + i] : '.';
		s[n] = 0;
		uiMonoS(ASCII_X, y + 1, S_ASCII, ASCII_W, uiCol[COL_DIM], s);
	}
	if (rows > DATA_ROWS) {
		float hh = DATA_ROWS * 13, bar = hh * DATA_ROWS / rows;
		uiRect(UI_W - 4, DATA_Y + 1, 2, hh, uiCol[COL_PANEL]);
		uiRect(UI_W - 4, DATA_Y + 1 + hh * dtop / rows, 2, bar, uiCol[COL_DIM]);
	}
	uiFooter(rows > DATA_ROWS ? BTN_UD " scroll   " BTN_B " back" : BTN_B " back");
}

static void dataInput(u32 kDown, u32 kRepeat)
{
	int rows = (df_->dataLen + 15) / 16, max = rows > DATA_ROWS ? rows - DATA_ROWS : 0;
	if ((kRepeat & KEY_UP) && dtop > 0) dtop--;
	if ((kRepeat & KEY_DOWN) && dtop < max) dtop++;
	if (kDown & KEY_B) appBack();
}

static void showData(const DfFile *f)
{
	static const Screen s = { NULL, dataInput, dataDraw };
	df_ = f, dtop = 0;
	appScreen(&s);
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
		showData(&a->files[fl.sel]);
	if (kDown & KEY_Y) save();
	if (kDown & KEY_B) appBack();
}

static const Screen appScreen_ = { NULL, appInput, appDraw };

// --- menu and family ---

static const MenuEntry dfEntries[] = {
	{ "Scan card", "Everything a DESFire tells without a key: version, storage, free memory, originality "
	               "signature, PICC and application key settings, applications and their files. Any other "
	               "ISO14443-4 card shows its ATS.", startScan },
	{ "Scan with keys", "The same, then the key dictionary (built in + " DF_KEYS ") on the PICC master key and "
	                    "every application key (DES, 2K3DES, 3K3DES, AES; AES over EV2 on EV2 / EV3 cards). Found "
	                    "keys open protected lists and files, in plain, MAC and full (encrypted) mode.", startKeyScan },
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
	"MIFARE DESFire (EV1-EV3, Light): version, storage, signature, key settings, applications and files, "
	"like pm3 hf mfdes info / lsapp; a key dictionary for protected ones. Other ISO14443-4 cards: the ATS.",
	dfMatch, dfProbe, dfShow, dfOpenMenu,
};
