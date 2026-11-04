// MIFARE DESFire family (any ISO14443-4 card gets in, for its ATS): the card screen (keyless or with the key
// dictionary) and an application screen with its files. Saves the info as text to the SD card.

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <3ds.h>

#include "app.h"
#include "desfire.h"
#include "dumplist.h"
#include "entry.h"
#include "pm3dict.h"
#include "probe.h"
#include "ui.h"

static Card sc;
static DfInfo di;
static int diResult; // dfReadInfo
static char diWhy[64];
static UiList al;

static const Screen cardScreen, appScreen_;
static void cardMenu(void), appMenu(void);

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

// From the generic scan: a card that isn't a DESFire goes on to the smart card family.
static int dfProbe(void)
{
	int r = probe(false);
	return r > 0 && diResult <= 0 ? FAMILY_PASS : r;
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
	if (dfSaveInfo(&di, path, sizeof(path))) toast("Saved %s", path + strlen(APP_DIR "/"));
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
	if (di.randomUid) {
		// the random one big on the left, the real one (GetCardUID) on the same row, right
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "Random UID (new every time)");
		if (di.hasRealUid) {
			char r[24];
			for (int i = 0; i < 7; i++) sprintf(r + 3 * i, "%02X ", di.realUid[i]);
			r[20] = 0;
			uiTextRight(UI_W - 12, y, S_SMALL, dim, "real UID (7 bytes)");
			uiTextRight(UI_W - 12, y + 16, 0.6f, txt, "%s", r);
		} else {
			uiTextRight(UI_W - 12, y, S_SMALL, dim, "real UID: needs the PICC key");
		}
	} else {
		uiText(12, y, S_SMALL, dim, "UID (%d bytes)", sc.uidLen);
	}
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
		uiText(14, y + SMALL_H, S_SMALL, uiCol[di.sigKey ? COL_OK : COL_WARN], "%s", di.sigKey ? "valid" : "invalid");
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
			if (al.top + i == al.sel) uiSel(8, y - 1, UI_W - 16, LINE_H);
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
	uiFooter(n ? BTN_A " application   " BTN_X " scan   " BTN_R " with keys   " BTN_Y " card   " BTN_B " back"
	           : BTN_X " scan   " BTN_R " with keys   " BTN_Y " card   " BTN_B " back");
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
		if (kDown & KEY_Y) cardMenu();
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
	const char *vendor, *name = dfAidName(a->aid, &vendor);
	char nm[96] = "";
	if (name) snprintf(nm, sizeof(nm), "%s (%s)   ", name, vendor);
	if (a->hasIso) {
		snprintf(s, sizeof(s), "%sISO FID %04X", nm, a->isoFid);
		if (a->nameLen) {
			strcat(s, ", DF name ");
			hexStr(s + strlen(s), a->name, a->nameLen);
		}
	} else {
		snprintf(s, sizeof(s), "%s%s", nm, name ? "no ISO FID" : "No ISO FID / DF name");
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
			if (fl.top + i == fl.sel) uiSel(8, y - 1, UI_W - 16, 2 * SMALL_H + 1);
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
	uiFooter(f && f->hasData && !f->dataSt ? BTN_A " contents   " BTN_UD " files   " BTN_LR " application   " BTN_Y " application menu   " BTN_B " back"
	                                       : BTN_UD " files   " BTN_LR " application   " BTN_Y " application menu   " BTN_B " back");
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
static int dataIsoFid = -1; // an ISO 7816 EF's contents (df_ a stand-in), -1 = a native file
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
	if (dataIsoFid >= 0) snprintf(t, sizeof(t), "DESFire: %06lX EF %04X (ISO 7816)", a->aid, dataIsoFid);
	else snprintf(t, sizeof(t), "DESFire: %06lX file %02X", a->aid, f->fid);
	if (dataIsoFid >= 0) snprintf(h, sizeof(h), "%d bytes", f->dataLen);
	else if (f->dataKey == 0xE) snprintf(h, sizeof(h), "%d bytes, free read", f->dataLen);
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
	if (f->set[0] == 5 && f->dataLen == 12 && dataIsoFid < 0)
		uiText(12, DATA_Y + 2 + 13 + 8, S_BODY, uiCol[COL_TEXT], "TMC %lu   TMV %02X%02X%02X%02X%02X%02X%02X%02X",
			(u32)(p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24), p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]);
	if (f->set[0] == 2 && f->dataLen == 4) {
		s32 v;
		memcpy(&v, p, 4);
		uiText(12, DATA_Y + 2 + 13 + 8, S_BODY, uiCol[COL_TEXT], "Value: %ld", v);
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
	df_ = f, dtop = 0, dataIsoFid = -1;
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
	if (kDown & KEY_Y) appMenu();
	if (kDown & KEY_B) appBack();
}

static const Screen appScreen_ = { NULL, appInput, appDraw };

// --- operations: create / write / delete / format / keys ---
// Each runs as a job: the scanned card on the reader (same UID), the operation, then a scan with keys
// so the screens show the result. A key the operation needs and the last scan didn't find is asked
// for first; keys that worked or were set go into DF_KEYS (the dictionary) for later scans.

static struct {
	const char *title;
	u32 aid;      // 0 = PICC
	u32 focus;    // the application the screens go back to afterwards
	int k;        // the key to authenticate with, -1 = none
	DfKey key;
	u8 c[300];    // the command (len 0: authenticate only)
	u32 len, hdr;
	u8 comm;
	u8 flags; // dfOp's
	bool change, picc; // ChangeKey: key nk becomes nkey (AES: version ver), old = its current one
	u8 nk, ver;
	DfKey nkey, old;
	int result;
	char why[80];
} op;

static int file_; // the application screen's file list selection, kept over the rescan
static DfKey *entered; // a key the user just entered: forgotten if it didn't authenticate

static void runOp(void)
{
	op.result = 0;
	*op.why = 0;
	if (!cardWait()) return;
	if (!dfRandomUid(&sc) && (card.uidLen != sc.uidLen || memcmp(card.uid, sc.uid, sc.uidLen))) {
		snprintf(op.why, sizeof(op.why), "Not the card that was scanned (another UID).");
		return;
	}
	const DfKey *k = op.k < 0 ? NULL : &op.key;
	if (op.change) op.result = dfOpChangeKey(&di, op.aid, op.k, k, op.nk, &op.nkey, op.ver, &op.old, op.picc);
	else if (!op.len) op.result = dfOpAuth(&di, op.aid, op.k, k);
	else op.result = dfOp(&di, op.aid, op.k, k, op.c, op.len, op.hdr, op.comm, op.flags);
	snprintf(op.why, sizeof(op.why), "%s", dfWhy());
	logp("%s: %s\n", op.title, op.result > 0 ? "done" : op.why);
	if (op.result > 0) {
		if (k) dfRememberKey(k);
		progOp("Reading the card again");
		probe(true);
	}
	iso14aParity(true);
}

static void doneOp(void)
{
	if (op.result <= 0) {
		if (entered && !strncmp(op.why, "key ", 4)) entered->known = false;
		entered = NULL;
		if (op.result < 0) msgBox(op.title, "The chip stopped answering.\nTry again.");
		else if (!mfCancel) msgBox(op.title, "Failed: %s", *op.why ? op.why : "no card");
		return;
	}
	entered = NULL;
	if (dfTmacLen) {
		u32 tmc = dfTmac[0] | dfTmac[1] << 8 | dfTmac[2] << 16 | dfTmac[3] << 24;
		toast("%s: done   TMC %lu   TMV %02X%02X%02X%02X%02X%02X%02X%02X", op.title, tmc, dfTmac[4], dfTmac[5], dfTmac[6],
			dfTmac[7], dfTmac[8], dfTmac[9], dfTmac[10], dfTmac[11]);
	} else {
		toast("%s: done", op.title);
	}
	// back where it was: the application by its AID, the file by its place
	int n = di.napps < DF_MAX_APPS ? di.napps : DF_MAX_APPS, found = -1;
	for (int i = 0; i < n; i++)
		if (di.apps[i].aid == op.focus) found = i;
	if (found >= 0) {
		al.sel = found, al.top = found >= APP_ROWS ? found - APP_ROWS + 1 : 0;
		int nf = di.apps[found].nfiles;
		fl.sel = file_ < nf ? file_ : nf ? nf - 1 : 0;
		fl.top = fl.sel >= 4 ? fl.sel - 3 : 0;
	} else if (appTop() == &appScreen_) {
		appBack(); // its application is gone
	}
}

static void opRun(void)
{
	jobStart(op.title, runOp, doneOp, true);
}

static void opReset(const char *title, u32 aid)
{
	memset(&op, 0, sizeof(op));
	op.title = title, op.aid = op.focus = aid, op.k = -1;
}

static void opAuth(int k, const DfKey *key)
{
	op.k = k;
	if (key) op.key = *key;
}

static void opCmd(const u8 *c, u32 len, u32 hdr, u8 comm, u8 flags)
{
	memcpy(op.c, c, len);
	op.len = len, op.hdr = hdr, op.comm = comm, op.flags = flags;
}

// --- keys the user enters ---

static struct {
	DfKey *slot;
	void (*cont)(void);
	char title[64], what[128];
} need;

static void needEntered(const u8 *b, u32 len)
{
	DfKey *s = need.slot;
	u8 type = s->type; // needAs set it
	memset(s, 0, sizeof(*s));
	s->known = true;
	s->type = type;
	memcpy(s->key, b, len);
	if (len == 8) memcpy(s->key + 8, b, 8), s->type = DF_2K3DES;
	entered = s;
	need.cont();
}

static void needAs(u8 type, u32 len)
{
	need.slot->type = type;
	char what[160];
	snprintf(what, sizeof(what), "%s (%s, %lu bytes).", need.what, len == 8 ? "DES" : dfKeyTypeName(type), len);
	entryHex(need.title, what, len, NULL, needEntered);
}

static void needDes(void) { needAs(DF_2K3DES, 8); }
static void need2k(void) { needAs(DF_2K3DES, 16); }
static void need3k(void) { needAs(DF_3K3DES, 24); }
static void needAes(void) { needAs(DF_AES, 16); }

// Asks for a key of type kt (GetKeySettings bits 6-7; -1 = unknown) into slot, then cont.
static void askKey(DfKey *slot, int kt, const char *title, const char *what, void (*cont)(void))
{
	need.slot = slot, need.cont = cont;
	snprintf(need.title, sizeof(need.title), "%s", title);
	snprintf(need.what, sizeof(need.what), "%s", what);
	if (kt == 1) need3k();
	else if (kt == 2) needAes();
	else if (kt == 0) {
		static const MenuItem items[] = { { "DES (8 bytes)", needDes }, { "2K3DES (16 bytes)", need2k } };
		popup("Key type", items, 2);
	} else {
		static const MenuItem items[] = { { "AES (16 bytes)", needAes }, { "DES (8 bytes)", needDes },
			{ "2K3DES (16 bytes)", need2k }, { "3K3DES (24 bytes)", need3k } };
		popup("Key type", items, 4);
	}
}

// Key k of aid (slot): known goes straight on, else the user enters it first.
static void needKey(u32 aid, int k, DfKey *slot, int kt, void (*cont)(void))
{
	if (slot->known) {
		cont();
		return;
	}
	char t[64], w[128];
	if (aid) snprintf(t, sizeof(t), "%06lX key %d", aid, k), snprintf(w, sizeof(w), "Key %d of application %06lX is not known: enter it", k, aid);
	else snprintf(t, sizeof(t), "PICC master key"), snprintf(w, sizeof(w), "The PICC master key is not known: enter it");
	askKey(slot, kt, t, w, cont);
}

static int piccType(void)
{
	return di.keySt ? -1 : di.maxKeys >> 6;
}

static int appType(const DfApp *a)
{
	return a->keySt ? -1 : a->maxKeys >> 6;
}

static DfApp *curApp(void)
{
	return &di.apps[al.sel];
}

static DfFile *curFile(void)
{
	DfApp *a = curApp();
	return a->fileSt || !a->nfiles ? NULL : &a->files[fl.sel];
}

static const char *const keyTypes[] = { "DES / 2K3DES", "3K3DES", "AES" };

// --- create application ---

static struct {
	u32 aid;
	int type, nkeys; // type: GetKeySettings bits 6-7
	u8 ks;
	u16 isoFid;      // 0 = no ISO IDs
	u8 dfName[16], dfLen;
} ca = { 0x112233, 2, 2, 0x0F };

static void caAidV(char *o) { sprintf(o, "%06lX", ca.aid); }
static void caTypeV(char *o) { sprintf(o, "%s", keyTypes[ca.type]); }
static void caKeysV(char *o) { sprintf(o, "%d", ca.nkeys); }
static void caKsV(char *o) { sprintf(o, "%02X", ca.ks); }
static void caAidSet(const u8 *b, u32 len) { ca.aid = b[0] << 16 | b[1] << 8 | b[2]; }
static void caAidE(void)
{
	u8 b[3] = { ca.aid >> 16, ca.aid >> 8, ca.aid };
	entryHex("Application ID", "The new application's AID (3 bytes, as shown). 000000 is the PICC.", 3, b, caAidSet);
}
static void caT0(void) { ca.type = 0; }
static void caT1(void) { ca.type = 1; }
static void caT2(void) { ca.type = 2; }
static void caTypeE(void)
{
	static const MenuItem items[] = { { "DES / 2K3DES", caT0 }, { "3K3DES", caT1 }, { "AES", caT2 } };
	popup("Key type", items, 3);
}
static void caKeysSet(s64 v) { ca.nkeys = v; }
static void caKeysE(void) { entryDec("Number of keys", "Keys in the application (key 0 is its master key).", 1, 14, ca.nkeys, caKeysSet); }
static void caKsSet(const u8 *b, u32 len) { ca.ks = b[0]; }
static void caKsE(void)
{
	entryHex("Key settings", "Bit 0: master key changeable, 1: file list free, 2: create / delete free, 3: "
		"configuration changeable; bits 4-7: the key that changes keys (E: the key itself, F: frozen). 0F = all open, "
		"keys changed with the master key.", 1, &ca.ks, caKsSet);
}

static void caFidV(char *o)
{
	if (ca.isoFid) sprintf(o, "%04X", ca.isoFid);
	else strcpy(o, "none");
}
static void caFidSet(const u8 *b, u32 len) { ca.isoFid = b[0] << 8 | b[1]; }
static void caFidE(void)
{
	u8 b[2] = { ca.isoFid >> 8, ca.isoFid };
	entryHex("ISO FID", "The application's ISO 7816 file ID (2 bytes, e.g. E110), for ISO SELECT. 0000 = no ISO IDs "
		"(and no DF name).", 2, b, caFidSet);
}
static void caNameV(char *o)
{
	if (!ca.isoFid || !ca.dfLen) {
		strcpy(o, "none");
		return;
	}
	for (int i = 0; i < ca.dfLen && i < 12; i++) sprintf(o + 2 * i, "%02X", ca.dfName[i]);
	if (ca.dfLen > 12) strcat(o, "..");
}
static void caNameSet(const u8 *b, u32 len) { memcpy(ca.dfName, b, len); }
static void caNameLen(s64 v)
{
	ca.dfLen = v;
	if (v) entryHex("DF name", "The application's ISO DF name (AID for ISO SELECT by name, e.g. D2760000850101 "
		"for an NDEF Type 4 application).", v, ca.dfName, caNameSet);
}
static void caNameE(void)
{
	if (!ca.isoFid) {
		msgBox("DF name", "Set an ISO FID first: a DF name needs ISO IDs.");
		return;
	}
	entryDec("DF name length", "Bytes in the DF name, 1-16 (0 = none).", 0, 16, ca.dfLen, caNameLen);
}

static const Field caFields[] = {
	{ "Application ID", caAidV, caAidE }, { "Key type", caTypeV, caTypeE },
	{ "Keys", caKeysV, caKeysE }, { "Key settings", caKsV, caKsE },
	{ "ISO FID", caFidV, caFidE }, { "DF name", caNameV, caNameE },
};
static int caCount(void) { return 6; }

static void caGo(void)
{
	opReset("Create application", 0); // on the PICC
	op.focus = ca.aid;
	if (!(di.keySet & 4) || di.keySt) opAuth(0, &di.piccKey);
	u8 c[26] = { 0xCA, ca.aid, ca.aid >> 8, ca.aid >> 16, ca.ks, ca.nkeys | ca.type << 6 };
	u32 n = 6;
	if (ca.isoFid) { // ISO file IDs: bit 5, the FID (LSB first), the DF name
		c[5] |= 0x20;
		c[n++] = ca.isoFid, c[n++] = ca.isoFid >> 8;
		memcpy(c + n, ca.dfName, ca.dfLen), n += ca.dfLen;
	}
	opCmd(c, n, 0, DF_PLAIN, false);
	opRun();
}

static void caRun(void)
{
	if (ca.aid == 0) {
		msgBox("Create application", "AID 000000 is the PICC itself.");
		return;
	}
	// creating needs the PICC master key unless the PICC's key settings make it free
	if ((di.keySet & 4) && !di.keySt) caGo();
	else needKey(0, 0, &di.piccKey, piccType(), caGo);
}

static void createApp(void)
{
	formOpen("DESFire: create application", "Create", "Its keys start as all zeros of the key type.",
		caFields, caCount, caRun);
}

// --- format ---

static void fmtGo(void)
{
	opReset("Format card", 0);
	opAuth(0, &di.piccKey);
	u8 c = 0xFC;
	opCmd(&c, 1, 0, DF_PLAIN, false);
	opRun();
}

static void fmtAsk(void)
{
	confirm("Format card", fmtGo, "Delete every application and file on this card? The PICC master key stays. "
		"This can't be undone.");
}

static void format(void)
{
	needKey(0, 0, &di.piccKey, piccType(), fmtAsk);
}

// --- delete application ---

static void daGo(void)
{
	u32 aid = curApp()->aid;
	opReset("Delete application", 0);
	op.focus = aid; // gone afterwards: back to the card screen
	opAuth(0, &di.piccKey);
	u8 c[4] = { 0xDA, aid, aid >> 8, aid >> 16 };
	opCmd(c, 4, 0, DF_PLAIN, false);
	opRun();
}

static void daNeed(void)
{
	needKey(0, 0, &di.piccKey, piccType(), daGo);
}

static void deleteApp(void)
{
	confirm("Delete application", daNeed, "Delete application %06lX and all of its files? This can't be undone.",
		curApp()->aid);
}

// --- create file ---

static struct {
	int fid, type, comm, r, w, rw, ch;
	s64 size, lower, upper, value, recSize, recMax;
	bool lc;
	u16 isoFid; // 0 = none (only for applications with ISO IDs)
	u8 tmKey[16], tmVer; // transaction MAC: its AES key and version
} cf = { 1, 0, 0, 0xE, 0, 0, 0, 32, 0, 1000, 0, 16, 4, false, 0 };

static void cfTmKeyV(char *o)
{
	for (int i = 0; i < 6; i++) sprintf(o + 2 * i, "%02X", cf.tmKey[i]);
	strcat(o, "..");
}
static void cfTmKeySet(const u8 *b, u32 len) { memcpy(cf.tmKey, b, 16); }
static void cfTmKeyE(void)
{
	entryHex("Transaction MAC key", "The AES key the card computes the transaction MACs (TMV) with.", 16, cf.tmKey, cfTmKeySet);
}
static void cfTmVerV(char *o) { sprintf(o, "%02X", cf.tmVer); }
static void cfTmVerSet(s64 v) { cf.tmVer = v; }
static void cfTmVerE(void) { entryDec("Key version", "The transaction MAC key's version.", 0, 255, cf.tmVer, cfTmVerSet); }

static void cfIsoV(char *o)
{
	if (cf.isoFid) sprintf(o, "%04X", cf.isoFid);
	else strcpy(o, "none");
}
static void cfIsoSet(const u8 *b, u32 len) { cf.isoFid = b[0] << 8 | b[1]; }
static void cfIsoE(void)
{
	u8 b[2] = { cf.isoFid >> 8, cf.isoFid };
	entryHex("ISO FID", "The file's ISO 7816 file ID (2 bytes, e.g. E104), for ISO SELECT. 0000 = none.", 2, b, cfIsoSet);
}

static const char *const fileTypes[] = { "standard", "backup", "value", "linear record", "cyclic record", "transaction MAC" };
static const char *const commModes[] = { "plain", "MAC", "full (encrypted)" };

static void keyWord(char *o, int k)
{
	if (k == 0xE) strcpy(o, "free");
	else if (k == 0xF) strcpy(o, "never");
	else sprintf(o, "key %d", k);
}

static void cfFidV(char *o) { sprintf(o, "%02X", cf.fid); }
static void cfTypeV(char *o) { strcpy(o, fileTypes[cf.type]); }
static void cfCommV(char *o) { strcpy(o, commModes[cf.comm]); }
static void cfRV(char *o) { keyWord(o, cf.r); }
static void cfWV(char *o) { keyWord(o, cf.w); }
static void cfRwV(char *o) { keyWord(o, cf.rw); }
static void cfChV(char *o) { keyWord(o, cf.ch); }
static void cfSizeV(char *o) { sprintf(o, "%lld bytes", cf.size); }
static void cfLowerV(char *o) { sprintf(o, "%lld", cf.lower); }
static void cfUpperV(char *o) { sprintf(o, "%lld", cf.upper); }
static void cfValueV(char *o) { sprintf(o, "%lld", cf.value); }
static void cfLcV(char *o) { strcpy(o, cf.lc ? "on" : "off"); }
static void cfRecSizeV(char *o) { sprintf(o, "%lld bytes", cf.recSize); }
static void cfRecMaxV(char *o) { sprintf(o, "%lld", cf.recMax); }

static void cfFidSet(s64 v) { cf.fid = v; }
static void cfFidE(void) { entryDec("File number", "The new file's number, 0-31.", 0, 31, cf.fid, cfFidSet); }
static void cfT0(void) { cf.type = 0; }
static void cfT1(void) { cf.type = 1; }
static void cfT2(void) { cf.type = 2; }
static void cfT3(void) { cf.type = 3; }
static void cfT4(void) { cf.type = 4; }
static void cfT5(void) { cf.type = 5, cf.w = 0xF; } // TMAC: write is RFU
static void cfTypeE(void)
{
	static const MenuItem items[] = { { "Standard data", cfT0 }, { "Backup data", cfT1 }, { "Value", cfT2 },
		{ "Linear record", cfT3 }, { "Cyclic record", cfT4 }, { "Transaction MAC", cfT5 } };
	popup("File type", items, 6);
}
static void cfC0(void) { cf.comm = 0; }
static void cfC1(void) { cf.comm = 1; }
static void cfC2(void) { cf.comm = 2; }
static void cfCommE(void)
{
	static const MenuItem items[] = { { "Plain", cfC0 }, { "MAC", cfC1 }, { "Full (encrypted)", cfC2 } };
	popup("Communication", items, 3);
}
static int *cfKeyField;
static void cfKeySet(s64 v) { *cfKeyField = v; }
static void cfKeyE(int *k, const char *what)
{
	cfKeyField = k;
	char w[96];
	snprintf(w, sizeof(w), "The key for %s: 0-13 a key number, 14 free, 15 never.", what);
	entryDec("Access key", w, 0, 15, *k, cfKeySet);
}
static void cfRE(void) { cfKeyE(&cf.r, "reading"); }
static void cfWE(void) { cfKeyE(&cf.w, "writing"); }
static void cfRwE(void) { cfKeyE(&cf.rw, "reading and writing"); }
static void cfChE(void) { cfKeyE(&cf.ch, "changing the file's settings"); }
static s64 *cfNum;
static void cfNumSet(s64 v) { *cfNum = v; }
static void cfNumE(s64 *v, const char *title, const char *what, s64 min, s64 max)
{
	cfNum = v;
	entryDec(title, what, min, max, *v, cfNumSet);
}
static void cfSizeE(void) { cfNumE(&cf.size, "File size", "Bytes in the file.", 1, 8192); }
static void cfLowerE(void) { cfNumE(&cf.lower, "Lower limit", "The lowest value the file may hold.", 0, 0x7FFFFFFF); }
static void cfUpperE(void) { cfNumE(&cf.upper, "Upper limit", "The highest value the file may hold.", 0, 0x7FFFFFFF); }
static void cfValueE(void) { cfNumE(&cf.value, "Value", "The value it starts with.", 0, 0x7FFFFFFF); }
static void cfLcE(void) { cf.lc = !cf.lc; }
static void cfRecSizeE(void) { cfNumE(&cf.recSize, "Record size", "Bytes per record.", 1, 1024); }
static void cfRecMaxE(void) { cfNumE(&cf.recMax, "Records", "How many records the file holds.", 1, 1024); }

// The fields shown: the common ones, then the type's own.
static Field cfShown[14];

static int cfCount(void)
{
	static const Field common[] = {
		{ "File number", cfFidV, cfFidE }, { "Type", cfTypeV, cfTypeE }, { "Communication", cfCommV, cfCommE },
		{ "Read", cfRV, cfRE }, { "Write", cfWV, cfWE }, { "Read / write", cfRwV, cfRwE },
		{ "Change settings", cfChV, cfChE },
	};
	int n = 0;
	for (; n < 7; n++) cfShown[n] = common[n];
	if (cf.type <= 1) {
		cfShown[n++] = (Field){ "Size", cfSizeV, cfSizeE };
	} else if (cf.type == 2) {
		cfShown[n++] = (Field){ "Lower limit", cfLowerV, cfLowerE };
		cfShown[n++] = (Field){ "Upper limit", cfUpperV, cfUpperE };
		cfShown[n++] = (Field){ "Value", cfValueV, cfValueE };
		cfShown[n++] = (Field){ "Limited credit", cfLcV, cfLcE };
	} else if (cf.type == 5) {
		cfShown[n++] = (Field){ "TM key", cfTmKeyV, cfTmKeyE };
		cfShown[n++] = (Field){ "TM key version", cfTmVerV, cfTmVerE };
	} else {
		cfShown[n++] = (Field){ "Record size", cfRecSizeV, cfRecSizeE };
		cfShown[n++] = (Field){ "Records", cfRecMaxV, cfRecMaxE };
	}
	if (curApp()->hasIso && cf.type != 2 && cf.type != 5) cfShown[n++] = (Field){ "ISO FID", cfIsoV, cfIsoE }; // value files have none
	return n;
}

static void put24(u8 *p, u32 v)
{
	p[0] = v, p[1] = v >> 8, p[2] = v >> 16;
}

static void put32le(u8 *p, u32 v)
{
	p[0] = v, p[1] = v >> 8, p[2] = v >> 16, p[3] = v >> 24;
}

static void cfGo(void)
{
	DfApp *a = curApp();
	opReset("Create file", a->aid);
	if (!(a->keySet & 4) || a->keySt) opAuth(0, &a->keys[0]);
	static const u8 cmds[] = { 0xCD, 0xCB, 0xCC, 0xC1, 0xC0, 0xCE };
	u8 c[32] = { cmds[cf.type], cf.fid };
	u32 n = 2;
	if (curApp()->hasIso && cf.type != 2 && cf.type != 5 && cf.isoFid) c[n++] = cf.isoFid, c[n++] = cf.isoFid >> 8;
	c[n++] = cf.comm == 2 ? 3 : cf.comm, c[n++] = cf.rw << 4 | cf.ch, c[n++] = cf.r << 4 | cf.w;
	if (cf.type <= 1) {
		put24(c + n, cf.size), n += 3;
	} else if (cf.type == 2) {
		put32le(c + n, cf.lower), put32le(c + n + 4, cf.upper), put32le(c + n + 8, cf.value), n += 12;
		c[n++] = cf.lc;
	} else if (cf.type == 5) { // key option 02 (AES), the key and its version go encrypted
		c[n++] = 0x02;
		memcpy(c + n, cf.tmKey, 16), n += 16;
		c[n++] = cf.tmVer;
		opCmd(c, n, 5, DF_FULL, 0);
		file_ = a->nfiles;
		opRun();
		return;
	} else {
		put24(c + n, cf.recSize), put24(c + n + 3, cf.recMax), n += 6;
	}
	opCmd(c, n, 0, DF_PLAIN, false);
	file_ = a->nfiles; // the new one: its place once the list is read again (IDs come sorted)
	opRun();
}

static void cfRun(void)
{
	DfApp *a = curApp();
	if (cf.type == 2 && (cf.lower > cf.upper || cf.value < cf.lower || cf.value > cf.upper)) {
		msgBox("Create file", "The value must lie within the limits.");
		return;
	}
	if ((a->keySet & 4) && !a->keySt) cfGo();
	else needKey(a->aid, 0, &a->keys[0], appType(a), cfGo);
}

static void createFile(void)
{
	// the first free file number
	DfApp *a = curApp();
	for (cf.fid = 0; cf.fid < 32; cf.fid++) {
		bool used = false;
		for (int i = 0; i < a->nfiles; i++) used |= a->files[i].fid == cf.fid;
		if (!used) break;
	}
	formOpen("DESFire: create file", "Create", cf.type == 5 ? "Transaction MAC: Read = reading TMC / TMV, Read / write = "
		"the CommitReaderID key (never: no reader ID), Write unused." : NULL, cfShown, cfCount, cfRun);
}

// --- delete file ---

static void dfGo(void)
{
	DfApp *a = curApp();
	opReset("Delete file", a->aid);
	if (!(a->keySet & 4) || a->keySt) opAuth(0, &a->keys[0]);
	u8 c[2] = { 0xDF, curFile()->fid };
	opCmd(c, 2, 0, DF_PLAIN, false);
	file_ = fl.sel;
	opRun();
}

static void dfNeed(void)
{
	DfApp *a = curApp();
	if ((a->keySet & 4) && !a->keySt) dfGo();
	else needKey(a->aid, 0, &a->keys[0], appType(a), dfGo);
}

static void deleteFile(void)
{
	DfFile *f = curFile();
	if (!f) {
		msgBox("Delete file", "No file selected.");
		return;
	}
	confirm("Delete file", dfNeed, "Delete file %02X of application %06lX? This can't be undone.", f->fid, curApp()->aid);
}

// --- write a file ---

static struct {
	int k;   // the key it writes with, 0xE = free
	u8 op;   // value files: 0C credit, DC debit, 1C limited credit
} wr;

static u32 fileSize(const DfFile *f)
{
	return f->len >= 7 ? f->set[4] | f->set[5] << 8 | f->set[6] << 16 : 0;
}

// The key for a write-type access from the candidates (access nibbles): free, then a known one, then
// the first real key (asked for). -1 = never.
static int pickKey(const DfApp *a, const int *cand, int n)
{
	for (int i = 0; i < n; i++)
		if (cand[i] == 0xE) return 0xE;
	for (int i = 0; i < n; i++)
		if (cand[i] < 14 && a->keys[cand[i]].known) return cand[i];
	for (int i = 0; i < n; i++)
		if (cand[i] < 14) return cand[i];
	return -1;
}

// The application's transaction MAC file, NULL = none.
static const DfFile *tmacFile(const DfApp *a)
{
	for (int i = 0; i < a->nfiles && !a->fileSt; i++)
		if (!a->files[i].st && a->files[i].len >= 4 && a->files[i].set[0] == 5) return &a->files[i];
	return NULL;
}

static void wrSend(void)
{
	DfApp *a = curApp();
	DfFile *f = curFile();
	// with a transaction MAC file: the commit returns TMC / TMV, after CommitReaderID if it wants one
	const DfFile *tm = tmacFile(a);
	if (tm && (op.flags & DF_COMMIT)) {
		u8 rid = tm->set[2] >> 4;
		op.flags |= DF_TMAC;
		if (rid != 0xF) {
			if (rid != 0xE && rid != wr.k) {
				msgBox(op.title, "The transaction MAC file %02X wants CommitReaderID with key %X, but this write "
					"goes with %s.", tm->fid, rid, wr.k == 0xE ? "free access" : "another key");
				return;
			}
			op.flags |= DF_READER_ID;
		}
	}
	if (wr.k != 0xE) opAuth(wr.k, &a->keys[wr.k]);
	u8 comm = wr.k == 0xE || (f->set[1] & 3) == 2 ? DF_PLAIN : f->set[1] & 3;
	op.comm = comm;
	file_ = fl.sel;
	opRun();
}

static void wrNeed(void)
{
	DfApp *a = curApp();
	if (wr.k == 0xE) wrSend();
	else needKey(a->aid, wr.k, &a->keys[wr.k], appType(a), wrSend);
}

static void wrData(const u8 *b, u32 len)
{
	DfApp *a = curApp();
	DfFile *f = curFile();
	bool rec = f->set[0] == 3 || f->set[0] == 4;
	opReset(rec ? "Write record" : "Write file", a->aid);
	u8 c[300] = { rec ? 0x3B : 0x3D, f->fid, 0, 0, 0 };
	put24(c + 5, len);
	memcpy(c + 8, b, len);
	opCmd(c, 8 + len, 7, DF_PLAIN, f->set[0] != 0);
	wrNeed();
}

static void wrAmount(s64 v)
{
	DfApp *a = curApp();
	DfFile *f = curFile();
	opReset(wr.op == 0x0C ? "Credit" : wr.op == 0xDC ? "Debit" : "Limited credit", a->aid);
	u8 c[6] = { wr.op, f->fid };
	put32le(c + 2, v);
	opCmd(c, 6, 1, DF_PLAIN, DF_COMMIT);
	wrNeed();
}

static void wrValue(u8 cmd, const char *what)
{
	DfApp *a = curApp();
	DfFile *f = curFile();
	u8 r = f->set[3] >> 4, w = f->set[3] & 0xF, rw = f->set[2] >> 4;
	// credit: read/write; debit: read, write or read/write; limited credit: write or read/write
	int cand[3], n = 0;
	if (cmd == 0x0C) cand[n++] = rw;
	else if (cmd == 0xDC) cand[n++] = r, cand[n++] = w, cand[n++] = rw;
	else cand[n++] = w, cand[n++] = rw;
	if ((wr.k = pickKey(a, cand, n)) < 0) {
		msgBox(what, "This file's access rights allow no %s.", what);
		return;
	}
	wr.op = cmd;
	char t[48], d[96];
	snprintf(t, sizeof(t), "%s %06lX file %02X", what, a->aid, f->fid);
	snprintf(d, sizeof(d), "Amount (%s with %s).", what, wr.k == 0xE ? "free access" : "the file's key");
	entryDec(t, d, 0, 0x7FFFFFFF, 0, wrAmount);
}

static void wrCredit(void) { wrValue(0x0C, "Credit"); }
static void wrDebit(void) { wrValue(0xDC, "Debit"); }
static void wrLimited(void) { wrValue(0x1C, "Limited credit"); }

static void writeFile(void)
{
	DfApp *a = curApp();
	DfFile *f = curFile();
	if (!f || f->st || f->len < 7) {
		msgBox("Write", f ? "This file's settings didn't read." : "No file selected.");
		return;
	}
	if (f->set[0] == 5) {
		msgBox("Write", "A transaction MAC file isn't written: the card updates it on every committed transaction "
			"(TMC, TMV).");
		return;
	}
	if (f->set[0] == 2) {
		static const MenuItem items[] = { { "Credit", wrCredit }, { "Debit", wrDebit }, { "Limited credit", wrLimited } };
		popup("Value file", items, 3);
		return;
	}
	int cand[2] = { f->set[3] & 0xF, f->set[2] >> 4 };
	if ((wr.k = pickKey(a, cand, 2)) < 0) {
		msgBox("Write", "This file can never be written.");
		return;
	}
	bool rec = f->set[0] == 3 || f->set[0] == 4;
	u32 len = rec ? (f->len >= 13 ? f->set[4] | f->set[5] << 8 | f->set[6] << 16 : 0) : fileSize(f);
	if (!len) return;
	char t[48], w[160];
	if (len > ENTRY_MAX) len = ENTRY_MAX;
	snprintf(t, sizeof(t), "%s %06lX file %02X", rec ? "Add a record to" : "Write", a->aid, f->fid);
	snprintf(w, sizeof(w), "%s (%lu bytes%s), sent %s.", rec ? "The new record" : fileSize(f) > len ? "The file's start" : "The file's contents",
		len, rec ? "" : ", from offset 0", wr.k == 0xE ? "with free access" : "with the file's key");
	const u8 *init = f->hasData && !f->dataSt && !rec && f->dataLen >= len ? di.pool + f->dataOff : NULL;
	entryHex(t, w, len, init, wrData);
}

// --- keys: enter one, change one ---

static int keyNo;
static DfKey newKey;
static u8 newVer;
static char verText[24];

static void enterDone(void)
{
	DfApp *a = curApp();
	bool picc = need.slot == &di.piccKey;
	opReset(picc ? "PICC master key" : "Key check", picc ? 0 : a->aid);
	opAuth(picc ? 0 : keyNo, need.slot);
	opRun();
}

static void enterPicc(void)
{
	askKey(&di.piccKey, piccType(), "PICC master key", "The PICC master key, checked on the card", enterDone);
}

static void enterAppKeyNo(s64 v)
{
	DfApp *a = curApp();
	keyNo = v;
	char t[48], w[96];
	snprintf(t, sizeof(t), "%06lX key %d", a->aid, keyNo);
	snprintf(w, sizeof(w), "Key %d of application %06lX, checked on the card", keyNo, a->aid);
	askKey(&a->keys[keyNo], appType(a), t, w, enterDone);
}

static void enterAppKey(void)
{
	DfApp *a = curApp();
	int n = a->keySt ? 14 : a->maxKeys & 0xF;
	entryDec("Key number", "Which key of the application to enter.", 0, n - 1, 0, enterAppKeyNo);
}

// changing: the new key into newKey (askKey on a scratch slot), then the key that authorizes it
static void ckGo(void)
{
	DfApp *a = curApp();
	bool picc = keyNo < 0;
	opReset(picc ? "Change PICC master key" : "Change key", picc ? 0 : a->aid);
	op.change = true, op.nkey = newKey, op.ver = newVer;
	if (picc) {
		op.picc = true, op.nk = 0;
		opAuth(0, &di.piccKey);
	} else {
		u8 ck = a->keySet >> 4;
		op.nk = keyNo;
		int by = keyNo == 0 || ck == 0xE ? keyNo : ck;
		opAuth(by, &a->keys[by]);
		if (by != keyNo) op.old = a->keys[keyNo];
	}
	opRun();
}

static void ckNeedOld(void)
{
	DfApp *a = curApp();
	u8 ck = a->keySet >> 4;
	int by = keyNo == 0 || ck == 0xE ? keyNo : ck;
	if (by != keyNo) needKey(a->aid, keyNo, &a->keys[keyNo], appType(a), ckGo); // the old key goes in the cryptogram
	else ckGo();
}

static void ckNeedAuth(void)
{
	DfApp *a = curApp();
	if (keyNo < 0) {
		needKey(0, 0, &di.piccKey, piccType(), ckGo);
		return;
	}
	u8 ck = a->keySet >> 4;
	int by = keyNo == 0 || ck == 0xE ? keyNo : ck;
	needKey(a->aid, by, &a->keys[by], appType(a), ckNeedOld);
}

static void ckConfirm(void)
{
	char hex[49];
	dfKeyHex(&newKey, hex);
	if (keyNo < 0)
		confirm("Change PICC master key", ckNeedAuth, "The PICC master key becomes %s %s. It goes into the "
			"dictionary; without it the card can't be formatted again.", dfKeyName(&newKey), hex);
	else
		confirm("Change key", ckNeedAuth, "Key %d of %06lX becomes %s %s%s.", keyNo, curApp()->aid, dfKeyName(&newKey), hex,
			newKey.type == DF_AES ? (snprintf(verText, sizeof(verText), ", version %02X", newVer), verText) : "");
}

static void ckVer(s64 v)
{
	newVer = v;
	ckConfirm();
}

// AES keys carry a version (DES ones in their bytes' low bits): asked for, the current one + 1 offered.
static void ckAsk(void)
{
	newVer = 0;
	if (newKey.type != DF_AES) {
		ckConfirm();
		return;
	}
	const DfApp *a = curApp();
	int cur = keyNo < 0 ? (di.keyVerSt ? -1 : di.keyVer) : keyNo < a->nKeyVer ? a->keyVer[keyNo] : -1;
	entryDec("Key version", "The new key's version (0-255), read back with GetKeyVersion.", 0, 255, (cur + 1) & 0xFF, ckVer);
}

static void changeAppKeyNo(s64 v)
{
	DfApp *a = curApp();
	u8 ck = a->keySet >> 4;
	keyNo = v;
	if (keyNo != 0 && ck == 0xF) {
		msgBox("Change key", "This application's keys are frozen: only the master key (0) changes, itself.");
		return;
	}
	char t[48];
	snprintf(t, sizeof(t), "New %06lX key %d", a->aid, keyNo);
	askKey(&newKey, appType(a), t, "The new key", ckAsk);
}

static void changeAppKey(void)
{
	DfApp *a = curApp();
	if (a->keySt) {
		msgBox("Change key", "The key settings didn't read: scan with keys (or enter the master key) first.");
		return;
	}
	if (!(a->keySet & 1) && (a->keySet >> 4) == 0xF) {
		msgBox("Change key", "This application's keys can't be changed (master key frozen, keys frozen).");
		return;
	}
	entryDec("Key number", "Which key to change.", 0, (a->maxKeys & 0xF) - 1, 0, changeAppKeyNo);
}

static void changePicc(void)
{
	if (!di.keySt && !(di.keySet & 1)) {
		msgBox("Change PICC master key", "The PICC master key is frozen.");
		return;
	}
	keyNo = -1;
	askKey(&newKey, -1, "New PICC master key", "The new PICC master key", ckAsk);
}

// --- key settings (ChangeKeySettings, encrypted, with the master key) ---

static u8 ksNew;
static bool ksPicc;

static void ksGo(void)
{
	DfApp *a = curApp();
	opReset(ksPicc ? "PICC key settings" : "Key settings", ksPicc ? 0 : a->aid);
	opAuth(0, ksPicc ? &di.piccKey : &a->keys[0]);
	u8 c[2] = { 0x54, ksNew };
	opCmd(c, 2, 0, DF_FULL, false);
	opRun();
}

static void ksNeed(void)
{
	DfApp *a = curApp();
	if (ksPicc) needKey(0, 0, &di.piccKey, piccType(), ksGo);
	else needKey(a->aid, 0, &a->keys[0], appType(a), ksGo);
}

static void ksSet(const u8 *b, u32 len)
{
	ksNew = b[0];
	char warn[160] = "";
	if (!(ksNew & 8)) strcat(warn, "\nBit 3 clear: these settings can never change again.");
	if (!(ksNew & 1)) strcat(warn, ksPicc ? "\nBit 0 clear: the PICC master key is frozen." : "\nBit 0 clear: the master key is frozen.");
	if (!ksPicc && (ksNew >> 4) == 0xF) strcat(warn, "\nBits 4-7 F: the other keys are frozen.");
	confirm(ksPicc ? "PICC key settings" : "Key settings", ksNeed, "Key settings become %02X.%s", ksNew, warn);
}

static void keySettings(bool picc)
{
	DfApp *a = curApp();
	ksPicc = picc;
	u8 cur = picc ? di.keySet : a->keySet;
	if ((picc ? di.keySt : a->keySt) == 0 && !(cur & 8)) {
		msgBox("Key settings", "These key settings are frozen (bit 3 clear).");
		return;
	}
	entryHex(picc ? "PICC key settings" : "Application key settings", picc
		? "Bit 0: PICC master key changeable, 1: application list free, 2: create application free, 3: settings "
		  "changeable. 0F = all open."
		: "Bit 0: master key changeable, 1: file list free, 2: create / delete free, 3: settings changeable; bits "
		  "4-7: the key that changes keys (E: the key itself, F: frozen).", 1, &cur, ksSet);
}

static void appKeySettings(void) { keySettings(false); }
static void piccKeySettings(void) { keySettings(true); }

// --- ISO 7816: the application's EFs by SELECT and READ BINARY / READ RECORD ---

static DfIsoEf isoEfs[DF_MAX_FILES];
static int isoN;
static char isoWhy[80];
static UiList il;

static void runIso(void)
{
	isoN = 0;
	*isoWhy = 0;
	if (!cardWait()) return;
	if (!dfRandomUid(&sc) && (card.uidLen != sc.uidLen || memcmp(card.uid, sc.uid, sc.uidLen))) {
		snprintf(isoWhy, sizeof(isoWhy), "Not the card that was scanned (another UID).");
		return;
	}
	u32 keep = di.poolUsed; // the EFs' data goes after the scan's, dropped again next time
	isoN = dfIsoRead(&di, curApp(), isoEfs, DF_MAX_FILES);
	snprintf(isoWhy, sizeof(isoWhy), "%s", dfWhy());
	if (isoN <= 0) di.poolUsed = keep;
	iso14aParity(true);
}

static const char *swName(u16 sw)
{
	switch (sw) {
	case 0x9000: return "ok";
	case 0x6700: return "wrong length";
	case 0x6981: return "not a binary file";
	case 0x6982: return "security status not satisfied";
	case 0x6985: return "conditions not satisfied";
	case 0x6A82: return "file not found";
	case 0x6A83: return "record not found";
	case 0x6A86: return "wrong P1 / P2";
	}
	return "error";
}

#define ISO_ROWS 9

static void isoDraw(void)
{
	const DfApp *a = curApp();
	char t[48], s[96];
	snprintf(t, sizeof(t), "DESFire: %06lX over ISO 7816", a->aid);
	uiHeader(t, NULL);
	if (a->nameLen) {
		strcpy(s, "SELECT by DF name ");
		hexStr(s + strlen(s), a->name, a->nameLen);
	} else {
		snprintf(s, sizeof(s), "SELECT by ISO FID %04X", a->isoFid);
	}
	uiText(12, 26, S_SMALL, uiCol[COL_DIM], "%s, then READ BINARY / RECORD", s);
	float y = 26 + SMALL_H + 4;
	for (int i = il.top; i < isoN && i < il.top + ISO_ROWS; i++, y += LINE_H) {
		const DfIsoEf *e = &isoEfs[i];
		if (i == il.sel) uiSel(8, y - 1, UI_W - 16, LINE_H);
		uiText(14, y, S_BODY, uiCol[COL_ACCENT], "EF %04X", e->fid);
		if (e->sw == 0x9000 && e->records)
			snprintf(s, sizeof(s), "records: %d, %d bytes", e->records_n, e->dataLen);
		else if (e->sw == 0x9000)
			snprintf(s, sizeof(s), "binary: %d bytes", e->dataLen);
		else
			snprintf(s, sizeof(s), "SW %04X %s", e->sw, swName(e->sw));
		uiText(90, y + 1, S_SMALL, uiCol[e->sw == 0x9000 ? COL_TEXT : COL_WARN], "%s", s);
	}
	uiFooter(BTN_UD " EF   " BTN_A " contents   " BTN_B " back");
}

static DfFile isoFile; // the data viewer's stand-in

static void isoInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&il, isoN, ISO_ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	if ((kDown & KEY_A) && isoN && isoEfs[il.sel].sw == 0x9000) {
		const DfIsoEf *e = &isoEfs[il.sel];
		memset(&isoFile, 0, sizeof(isoFile));
		isoFile.hasData = true, isoFile.dataOff = e->dataOff, isoFile.dataLen = e->dataLen, isoFile.dataKey = 0xE;
		showData(&isoFile);
		dataIsoFid = e->fid;
	}
	if (kDown & KEY_B) appBack();
}

static const Screen isoScreen = { NULL, isoInput, isoDraw };

static void doneIso(void)
{
	if (isoN < 0) msgBox("ISO 7816", "The chip stopped answering.\nTry again.");
	else if (!isoN && !mfCancel) msgBox("ISO 7816", "%s", *isoWhy ? isoWhy : "no card");
	else if (isoN > 0) {
		il = (UiList){ 0 };
		appScreen(&isoScreen);
	}
}

static void isoRead(void)
{
	const DfApp *a = curApp();
	if (!a->hasIso) {
		msgBox("ISO 7816", "This application has no ISO IDs (no ISO FID / DF name): only native commands reach it.");
		return;
	}
	jobStart("Reading over ISO 7816", runIso, doneIso, true);
}

// --- SetConfiguration (5C, encrypted, PICC master key) ---

static u8 cfgData[24], cfgLen;
static const char *cfgTitle;

static void cfgGo(void)
{
	opReset(cfgTitle, 0);
	opAuth(0, &di.piccKey);
	u8 c[26] = { 0x5C };
	memcpy(c + 1, cfgData, cfgLen);
	opCmd(c, 1 + cfgLen, 1, cfgData[0] == 0x02 ? DF_FULL80 : DF_FULL, 0); // the ATS: 80-padded (pm3)
	opRun();
}

static void cfgNeed(void)
{
	needKey(0, 0, &di.piccKey, piccType(), cfgGo);
}

static u8 atsNew[20], atsLen;

static void atsSet(const u8 *b, u32 len)
{
	memcpy(atsNew, b, len);
	atsNew[0] = len; // TL: the ATS's own length
	cfgData[0] = 0x02, cfgLen = 1 + len, cfgTitle = "Set ATS";
	memcpy(cfgData + 1, atsNew, len);
	char hex[48];
	hexStr(hex, atsNew, len);
	confirm("Set ATS", cfgNeed, "The card's ATS becomes %s. A broken one can stop ISO14443-4 (and so this app) from "
		"reaching the card: keep T0 / TA / TB / TC as they are.", hex);
}

static void atsLenSet(s64 v)
{
	atsLen = v;
	u8 init[20] = { 0 };
	memcpy(init, di.ats, di.atsLen < v ? di.atsLen : v);
	entryHex("ATS", "The new ATS (its first byte, the length, is set for you). This card's: T0 75, TA 77, TB 81, TC 02, "
		"then historical bytes.", v, init, atsSet);
}

static void cfgAts(void)
{
	entryDec("ATS length", "Bytes in the new ATS, its length byte included (6 = no change in size).", 5, 20, di.atsLen, atsLenSet);
}

static void cfgAtsDefault(void)
{
	static const u8 def[6] = { 0x06, 0x75, 0x77, 0x81, 0x02, 0x80 };
	cfgData[0] = 0x02, cfgLen = 7, cfgTitle = "Set ATS";
	memcpy(cfgData + 1, def, 6);
	confirm("Set ATS", cfgNeed, "Back to the DESFire EV2 / EV3 ATS 067577810280?");
}

static void randomGo2(void)
{
	confirm("Random UID", cfgNeed, "Last chance: turn on random ID for good?");
}

static void cfgRandom(void)
{
	if (di.randomUid) {
		msgBox("Random UID", "Random ID is on already.");
		return;
	}
	cfgData[0] = 0x00, cfgData[1] = 0x02, cfgLen = 2, cfgTitle = "Random UID";
	confirm("Random UID", randomGo2, "Turn on random ID? The card then shows a new random UID on every activation; the "
		"real one only comes with a key (GetCardUID). This can NEVER be turned off again.");
}

static void formatGo2(void)
{
	confirm("Disable format", cfgNeed, "Last chance: disable formatting for good?");
}

static void cfgNoFormat(void)
{
	cfgData[0] = 0x00, cfgData[1] = 0x01 | (di.randomUid ? 0x02 : 0), cfgLen = 2, cfgTitle = "Disable format";
	confirm("Disable format", formatGo2, "Disable FormatPICC? Applications can still be deleted, but their memory "
		"never comes back. This can NEVER be turned on again.");
}

static void configuration(void)
{
	static const MenuItem items[] = {
		{ "Custom ATS", cfgAts }, { "Default ATS", cfgAtsDefault }, { "Random UID (permanent)", cfgRandom },
		{ "Disable format (permanent)", cfgNoFormat },
	};
	popup("Configuration", items, 4);
}

// --- the menus ---

static void cardMenu(void)
{
	static const MenuItem items[] = {
		{ "Save info", save }, { "Create application", createApp }, { "Enter PICC master key", enterPicc },
		{ "Change PICC master key", changePicc }, { "PICC key settings", piccKeySettings }, { "Format card", format },
		{ "Configuration", configuration },
	};
	popup("Card", items, 7);
}

static void appMenu(void)
{
	static const MenuItem items[] = {
		{ "Write file", writeFile }, { "Create file", createFile }, { "Delete file", deleteFile },
		{ "Enter a key", enterAppKey }, { "Change a key", changeAppKey }, { "Key settings", appKeySettings },
		{ "ISO 7816 read", isoRead }, { "Delete application", deleteApp }, { "Save info", save },
	};
	popup("Application", items, 9);
}

// --- saved info files (Save info on the card screen): emulate ---

static DfInfo ld; // the file picked (dfLoadInfo)

// applications + 1, 0: not an info file (keys.txt, ...)
static int infoApps(const char *path, u32 size)
{
	(void)size;
	return dfLoadInfo(&ld, path) ? ld.napps + 1 : 0;
}

static DumpDir infos = { .dir = DF_DIR, .ext = ".txt", .info = infoApps };
static UiList fl;

static void filesScan(void)
{
	dumpScan(&infos);
	if (fl.sel >= infos.n) fl.sel = infos.n ? infos.n - 1 : 0;
}

void dfFilesChanged(void)
{
	filesScan();
}

static void filePath(char *out, u32 max)
{
	snprintf(out, max, DF_DIR "/%s", infos.ent[fl.sel].name);
}

static void actEmu(void)
{
	char name[64];
	snprintf(name, sizeof(name), "%s", infos.ent[fl.sel].name);
	emuStartDf(&ld, name);
}

static void fileDelete(void)
{
	char path[128];
	filePath(path, sizeof(path));
	remove(path);
	toast("Deleted %s", infos.ent[fl.sel].name);
	filesScan();
}

static void filesInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&fl, infos.n, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!infos.n) return;
	if (kDown & (KEY_A | KEY_X)) {
		char path[128];
		filePath(path, sizeof(path));
		if (!dfLoadInfo(&ld, path)) {
			msgBox("Saved cards", "%s is not a DESFire info file.", infos.ent[fl.sel].name);
			return;
		}
		static const MenuItem items[] = { { "Emulate this card", actEmu } };
		popup(infos.ent[fl.sel].name, items, 1);
	}
	if (kDown & KEY_Y) confirm("Delete", fileDelete, "Delete %s?", infos.ent[fl.sel].name);
}

static void filesDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%d file%s", infos.n, infos.n == 1 ? "" : "s");
	uiHeader("Saved DESFire cards", hdr);
	if (!infos.n) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No info files yet.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Scan a card, then " BTN_Y " on the card screen");
		uiFooter(BTN_B " back");
		return;
	}
	for (int i = 0; i < 12 && fl.top + i < infos.n; i++) {
		const DumpEnt *f = &infos.ent[fl.top + i];
		float y = 24 + i * LINE_H;
		if (fl.top + i == fl.sel) uiSel(4, y - 1, UI_W - 8, LINE_H);
		char name[64];
		snprintf(name, sizeof(name), "%s", f->name);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(name, 190, S_BODY));
		uiTextRight(268, y + 1, S_SMALL, uiCol[f->info ? COL_ACCENT : COL_ERR], f->info ? "%d app%s" : "not info",
			f->info - 1, f->info == 2 ? "" : "s");
		if (f->mtime > 1) {
			time_t t = f->mtime;
			struct tm *tm = gmtime(&t);
			uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%04d-%02d-%02d %02d:%02d", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);
		}
	}
	if (infos.n > 12) uiTextRight(UI_W - 6, UI_H - 34, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", fl.top + 1,
		fl.top + 12 < infos.n ? fl.top + 12 : infos.n, infos.n);
	uiFooter(BTN_A "/" BTN_X " actions   " BTN_Y " delete   " BTN_B " back");
}

static const Screen filesScreen = { filesScan, filesInput, filesDraw };

static void openFiles(void)
{
	appScreen(&filesScreen);
}

// --- menu and family ---

static void startDownload(void)
{
	pm3DictDownload("Downloading pm3's DESFire keys", "mfdes_default_keys.dic", DF_PM3_KEYS,
		1ull << 16 | 1ull << 32 | 1ull << 48, NULL);
}

static const MenuEntry dfEntries[] = {
	{ "Scan card", "Everything a DESFire tells without a key: version, storage, free memory, originality "
	               "signature, PICC and application key settings, applications and their files. Any other "
	               "ISO14443-4 card shows its ATS.", startScan },
	{ "Scan with keys", "The same, then the key dictionary (built in, " DF_KEYS ", pm3's if downloaded) on the PICC master key and "
	                    "every application key (DES, 2K3DES, 3K3DES, AES; AES over EV2 on EV2 / EV3 cards, D40 on MF3ICD40). Found "
	                    "keys open protected lists and files, in plain, MAC and full (encrypted) mode.", startKeyScan },
	{ "Saved cards", "Info files saved from the card screen (" BTN_Y "): emulate one, the 3DS answering as that card "
	                 "with what the file holds (and its keys).", openFiles },
	{ "Download keys", "Fetch pm3's mfdes_default_keys.dic (~60 keys, over Wi-Fi) to " DF_DIR ": Scan with keys "
	                   "tries them after the built-in ones and keys.txt.", startDownload },
};

static void dfExtra(float x, float y, float w)
{
	uiText(x, y, S_SMALL, uiCol[COL_DIM], "Info files: " DF_DIR " (" BTN_Y " on the card screen)");
	if (sc.uidLen) menuLastCard(x, y + SMALL_H, w, &sc, diResult > 0 ? dfVersionName(&di) : cardTypeName(&sc));
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
