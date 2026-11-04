// GlobalPlatform tool (gp.h): the security domain's card data, the keys (found offline: a wrong one is
// never sent), the applets and packages on the card; delete them, install CAP files from the SD card.

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "gp.h"
#include "probe.h"
#include "scard.h"
#include "ui.h"

static GpCard gc;
static int gcResult;      // gpOpen
static char gcWhy[96];
static GpKeys keys;       // the ones that worked (or were entered)
static bool keysOk;       // the card took them
static bool keysEntered;  // try keys first
static int keysTried;     // how many the last open checked
static Card gcCard;
static UiList el;

static const Screen gpScreen;

// --- the operations: open, authenticate (when the keys are known), the op, list again ---

enum { OP_LIST, OP_DELETE, OP_INSTALL };
static int op, opResult;
static u8 opAid[16], opAidLen;
static bool opRelated;
static GpCap cap;
static char opWhy[96];

// The ISD, its data, keys that check out offline (entered ones, the default, GP_KEYS), and with them the
// secure channel. 1 = authenticated, 0 = keys unknown / refused (gcWhy), -1 = monitor.
static int openAuth(void)
{
	gcResult = gpOpen(&gc);
	gcCard = card;
	if (gcResult <= 0) {
		snprintf(gcWhy, sizeof(gcWhy), "%s", gpWhy());
		return gcResult;
	}
	static GpKeys list[64];
	int n = 0;
	if (keysEntered || keysOk) list[n++] = keys;
	n += gpKeyList(list + n, 64 - n);
	keysOk = false;
	keysTried = 0;
	for (int i = 0; i < n && !mfCancel; i++) {
		if (i && !memcmp(&list[i], &list[0], sizeof(GpKeys))) continue;
		progOp("Checking key %d of %d", i + 1, n);
		keysTried++;
		int r = gpCheck(&gc, &list[i]);
		if (r < 0) return -1;
		if (!r && gc.scp && gc.scp != 3) break; // not SCP03: no key will do
		if (!r && !strstr(gpWhy(), "cryptogram")) break; // refused INITIALIZE UPDATE
		if (!r) continue;
		keys = list[i];
		keysOk = true;
		break;
	}
	if (!keysOk) {
		snprintf(gcWhy, sizeof(gcWhy), "%s", keysTried ? gpWhy() : "cancelled");
		if (strstr(gcWhy, "cryptogram")) snprintf(gcWhy, sizeof(gcWhy), "None of %d known keys fits (none was sent).", keysTried);
		return 0;
	}
	progOp("Authenticating");
	int r = gpAuth(&gc, &keys);
	if (r <= 0) {
		keysOk = false;
		snprintf(gcWhy, sizeof(gcWhy), "%s", gpWhy());
		return r;
	}
	if (memcmp(&keys, &gpDefaultKeys, sizeof(keys))) gpRememberKey(&keys);
	return 1;
}

static void runOp(void)
{
	opResult = 0;
	*opWhy = 0;
	gcResult = 0, *gcWhy = 0;
	if (!cardWait()) return;
	int r = openAuth();
	if (r <= 0) {
		opResult = r;
		snprintf(opWhy, sizeof(opWhy), "%s", gcWhy);
		iso14aParity(true);
		return;
	}
	u16 sw;
	if (op == OP_DELETE) {
		progOp("DELETE");
		r = gpDelete(opAid, opAidLen, opRelated, &sw);
	} else if (op == OP_INSTALL) {
		// the package again: out with the old one (and its applets) first
		progOp("Listing");
		r = gpList(&gc);
		for (int i = 0; r > 0 && i < gc.nent; i++)
			if (gc.ent[i].kind == GP_PKG && gc.ent[i].aidLen == cap.pkgLen && !memcmp(gc.ent[i].aid, cap.pkg, cap.pkgLen)) {
				progOp("Deleting the old package");
				r = gpDelete(cap.pkg, cap.pkgLen, true, &sw);
			}
		if (r > 0) r = gpInstall(&cap);
	}
	if (r <= 0) snprintf(opWhy, sizeof(opWhy), "%s", gpWhy());
	opResult = r;
	if (r >= 0) {
		progOp("Listing");
		if (gpList(&gc) <= 0 && r > 0) snprintf(opWhy, sizeof(opWhy), "listing: %s", gpWhy());
	}
	iso14aParity(true);
}

static void doneOp(void)
{
	if (op == OP_INSTALL) gpCapFree(&cap);
	if (opResult < 0) {
		msgBox("GlobalPlatform", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!gcResult) {
		if (!mfCancel && *gcWhy) msgBox("GlobalPlatform", "No security domain:\n%s", gcWhy);
		return;
	}
	if (appTop() != &gpScreen) {
		el = (UiList){ 0 };
		appScreen(&gpScreen);
	}
	if (el.sel >= gc.nent) el = (UiList){ 0 };
	if (op == OP_LIST && !keysOk && !mfCancel)
		msgBox("GlobalPlatform", "%s\nThe card data is shown; the applet list needs the keys (" BTN_Y " enter keys). "
			"A key is only used once the card's cryptogram proves it right, so trying costs nothing.", gcWhy);
	else if (op != OP_LIST && opResult == 0)
		msgBox(op == OP_DELETE ? "Delete" : "Install", "%s", opWhy);
	else if (op == OP_DELETE)
		toast("Deleted");
	else if (op == OP_INSTALL)
		toast("Installed%s", *opWhy ? opWhy : "");
}

static void startOp(int o, const char *title)
{
	op = o;
	jobStart(title, runOp, doneOp, true);
}

void gpOpenTool(void)
{
	startOp(OP_LIST, "GlobalPlatform");
}

// --- the screen ---

#define ROWS 8

static const char *kindName(const GpEntry *e)
{
	return e->kind == GP_ISD ? "ISD" : e->kind == GP_PKG ? "package" : e->priv & 0x80 ? "domain" : "applet";
}

static void gpDraw(void)
{
	char s[300], aid[40];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	gpAidHex(aid, gc.isd, gc.isdLen);
	uiHeader("GlobalPlatform", aid);
	float y = 26;
	gpCrdDesc(&gc, s, sizeof(s));
	uiText(12, y, S_BODY, txt, "%s", uiFit(s, UI_W - 24, S_BODY));
	y += LINE_H + 2;
	gpCplcDesc(&gc, s, sizeof(s));
	char *nl = strchr(s, '\n');
	if (nl) *nl = 0;
	uiText(12, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 24, S_SMALL));
	if (nl) uiText(12, y + SMALL_H, S_SMALL, txt, "%s", uiFit(nl + 1, UI_W - 24, S_SMALL));
	y += 2 * SMALL_H;
	if (keysOk) {
		char k[40];
		bool def = !memcmp(&keys, &gpDefaultKeys, sizeof(keys));
		bool same = !memcmp(keys.enc, keys.mac, 16) && !memcmp(keys.enc, keys.dek, 16);
		scHex(k, keys.enc, 16);
		snprintf(s, sizeof(s), "Keys: %s%s, version %02X, SCP%02X i=%02X", def ? "default 404142..4F" : k,
			same || def ? "" : " (+ MAC, DEK)", gc.kvn, gc.scp, gc.scpI);
		uiText(12, y, S_SMALL, uiCol[COL_OK], "%s", uiFit(s, UI_W - 24, S_SMALL));
	} else {
		snprintf(s, sizeof(s), "Keys unknown: %s", gcWhy);
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "%s", uiFit(s, UI_W - 24, S_SMALL));
	}
	y += SMALL_H + 4;
	if (!gc.listed) {
		uiRect(8, y, UI_W - 16, 3 * SMALL_H + 6, uiCol[COL_PANEL]);
		uiTextWrap(14, y + 3, UI_W - 28, S_SMALL, dim, "The applets, security domains and packages on the card show "
			"once the keys are known (" BTN_Y " enter keys, then " BTN_X " to try them).");
		uiFooter(BTN_X " try again   " BTN_Y " keys / install   " BTN_B " back");
		return;
	}
	int n = gc.nent;
	if (gc.hasSeq) uiText(12, y, S_SMALL, dim, "%d entr%s, sequence counter %lu", n, n == 1 ? "y" : "ies", gc.seq);
	else uiText(12, y, S_SMALL, dim, "%d entr%s", n, n == 1 ? "y" : "ies");
	if (n > ROWS) uiTextRight(UI_W - 12, y, S_SMALL, dim, "%d-%d of %d", el.top + 1, el.top + ROWS < n ? el.top + ROWS : n, n);
	y += SMALL_H + 1;
	for (int i = 0; i < ROWS && el.top + i < n; i++, y += LINE_H) {
		const GpEntry *e = &gc.ent[el.top + i];
		if (el.top + i == el.sel) uiSel(8, y - 1, UI_W - 16, LINE_H);
		uiText(14, y + 1, S_SMALL, e->kind == GP_PKG ? dim : uiCol[COL_ACCENT], "%s", kindName(e));
		gpAidHex(aid, e->aid, e->aidLen);
		uiMonoS(66, y + 2, 0.34f, 5.6f, txt, aid);
		const ScApplet *a = scAppletFor(e->aid, e->aidLen);
		const char *st = gpStateName(e->kind, e->state);
		if (a && e->kind != GP_PKG) snprintf(s, sizeof(s), "%s, %s", a->name, st);
		else if (e->kind == GP_PKG && e->nmods) snprintf(s, sizeof(s), "%d applet class%s, %s", e->nmods, e->nmods == 1 ? "" : "es", st);
		else snprintf(s, sizeof(s), "%s", st);
		uiTextRight(UI_W - 14, y + 1, S_SMALL, e->state == 0x83 || (e->state & 0x80 && e->kind == GP_APP) ? uiCol[COL_WARN] : dim,
			"%s", uiFit(s, UI_W - 14 - 66 - 5.6f * e->aidLen * 2 - 10, S_SMALL));
	}
	uiFooter(n ? BTN_A " actions   " BTN_X " refresh   " BTN_Y " keys / install   " BTN_B " back"
	           : BTN_X " refresh   " BTN_Y " keys / install   " BTN_B " back");
}

// --- delete ---

static void delGo(void)
{
	startOp(OP_DELETE, "Deleting");
}

static void delAsk(void)
{
	const GpEntry *e = &gc.ent[el.sel];
	char aid[40];
	gpAidHex(aid, e->aid, e->aidLen);
	memcpy(opAid, e->aid, e->aidLen), opAidLen = e->aidLen;
	opRelated = e->kind == GP_PKG;
	if (e->kind == GP_ISD) {
		msgBox("Delete", "The issuer security domain can't be deleted.");
		return;
	}
	int inst = 0;
	for (int i = 0; i < gc.nent; i++)
		if (gc.ent[i].kind == GP_APP && gc.ent[i].pkgLen == e->aidLen && !memcmp(gc.ent[i].pkg, e->aid, e->aidLen)) inst++;
	if (e->kind == GP_PKG)
		confirm("Delete package", delGo, "Delete package %s%s? Its code is gone from the card (install the CAP file "
			"again to get it back).", aid, inst ? " and its applets" : "");
	else
		confirm("Delete applet", delGo, "Delete %s %s? Whatever it stored (keys, accounts, PINs) is gone for good; "
			"its package stays.", kindName(e), aid);
}

static void details(void)
{
	const GpEntry *e = &gc.ent[el.sel];
	char aid[40], s[400] = "", m[40];
	gpAidHex(aid, e->aid, e->aidLen);
	const ScApplet *a = scAppletFor(e->aid, e->aidLen);
	u32 o = 0;
	o += snprintf(s + o, sizeof(s) - o, "AID %s\n%s%s%s", aid, a ? a->name : "", a ? "\n" : "", gpStateName(e->kind, e->state));
	if (e->kind != GP_PKG) o += snprintf(s + o, sizeof(s) - o, ", privileges %02X%s%s", e->priv,
		e->priv & 0x80 ? " (security domain)" : "", e->priv & 0x04 ? " (default selected)" : "");
	if (e->kind == GP_APP && e->pkgLen) gpAidHex(m, e->pkg, e->pkgLen), o += snprintf(s + o, sizeof(s) - o, "\nPackage %s", m);
	if (e->kind == GP_PKG && !e->pkgLen && (e->pkg[0] || e->pkg[1]))
		o += snprintf(s + o, sizeof(s) - o, ", version %d.%d", e->pkg[0], e->pkg[1]);
	for (int i = 0; i < e->nmods; i++) gpAidHex(m, e->mods[i], e->modLen[i]), o += snprintf(s + o, sizeof(s) - o, "\nApplet class %s", m);
	msgBox(kindName(e), "%s", s);
}

static void actions(void)
{
	static const MenuItem items[] = { { "Details", details }, { "Delete", delAsk } };
	popup("Entry", items, 2);
}

// --- keys ---

static void keySet(const u8 *b, u32 len)
{
	memcpy(keys.enc, b, 16), memcpy(keys.mac, b, 16), memcpy(keys.dek, b, 16);
	keysEntered = true, keysOk = false;
	startOp(OP_LIST, "GlobalPlatform");
}

static void keyEnter(void)
{
	entryHex("GlobalPlatform key", "AES-128, used for ENC, MAC and DEK alike (three different keys: one line in "
		GP_KEYS "). Checked against the card's cryptogram before anything is sent.", 16, keys.enc, keySet);
}

static void keyDefault(void)
{
	keys = gpDefaultKeys;
	keysEntered = true, keysOk = false;
	startOp(OP_LIST, "GlobalPlatform");
}

// --- install: CAP files on the SD card ---

typedef struct {
	char name[64];
	u32 size;
} CapEnt;
static CapEnt caps[64];
static int ncaps;
static UiList cl;

static void capsScan(void)
{
	ncaps = 0;
	DIR *dir = opendir(GP_CAPS);
	struct dirent *e;
	while (dir && (e = readdir(dir)) && ncaps < 64) {
		int len = strlen(e->d_name);
		if (len < 5 || len >= 64 || strcasecmp(e->d_name + len - 4, ".cap")) continue;
		char path[128];
		snprintf(path, sizeof(path), GP_CAPS "/%s", e->d_name);
		struct stat st;
		if (stat(path, &st)) continue;
		snprintf(caps[ncaps].name, sizeof(caps[ncaps].name), "%s", e->d_name);
		caps[ncaps++].size = st.st_size;
	}
	if (dir) closedir(dir);
	if (cl.sel >= ncaps) cl = (UiList){ 0 };
}

static void installGo(void)
{
	appBack(); // the file list
	startOp(OP_INSTALL, "Installing");
}

static void capsInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&cl, ncaps, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!(kDown & KEY_A) || !ncaps) return;
	char path[128];
	snprintf(path, sizeof(path), GP_CAPS "/%s", caps[cl.sel].name);
	gpCapFree(&cap);
	if (!gpCapLoad(path, &cap)) {
		msgBox("Install", "%s: %s", caps[cl.sel].name, gpWhy());
		return;
	}
	char pkg[40], apps[200] = "", a[40];
	gpAidHex(pkg, cap.pkg, cap.pkgLen);
	for (int i = 0; i < cap.napplets; i++) gpAidHex(a, cap.apps[i], cap.appLen[i]), sprintf(apps + strlen(apps), "\n  %s", a);
	bool present = false;
	for (int i = 0; i < gc.nent; i++)
		present |= gc.ent[i].kind == GP_PKG && gc.ent[i].aidLen == cap.pkgLen && !memcmp(gc.ent[i].aid, cap.pkg, cap.pkgLen);
	confirm("Install", installGo, "Install %s?\nPackage %s v%d.%d, %lu bytes to load\n%s%s%s", cap.name, pkg, cap.pkgMajor,
		cap.pkgMinor, cap.lfLen, cap.napplets ? "Applets (instance AID = class AID):" : "A library: no applets", apps,
		present ? "\nThe package is on the card already: it goes first, with its applets and their data." : "");
}

static void capsDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%d file%s", ncaps, ncaps == 1 ? "" : "s");
	uiHeader("Install CAP file", hdr);
	if (!ncaps) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No CAP files.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], "Copy .cap files to " GP_CAPS);
		uiFooter(BTN_B " back");
		return;
	}
	for (int i = 0; i < 12 && cl.top + i < ncaps; i++) {
		const CapEnt *f = &caps[cl.top + i];
		float y = 24 + i * LINE_H;
		if (cl.top + i == cl.sel) uiSel(4, y - 1, UI_W - 8, LINE_H);
		char name[64];
		snprintf(name, sizeof(name), "%s", f->name);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(name, 300, S_BODY));
		uiTextRight(UI_W - 10, y + 1, S_SMALL, uiCol[COL_DIM], "%lu bytes", f->size);
	}
	uiFooter(BTN_A " install   " BTN_B " back");
}

static const Screen capsScreen = { capsScan, capsInput, capsDraw };

static void install(void)
{
	if (!keysOk) {
		msgBox("Install", "Installing needs the card's keys first.");
		return;
	}
	appScreen(&capsScreen);
}

static void save(void)
{
	char path[128], uid[32];
	uidHex(&gcCard, uid, "");
	mkdir(APP_DIR, 0777);
	mkdir(GP_DIR, 0777);
	snprintf(path, sizeof(path), GP_DIR "/%s.txt", uid);
	FILE *f = fopen(path, "w");
	if (!f) {
		msgBox("Save", "Could not write to the SD card.");
		return;
	}
	char s[300], aid[40];
	gpAidHex(aid, gc.isd, gc.isdLen);
	fprintf(f, "UID %s, ISD %s\n", uid, aid);
	gpCrdDesc(&gc, s, sizeof(s)), fprintf(f, "%s\n", s);
	gpCplcDesc(&gc, s, sizeof(s)), fprintf(f, "%s\n", s);
	if (keysOk) fprintf(f, "key version %02X, SCP%02X i=%02X\n", gc.kvn, gc.scp, gc.scpI);
	for (int i = 0; i < gc.nent; i++) {
		const GpEntry *e = &gc.ent[i];
		gpAidHex(aid, e->aid, e->aidLen);
		fprintf(f, "%-8s %-32s %s priv %02X", kindName(e), aid, gpStateName(e->kind, e->state), e->priv);
		if (e->pkgLen) gpAidHex(aid, e->pkg, e->pkgLen), fprintf(f, " package %s", aid);
		for (int m = 0; m < e->nmods; m++) gpAidHex(aid, e->mods[m], e->modLen[m]), fprintf(f, " class %s", aid);
		fprintf(f, "\n");
	}
	fclose(f);
	toast("Saved %s", path + strlen(APP_DIR "/"));
}

static void gpMenu(void)
{
	static const MenuItem items[] = {
		{ "Install CAP file", install }, { "Enter key", keyEnter }, { "Default key (404142..4F)", keyDefault },
		{ "Save list", save },
	};
	popup("GlobalPlatform", items, 4);
}

static void gpInput(u32 kDown, u32 kRepeat)
{
	int n = gc.listed ? gc.nent : 0;
	uiListNav(&el, n, ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	if ((kDown & KEY_A) && n) actions();
	if (kDown & KEY_X) startOp(OP_LIST, "GlobalPlatform");
	if (kDown & KEY_Y) gpMenu();
	if (kDown & KEY_B) appBack();
}

static const Screen gpScreen = { NULL, gpInput, gpDraw };
