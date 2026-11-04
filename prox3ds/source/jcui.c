// Java Card applets on the 3DS: the card the VM is (jccard.c) with its applets, installing
// CAP files from the SD card, and emulating it (emuui.c emuStartJc).

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <3ds.h>

#include "app.h"
#include "gp.h"
#include "jccard.h"
#include "scard.h"
#include "ui.h"

static bool restored;
static UiList al; // the applets, then the packages without one (libraries)

static void aidHex(char *o, const u8 *aid, int len)
{
	for (int i = 0; i < len; i++) o += sprintf(o, "%02X", aid[i]);
	*o = 0;
}

static const char *capName(int pkg)
{
	const char *p = jcCard.vm.pkgs[pkg].path, *s = strrchr(p, '/');
	return s ? s + 1 : p;
}

// The packages without applets (libraries) into libs; how many.
static int libraries(int *libs)
{
	int n = 0;
	for (int p = 0; p < jcCard.vm.npkgs; p++) {
		bool has = !jcCard.vm.pkgs[p].path[0];
		for (int i = 0; i < jcCard.napplets; i++) has |= jcCard.applets[i].pkg == p;
		if (!has) libs[n++] = p;
	}
	return n;
}

static int rows(void)
{
	int libs[JC_PKGS];
	return jcCard.napplets + libraries(libs);
}

// The package of list row i.
static int rowPkg(int i)
{
	int libs[JC_PKGS];
	libraries(libs);
	return i < jcCard.napplets ? jcCard.applets[i].pkg : libs[i - jcCard.napplets];
}

// --- CAP files on the SD card ---

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

static void capsInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&cl, ncaps, 12, kRepeat);
	if (kDown & KEY_B) appBack();
	if (!(kDown & KEY_A) || !ncaps) return;
	char path[128];
	snprintf(path, sizeof(path), GP_CAPS "/%s", caps[cl.sel].name);
	int n = jcCard.napplets, p = jcCardInstallCap(path);
	appBack();
	if (p < 0) {
		msgBox("Install", "%s: %s", caps[cl.sel].name, jcCard.vm.why);
		return;
	}
	jcCardSave();
	if (jcCard.napplets == n) toast("%s: library loaded", caps[cl.sel].name);
	else toast("%s: %d applet%s installed", caps[cl.sel].name, jcCard.napplets - n, jcCard.napplets - n == 1 ? "" : "s");
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

// --- the card ---

static void installCap(void)
{
	appScreen(&capsScreen);
}

static void deleteGo(void)
{
	int pkg = rowPkg(al.sel);
	char name[64];
	snprintf(name, sizeof(name), "%s", capName(pkg));
	if (!jcCardDeletePkg(pkg)) {
		msgBox("Delete", "%s can't go: %s.", name, jcCard.vm.why);
		return;
	}
	jcCardSave();
	jcCardRestore(); // drops the package's code and objects for good
	if (al.sel >= rows()) al = (UiList){ 0 };
	toast("Deleted %s", name);
}

static void deletePkg(void)
{
	if (!rows()) return;
	int pkg = rowPkg(al.sel), n = 0;
	for (int i = 0; i < jcCard.napplets; i++) n += jcCard.applets[i].pkg == pkg;
	if (!n) confirm("Delete", deleteGo, "Delete the library %s?", capName(pkg));
	else confirm("Delete", deleteGo, "Delete %s with its %d applet%s and their data?", capName(pkg), n, n == 1 ? "" : "s");
}

static void wipeGo(void)
{
	jcCardInit();
	jcCardSave();
	al = (UiList){ 0 };
	toast("The Java Card is empty");
}

static void wipe(void)
{
	confirm("Wipe", wipeGo, "Delete every package, applet and their data from the 3DS's Java Card?");
}

static const MenuItem actions[] = {
	{ "Install a CAP file", installCap },
	{ "Delete this package", deletePkg },
	{ "Wipe the card", wipe },
};

static void show(void)
{
	if (!restored) {
		restored = true;
		jcCardRestore();
	}
	if (al.sel >= rows()) al = (UiList){ 0 };
}

static void input(u32 kDown, u32 kRepeat)
{
	uiListNav(&al, rows(), 9, kRepeat);
	if (kDown & KEY_B) appBack();
	if (kDown & KEY_X) popup("Java Card", actions, rows() ? 3 : 1);
	if (kDown & KEY_A) {
		if (jcCard.napplets) emuStartJc();
		else installCap();
	}
}

static void draw(void)
{
	char hdr[48];
	int libs[JC_PKGS], nlibs = libraries(libs), n = jcCard.napplets + nlibs;
	int o = snprintf(hdr, sizeof(hdr), "%d applet%s", jcCard.napplets, jcCard.napplets == 1 ? "" : "s");
	if (nlibs) snprintf(hdr + o, sizeof(hdr) - o, ", %d librar%s", nlibs, nlibs == 1 ? "y" : "ies");
	uiHeader("Java Card", hdr);
	u32 dim = uiCol[COL_DIM];
	if (!n) {
		uiTextCenter(UI_W / 2, 90, S_BODY, dim, "No applets installed.");
		uiTextCenter(UI_W / 2, 108, S_SMALL, dim, "A installs a CAP file from " GP_CAPS);
		uiTextCenter(UI_W / 2, 122, S_SMALL, dim, "The 3DS then answers as a card with its applets.");
		uiFooter(BTN_A " install   " BTN_B " back");
		return;
	}
	for (int i = 0; i < 9 && al.top + i < n; i++) {
		float y = 24 + i * (LINE_H + SMALL_H);
		if (al.top + i == al.sel) uiSel(4, y - 1, UI_W - 8, LINE_H + SMALL_H);
		char aid[40], cap[64];
		if (al.top + i >= jcCard.napplets) {
			const JcPkg *p = &jcCard.vm.pkgs[libs[al.top + i - jcCard.napplets]];
			aidHex(aid, p->aid, p->aidLen);
			uiText(10, y, S_BODY, uiCol[COL_TEXT], "Library %u.%u", p->major, p->minor);
			snprintf(cap, sizeof(cap), "%s", capName(libs[al.top + i - jcCard.napplets]));
			uiTextRight(UI_W - 10, y + 1, S_SMALL, dim, "%s", uiFit(cap, 150, S_SMALL));
			uiText(10, y + LINE_H - 2, S_SMALL, dim, "%s", aid);
			continue;
		}
		const JcApplet *a = &jcCard.applets[al.top + i];
		aidHex(aid, a->aid, a->aidLen);
		const ScApplet *k = scAppletFor(a->aid, a->aidLen);
		uiText(10, y, S_BODY, uiCol[COL_TEXT], "%s", k ? k->name : aid);
		snprintf(cap, sizeof(cap), "%s", capName(a->pkg));
		uiTextRight(UI_W - 10, y + 1, S_SMALL, dim, "%s", uiFit(cap, 150, S_SMALL));
		uiText(10, y + LINE_H - 2, S_SMALL, dim, "%s", k ? aid : "");
	}
	uiFooter(BTN_A " emulate   " BTN_X " actions   " BTN_B " back");
}

static const Screen jcScreen = { show, input, draw };

void jcOpen(void)
{
	appScreen(&jcScreen);
}
