// Smart card family (any ISO14443-4 card that isn't a DESFire): the card screen with its ATS, security
// domain data and the applets that answered, each opening its tool (scard.h); an APDU console.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "probe.h"
#include "scard.h"
#include "ui.h"

static Card sc;
static ScInfo si;
static int siResult;
static char siWhy[96];
static UiList al;

static const Screen cardScreen;

static int scProbe(void)
{
	al = (UiList){ 0 };
	siResult = scReadInfo(&si);
	sc = card;
	snprintf(siWhy, sizeof(siWhy), "%s", scInfoWhy());
	if (siResult <= 0) logp("smart card: %s\n", siWhy);
	iso14aParity(true);
	return siResult < 0 ? -1 : siResult;
}

static int scanResult;

static void runScan(void)
{
	scanResult = 0;
	if (cardWait()) scanResult = scProbe();
}

static void scShow(void)
{
	appScreen(&cardScreen);
}

static void doneScan(void)
{
	if (scanResult > 0) scShow();
	else if (scanResult < 0) msgBox("Scan", "The chip stopped answering.\nTry again.");
	else if (!mfCancel) msgBox("Scan", "No ISO14443-4 answer:\n%s", siWhy);
}

static void startScan(void)
{
	jobStart("Scanning", runScan, doneScan, true);
}

static void save(void)
{
	char path[128];
	if (scSaveInfo(&si, &sc, path, sizeof(path))) toast("Saved %s", path + strlen(MF_DIR "/"));
	else msgBox("Save", "Could not write to the SD card.");
}

// --- card screen ---

#define APP_ROWS 5

static void cardDraw(void)
{
	char hdr[48], s[420];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	snprintf(hdr, sizeof(hdr), "ATQA %02X%02X  SAK %02X", sc.atqa[1], sc.atqa[0], sc.sak);
	uiHeader("Smart card", hdr);
	float y = 28;
	uidHex(&sc, s, " ");
	uiText(12, y, S_SMALL, dim, "UID (%d bytes)", sc.uidLen);
	uiText(12, y + 12, 0.8f, uiCol[COL_ACCENT], "%s", s);
	y += 40;
	if (si.hasGp) gpCrdDesc(&si.gp, s, sizeof(s));
	else snprintf(s, sizeof(s), "%s", cardTypeName(&sc));
	uiText(12, y, S_BODY, txt, "%s", uiFit(s, UI_W - 24, S_BODY));
	y += LINE_H + 4;
	uiRect(8, y, UI_W - 16, 4 * SMALL_H + 6, uiCol[COL_PANEL]);
	y += 3;
	strcpy(s, "ATS ");
	scHex(s + 4, si.ats, si.atsLen);
	uiText(14, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
	y += SMALL_H;
	// the ATS in short: frame size, FWT, CID / NAD, historical bytes; then the CPLC
	static const u16 fsc[] = { 16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024, 2048, 4096 };
	u8 t0 = si.atsLen > 1 ? si.ats[1] : 0x02, tb = 0x40, tc = 0x02;
	int i = 2;
	if ((t0 & 0x10) && i < si.atsLen) i++;
	if ((t0 & 0x20) && i < si.atsLen) tb = si.ats[i++];
	if ((t0 & 0x40) && i < si.atsLen) tc = si.ats[i++];
	u32 fwt = 302u << (tb >> 4);
	int hist = si.atsLen > i ? si.atsLen - i : 0;
	snprintf(s, sizeof(s), "Frames up to %d bytes, FWT %lu.%lu ms, CID %s, NAD %s, %d hist. byte%s",
		(t0 & 15) < 13 ? fsc[t0 & 15] : 4096, fwt / 1000, fwt % 1000 / 100, tc & 2 ? "yes" : "no", tc & 1 ? "yes" : "no",
		hist, hist == 1 ? "" : "s");
	uiText(14, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
	y += SMALL_H;
	char d[400];
	if (si.hasGp && si.gp.cplcLen) {
		gpCplcDesc(&si.gp, d, sizeof(d));
		char *nl = strchr(d, '\n');
		if (nl) *nl++ = 0;
		uiText(14, y, S_SMALL, txt, "%s", uiFit(d, UI_W - 28, S_SMALL));
		if (nl) uiText(14, y + SMALL_H, S_SMALL, txt, "%s", uiFit(nl, UI_W - 28, S_SMALL));
	} else if (siResult <= 0) {
		uiText(14, y, S_SMALL, uiCol[COL_WARN], "%s", siWhy);
	} else {
		uiText(14, y, S_SMALL, dim, si.hasGp ? "No CPLC" : "No GlobalPlatform security domain answered");
	}
	y += 2 * SMALL_H + 6;

	int n = si.nfound;
	if (!n) {
		uiText(12, y, S_SMALL, dim, "No known applet answered SELECT (more AIDs: smartcard/aids.txt)");
	} else {
		uiText(12, y, S_SMALL, dim, "%d applet%s answered", n, n == 1 ? "" : "s");
		if (n > APP_ROWS) uiTextRight(UI_W - 12, y, S_SMALL, dim, "%d-%d of %d", al.top + 1,
			al.top + APP_ROWS < n ? al.top + APP_ROWS : n, n);
		y += SMALL_H + 1;
		for (int i = 0; i < APP_ROWS && al.top + i < n; i++, y += LINE_H) {
			const ScFound *f = &si.found[al.top + i];
			if (al.top + i == al.sel) uiRect(8, y - 1, UI_W - 16, LINE_H, uiCol[COL_SEL]);
			uiText(14, y, S_BODY, uiCol[f->app && f->app->open ? COL_ACCENT : COL_TEXT], "%s", f->name);
			scHex(s, f->aid, f->aidLen);
			uiMonoS(170, y + 2, 0.34f, 5.6f, dim, s);
			if (f->sw != 0x9000) uiTextRight(UI_W - 14, y + 1, S_SMALL, uiCol[COL_WARN], "%04X", f->sw);
			else if (f->app && f->app->open) uiTextRight(UI_W - 14, y + 1, S_SMALL, uiCol[COL_ACCENT], "tool");
		}
	}
	const ScFound *f = n ? &si.found[al.sel] : NULL;
	if (f && f->app && f->app->open)
		uiFooter(BTN_A " open   " BTN_R " details   " BTN_X " scan   " BTN_Y " card   " BTN_B " back");
	else if (f)
		uiFooter(BTN_A " details   " BTN_X " scan   " BTN_Y " card   " BTN_B " back");
	else
		uiFooter(BTN_X " scan   " BTN_Y " card   " BTN_B " back");
}

static void details(const ScFound *f)
{
	char aid[40], fci[300], asc[132];
	scHex(aid, f->aid, f->aidLen);
	scHex(fci, f->fci, f->fciLen < 100 ? f->fciLen : 100);
	u32 k = 0;
	for (u32 i = 0; i < f->fciLen && k < sizeof(asc) - 1; i++)
		if (f->fci[i] >= 32 && f->fci[i] < 127) asc[k++] = f->fci[i];
	asc[k] = 0;
	msgBox(f->name, "AID %s\nSELECT: SW %04X %s\n%s%s%s%s%s%s", aid, f->sw, scSwName(f->sw),
		f->app ? f->app->help : "From " SC_AIDS ".", f->fciLen ? "\nAnswer: " : "\nNo data in the answer.", fci,
		f->fciLen > 100 ? "..." : "", k >= 4 ? "\nText in it: " : "", k >= 4 ? asc : "");
}

static void cardMenu(void);

static void cardInput(u32 kDown, u32 kRepeat)
{
	int n = si.nfound;
	uiListNav(&al, n, APP_ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	const ScFound *f = n ? &si.found[al.sel] : NULL;
	if ((kDown & KEY_A) && f) {
		if (f->app && f->app->open) f->app->open();
		else details(f);
	}
	if ((kDown & KEY_R) && f) details(f);
	if (kDown & KEY_X) startScan();
	if (kDown & KEY_Y) cardMenu();
	if (kDown & KEY_B) appBack();
}

static const Screen cardScreen = { NULL, cardInput, cardDraw };

static void cardMenu(void)
{
	static const MenuItem items[] = {
		{ "APDU console", apduConsole }, { "GlobalPlatform", gpOpenTool }, { "Save info", save },
	};
	popup("Card", items, 3);
}

// --- APDU console: commands typed in hex, their answers; the session stays up between commands ---

#define CON_MAX 24
#define CON_ANS 512

typedef struct {
	u8 cmd[261];
	u16 cmdLen;
	u8 ans[CON_ANS];
	u16 ansLen, sw;
	char note[128]; // instead of an answer: activation, lost card
} ConEntry;

static ConEntry con[CON_MAX];
static int conN;     // entries (the oldest drop off)
static int conTop = -1; // first line shown, -1 = follow the end
static u32 conJob;   // jobCount() after our last command: another job since means the session is gone
static bool conUp;
static u8 conCmd[261];
static u32 conLen;

static ConEntry *conAdd(void)
{
	if (conN == CON_MAX) memmove(con, con + 1, (CON_MAX - 1) * sizeof(*con)), conN--;
	ConEntry *e = &con[conN++];
	memset(e, 0, sizeof(*e));
	return e;
}

static void runCon(void)
{
	static u8 ans[SC_MAX_ANS];
	if (conJob != jobCount() - 1) conUp = false; // someone else had the card
	if (!conUp) {
		if (!cardWait()) return;
		u8 ats[32];
		int r = scActivate(ats, sizeof(ats));
		ConEntry *e = conAdd();
		if (r <= 0) {
			snprintf(e->note, sizeof(e->note), "activation failed: %s", scWhy());
			return;
		}
		char h[66], uid[32];
		uidHex(&card, uid, "");
		scHex(h, ats, ats[0] < 32 ? ats[0] : 32);
		snprintf(e->note, sizeof(e->note), "card %s activated, ATS %s", uid, h);
		conUp = true;
	}
	ConEntry *e = conAdd();
	memcpy(e->cmd, conCmd, conLen);
	e->cmdLen = conLen;
	u16 sw;
	int n = scApdu(conCmd, conLen, ans, sizeof(ans), &sw);
	if (n < 0) {
		snprintf(e->note, sizeof(e->note), "%s", n == -2 ? "the chip stopped answering" : scWhy());
		conUp = false;
		return;
	}
	e->sw = sw;
	e->ansLen = n;
	memcpy(e->ans, ans, n < CON_ANS ? n : CON_ANS);
	iso14aParity(true);
}

static void doneCon(void)
{
	conJob = jobCount();
	conTop = -1;
}

static void conSend(void)
{
	jobStart("APDU", runCon, doneCon, true);
}

static void conType(const char *init)
{
	char s[600];
	if (!textInput("APDU in hex: CLA INS P1 P2 [Lc data] [Le]", init, s, sizeof(s))) return;
	int n = scUnhex(s, conCmd, sizeof(conCmd));
	if (n < 4) {
		msgBox("APDU", n < 0 ? "Not hex (or longer than 261 bytes)." : "An APDU takes at least 4 bytes: CLA INS P1 P2.");
		return;
	}
	if (n > 5 && (u32)n != 5u + conCmd[4] && (u32)n != 6u + conCmd[4]) {
		msgBox("APDU", "Lc (byte 5, %02X) says %d data bytes, but %d follow.", conCmd[4], conCmd[4], n - 5);
		return;
	}
	conLen = n;
	conSend();
}

#define CON_COLS 64 // hex digits per line
#define CON_ROWS 13

// The console as lines: "> cmd", "< answer SW", wrapped; kind 0 command, 1 answer, 2 note, 3 SW
typedef struct {
	char s[CON_COLS + 1];
	u8 kind;
	u16 sw;
} ConLine;

static int conLines(ConLine *out, int max)
{
	int n = 0;
	char h[2 * CON_ANS + 1];
	for (int i = 0; i < conN && n < max; i++) {
		const ConEntry *e = &con[i];
		if (e->cmdLen) {
			scHex(h, e->cmd, e->cmdLen);
			for (u32 o = 0; o < strlen(h) && n < max; o += CON_COLS, n++) {
				snprintf(out[n].s, sizeof(out[n].s), "%.*s", CON_COLS, h + o);
				out[n].kind = 0;
			}
		}
		if (*e->note) {
			snprintf(out[n].s, sizeof(out[n].s), "%s", e->note);
			out[n++].kind = 2;
			continue;
		}
		if (!e->cmdLen) continue;
		u32 k = e->ansLen < CON_ANS ? e->ansLen : CON_ANS;
		scHex(h, e->ans, k);
		for (u32 o = 0; o < 2 * k && n < max; o += CON_COLS, n++) {
			snprintf(out[n].s, sizeof(out[n].s), "%.*s", CON_COLS, h + o);
			out[n].kind = 1;
		}
		if (n < max) {
			snprintf(out[n].s, sizeof(out[n].s), "%04X %s%s", e->sw, scSwName(e->sw),
				e->ansLen > CON_ANS ? " (answer cut)" : "");
			out[n].kind = 3, out[n++].sw = e->sw;
		}
	}
	return n;
}

static ConLine conL[CON_MAX * 20];

static void conDraw(void)
{
	char hdr[32];
	snprintf(hdr, sizeof(hdr), "%s", conUp ? "session up" : "no session");
	uiHeader("APDU console", hdr);
	int n = conLines(conL, sizeof(conL) / sizeof(conL[0]));
	int max = n > CON_ROWS ? n - CON_ROWS : 0, top = conTop < 0 || conTop > max ? max : conTop;
	if (!n) {
		uiTextWrap(12, 40, UI_W - 24, S_SMALL, uiCol[COL_DIM], "Commands go to the card on the reader as typed, "
			"in hex (CLA INS P1 P2 [Lc data] [Le]); 61xx answers are collected with GET RESPONSE. The card stays "
			"activated between commands, so a SELECT holds for the next ones, until another operation or the "
			"card leaves.\n\nExample: 00A4040007A0000005272101 selects YubiKey OATH.");
	}
	for (int i = top; i < n && i < top + CON_ROWS; i++) {
		float y = 26 + (i - top) * 14;
		const ConLine *l = &conL[i];
		bool first = !i || conL[i - 1].kind != l->kind || l->kind >= 2;
		u32 col = l->kind == 0 ? uiCol[COL_ACCENT] : l->kind == 1 ? uiCol[COL_TEXT] : l->kind == 2 ? uiCol[COL_DIM]
			: l->sw == 0x9000 ? uiCol[COL_OK] : uiCol[COL_WARN];
		if (first && l->kind < 2) uiText(4, y, S_SMALL, uiCol[COL_DIM], l->kind ? "<" : ">");
		if (l->kind < 2) uiMonoS(16, y + 1, 0.34f, 5.6f, col, l->s);
		else uiText(16, y, S_SMALL, col, "%s", l->s);
	}
	if (n > CON_ROWS) {
		float hh = CON_ROWS * 14, bar = hh * CON_ROWS / n;
		uiRect(UI_W - 4, 26, 2, hh, uiCol[COL_PANEL]);
		uiRect(UI_W - 4, 26 + hh * top / n, 2, bar, uiCol[COL_DIM]);
	}
	uiFooter(conN ? BTN_A " new   " BTN_X " again   " BTN_Y " edit   " BTN_L " clear   " BTN_R " reset card   " BTN_B " back"
	              : BTN_A " new APDU   " BTN_B " back");
}

static void conInput(u32 kDown, u32 kRepeat)
{
	int n = conLines(conL, sizeof(conL) / sizeof(conL[0]));
	int max = n > CON_ROWS ? n - CON_ROWS : 0, top = conTop < 0 || conTop > max ? max : conTop;
	if (kRepeat & KEY_UP) top--;
	if (kRepeat & KEY_DOWN) top++;
	top = top < 0 ? 0 : top > max ? max : top;
	conTop = top == max ? -1 : top;
	char h[600];
	if (kDown & KEY_A) conType("");
	if ((kDown & KEY_X) && conLen) conSend();
	if (kDown & KEY_Y) {
		scHex(h, conCmd, conLen);
		conType(h);
	}
	if (kDown & KEY_L) conN = 0, conTop = -1;
	if (kDown & KEY_R) {
		conUp = false;
		toast("The next command activates the card again");
	}
	if (kDown & KEY_B) appBack();
}

void apduConsole(void)
{
	static const Screen s = { NULL, conInput, conDraw };
	appScreen(&s);
}

// --- menu and family ---

static MenuEntry scEntries[4 + 8];
static void scExtra(float y);
static Menu scMenu = { "Smart card", scEntries, 0, scExtra };

static void scExtra(float y)
{
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "Info files: " SC_DIR " (" BTN_Y " on the card screen)");
	if (sc.uidLen) menuLastCard(y + SMALL_H, &sc, si.hasGp ? "GlobalPlatform card" : cardTypeName(&sc));
}

static void scMenuInput(u32 kDown, u32 kRepeat)
{
	menuInput(&scMenu, kDown, kRepeat);
}

static void scMenuDraw(void)
{
	menuDraw(&scMenu);
}

static void scOpenMenu(void)
{
	static const Screen s = { NULL, scMenuInput, scMenuDraw };
	if (!scMenu.n) {
		int n = 0;
		scEntries[n++] = (MenuEntry){ "Scan card", "The ATS, the GlobalPlatform security domain's card data (CPLC, "
			"card recognition data) and every known applet that answers SELECT; each opens its tool.", startScan };
		scEntries[n++] = (MenuEntry){ "APDU console", "Send APDUs typed in hex to the card on the reader and see "
			"the answers, the session kept up between commands.", apduConsole };
		for (int i = 0; i < scNumApplets && n < (int)(sizeof(scEntries) / sizeof(scEntries[0])); i++)
			if (scApplets[i].open) scEntries[n++] = (MenuEntry){ scApplets[i].name, scApplets[i].help, scApplets[i].open };
		scMenu.n = n;
	}
	appScreen(&s);
}

// ISO14443-4 without Classic: what DESFire passes on, or straight from the DESFire family's match.
static bool scMatch(const Card *c)
{
	return (c->sak & 0x20) && !(c->sak & 0x08);
}

const CardFamily scFamily = {
	"Smart card",
	"Any other ISO14443-4 card (JavaCards, YubiKeys, ...): the ATS, applets by AID, an APDU console, "
	"GlobalPlatform applet management, and tools for known applets (YubiKey OATH codes).",
	scMatch, scProbe, scShow, scOpenMenu,
};
