// EMV payment cards (emv.h): the card number (masked until asked), expiry, cardholder, counters and the
// transaction log, an application at a time.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "emv.h"
#include "probe.h"
#include "ui.h"

static EmvCard ec;
static int readResult;
static char readWhy[96];
static int cur;     // the application shown
static bool showPan;
static UiList ll;

static const Screen emvScreen;

static void runRead(void)
{
	readResult = 0;
	*readWhy = 0;
	if (!cardWait()) return;
	readResult = emvRead(&ec);
	snprintf(readWhy, sizeof(readWhy), "%s", emvWhy());
	iso14aParity(true);
}

static void doneRead(void)
{
	if (readResult < 0) {
		msgBox("Payment card", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!readResult) {
		if (!mfCancel && *readWhy) msgBox("Payment card", "%s", readWhy);
		return;
	}
	cur = 0, showPan = false, ll = (UiList){ 0 };
	appScreen(&emvScreen);
}

void emvOpenTool(void)
{
	jobStart("Reading the payment card", runRead, doneRead, true);
}

static void save(void)
{
	char path[128];
	if (emvSave(&ec, path, sizeof(path))) toast("Saved %s (full card number)", path + strlen(APP_DIR "/"));
	else msgBox("Save", "Could not write to the SD card.");
}

// --- the screen ---

#define LOG_ROWS 5

static void dateText(char *out, const u8 *d)
{
	sprintf(out, "%02X/%02X", d[1], d[0]);
}

static void emvDraw(void)
{
	const EmvApp *a = &ec.app[cur];
	char hdr[48], s[160], t[64];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	const char *brand = emvBrand(a->aid, a->aidLen);
	if (ec.napps > 1) snprintf(hdr, sizeof(hdr), "application %d of %d", cur + 1, ec.napps);
	else snprintf(hdr, sizeof(hdr), "%s", ec.ppse ? "from the PPSE" : "known AID");
	uiHeader("Payment card", hdr);

	float y = 26;
	snprintf(s, sizeof(s), "%s", *a->label ? a->label : *brand ? brand : "Payment application");
	uiText(12, y, S_TITLE, uiCol[COL_ACCENT], "%s", uiFit(s, 250, S_TITLE));
	if (*brand && strcmp(brand, a->label)) uiTextRight(UI_W - 12, y + 2, S_SMALL, dim, "%s", brand);
	y += 18;
	scHex(s, a->aid, a->aidLen);
	uiText(12, y, S_SMALL, dim, "AID %s", s);
	y += SMALL_H + 4;

	if (*a->pan) {
		emvPanText(a->pan, showPan, s);
		uiText(12, y, 0.8f, txt, "%s", s);
	} else {
		uiText(12, y + 4, S_BODY, dim, "No card number in what the card gave");
	}
	y += 24;

	int o = 0;
	*s = 0;
	if (a->hasExp) dateText(t, a->exp), o += sprintf(s + o, "Expires %s", t);
	if (a->hasEff) dateText(t, a->eff), o += sprintf(s + o, "%sfrom %s", o ? ", " : "Valid ", t);
	if (a->panSeq >= 0) o += sprintf(s + o, "%sseq. %02d", o ? "   " : "", a->panSeq);
	if (a->svc >= 0) o += sprintf(s + o, "%sservice %03d", o ? "   " : "", a->svc);
	uiText(12, y, S_BODY, txt, "%s", uiFit(s, UI_W - 24, S_BODY));
	y += LINE_H;
	o = 0;
	*s = 0;
	if (*a->name) o += sprintf(s + o, "%s", a->name);
	if (a->country) {
		const char *c = emvCountry(a->country);
		if (c) o += sprintf(s + o, "%s%s", o ? ", issued in " : "Issued in ", c);
		else o += sprintf(s + o, "%s%03X", o ? ", issuer country " : "Issuer country ", a->country);
	}
	if (a->currency) {
		const char *c = emvCurrency(a->currency, NULL);
		if (c) o += sprintf(s + o, "%s%s", o ? ", " : "", c);
	}
	if (o) uiText(12, y, S_BODY, txt, "%s", uiFit(s, UI_W - 24, S_BODY));
	y += LINE_H + 2;

	uiRect(8, y, UI_W - 16, SMALL_H + 4, uiCol[COL_PANEL]);
	o = 0;
	*s = 0;
	if (a->atc >= 0) o += sprintf(s + o, "ATC %d", a->atc);
	if (a->lastOnlineAtc >= 0) o += sprintf(s + o, "%slast online %d", o ? ", " : "", a->lastOnlineAtc);
	if (a->pinTries >= 0) o += sprintf(s + o, "%sPIN tries %d", o ? "   " : "", a->pinTries);
	if (a->hasAip) emvAuthText(a->aip, t), o += sprintf(s + o, "%s%s", o ? "   " : "", t);
	o += sprintf(s + o, "%s%d record%s", o ? "   " : "", a->nrec, a->nrec == 1 ? "" : "s");
	uiText(14, y + 2, S_SMALL, txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
	y += SMALL_H + 8;

	// the transaction log
	if (*a->why) {
		snprintf(s, sizeof(s), "%s", a->why);
		uiText(12, y, S_SMALL, uiCol[COL_WARN], "%s", uiFit(s, UI_W - 24, S_SMALL));
		y += SMALL_H;
	}
	if (!a->logSfi) {
		uiText(12, y, S_SMALL, dim, "No transaction log on this application");
	} else if (!a->nlog) {
		uiText(12, y, S_SMALL, dim, "Transaction log (SFI %d): empty", a->logSfi);
	} else {
		uiText(12, y, S_SMALL, dim, "Transaction log: %d entr%s", a->nlog, a->nlog == 1 ? "y" : "ies");
		if (a->nlog > LOG_ROWS) uiTextRight(UI_W - 12, y, S_SMALL, dim, "%d-%d of %d  " BTN_UD, ll.top + 1,
			ll.top + LOG_ROWS < a->nlog ? ll.top + LOG_ROWS : a->nlog, a->nlog);
		y += SMALL_H + 1;
		for (int i = 0; i < LOG_ROWS && ll.top + i < a->nlog && y < UI_H - 30; i++, y += SMALL_H) {
			const EmvLog *l = &a->log[ll.top + i];
			char d[24] = "", am[32] = "";
			if (l->has & LOG_DATE) sprintf(d, "20%02X-%02X-%02X", l->date[0], l->date[1], l->date[2]);
			if (l->has & LOG_TIME) sprintf(d + strlen(d), " %02X:%02X", l->time[0], l->time[1]);
			uiText(14, y, S_SMALL, txt, "%s", d);
			if (l->has & LOG_AMOUNT) {
				emvAmount(l->amount, l->currency, am);
				uiTextRight(242, y, S_SMALL, uiCol[l->type == 0x20 ? COL_OK : COL_TEXT], "%s%s", l->type == 0x20 ? "+" : "", am);
			}
			*s = 0;
			if (l->has & LOG_MERCHANT) snprintf(s, sizeof(s), "%s", l->merchant);
			else if (l->has & LOG_COUNTRY) snprintf(s, sizeof(s), "%s", emvCountry(l->country) ?: "");
			if (l->has & LOG_TYPE && l->type == 0x01) snprintf(s + strlen(s), sizeof(s) - strlen(s), "%scash", *s ? ", " : "");
			uiText(250, y, S_SMALL, dim, "%s", uiFit(s, UI_W - 262, S_SMALL));
		}
	}
	if (ec.napps > 1)
		uiFooter(BTN_A " number   " BTN_R " next app   " BTN_X " read   " BTN_Y " save   " BTN_B " back");
	else
		uiFooter(BTN_A " number   " BTN_X " read again   " BTN_Y " save   " BTN_B " back");
}

static void emvInput(u32 kDown, u32 kRepeat)
{
	int max = ec.app[cur].nlog > LOG_ROWS ? ec.app[cur].nlog - LOG_ROWS : 0;
	if (kRepeat & KEY_UP) ll.top--;
	if (kRepeat & KEY_DOWN) ll.top++;
	ll.top = ll.top < 0 ? 0 : ll.top > max ? max : ll.top;
	if (kDown & KEY_A) showPan = !showPan;
	if ((kDown & (KEY_L | KEY_R)) && ec.napps > 1) {
		cur = (cur + (kDown & KEY_R ? 1 : ec.napps - 1)) % ec.napps;
		ll = (UiList){ 0 };
	}
	if (kDown & KEY_X) {
		appBack();
		emvOpenTool();
	}
	if (kDown & KEY_Y) save();
	if (kDown & KEY_B) appBack();
}

static const Screen emvScreen = { NULL, emvInput, emvDraw };
