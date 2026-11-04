// FIDO security keys (fido.h): what the key says about itself, U2F and CTAP2 getInfo.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "fido.h"
#include "probe.h"
#include "ui.h"

static FidoInfo fi;
static int readResult;
static char readWhy[96];

static const Screen fidoScreen;

static void runRead(void)
{
	readResult = 0;
	*readWhy = 0;
	if (!cardWait()) return;
	readResult = fidoRead(&fi);
	snprintf(readWhy, sizeof(readWhy), "%s", fidoWhy());
	iso14aParity(true);
}

static void doneRead(void)
{
	if (readResult < 0) {
		msgBox("FIDO key", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!readResult) {
		if (!mfCancel && *readWhy) msgBox("FIDO key", "%s", readWhy);
		return;
	}
	appScreen(&fidoScreen);
}

void fidoOpenTool(void)
{
	jobStart("Reading the FIDO key", runRead, doneRead, true);
}

static void save(void)
{
	char path[128];
	if (fidoSave(&fi, path, sizeof(path))) toast("Saved %s", path + strlen(MF_DIR "/"));
	else msgBox("Save", "Could not write to the SD card.");
}

// --- the screen ---

// A label and its value; a list too long for the line goes on to a second one after a comma.
static float row(float y, const char *label, const char *val, u32 col)
{
	char s[256], t[256];
	float w = UI_W - 122;
	snprintf(s, sizeof(s), "%s", val);
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "%s", label);
	strcpy(t, s);
	if (strcmp(uiFit(t, w, S_SMALL), s))
		for (char *c = s + strlen(s); c > s; c--) {
			if (c[0] != ',' || c[1] != ' ') continue;
			*c = 0;
			strcpy(t, s);
			if (strcmp(uiFit(t, w, S_SMALL), s)) continue;
			uiText(110, y, S_SMALL, col, "%s,", s);
			y += SMALL_H + 1;
			snprintf(t, sizeof(t), "%s", c + 2);
			uiText(110, y, S_SMALL, col, "%s", uiFit(t, w, S_SMALL));
			return y + SMALL_H + 1;
		}
	uiText(110, y, S_SMALL, col, "%s", uiFit(s, w, S_SMALL));
	return y + SMALL_H + 1;
}

// What an option means in words; "" = say it as name yes / no, NULL = not worth a word (off, nothing named).
static const char *optText(const FidoOpt *o)
{
	static const struct {
		const char *name, *on, *off;
	} t[] = {
		{ "clientPin", "PIN set", "no PIN set" },
		{ "rk", "passkeys", "no passkeys" },
		{ "uv", "built-in UV set up", "built-in UV not set up" },
		{ "up", "touch / presence", "no presence check" },
		{ "plat", "platform", NULL },
		{ "credMgmt", "credential management", NULL },
		{ "credentialMgmtPreview", "credential management (preview)", NULL },
		{ "bioEnroll", "fingerprints enrolled", "no fingerprints enrolled" },
		{ "largeBlobs", "large blobs", NULL },
		{ "ep", "enterprise attestation on", "enterprise attestation off" },
		{ "alwaysUv", "always UV", NULL },
		{ "makeCredUvNotRqd", "no UV for non-passkeys", NULL },
		{ "pinUvAuthToken", "PIN/UV tokens", NULL },
		{ "setMinPINLength", "settable min PIN", NULL },
		{ "authnrCfg", "config command", NULL },
	};
	for (u32 i = 0; i < sizeof(t) / sizeof(t[0]); i++)
		if (!strcmp(o->name, t[i].name)) return o->on ? t[i].on : t[i].off;
	return "";
}

static void fidoDraw(void)
{
	char s[256], g[37];
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	const char *model = fi.hasAaguid ? fidoModel(fi.aaguid) : NULL;
	uiHeader("FIDO key", fi.ctap2 ? "CTAP2 getInfo" : "U2F only");

	float y = 26;
	uiText(12, y, S_TITLE, uiCol[COL_ACCENT], "%s", model ? model : fi.ctap2 ? "FIDO2 authenticator" : "U2F security key");
	y += 18;
	if (fi.hasAaguid) {
		fidoAaguidText(fi.aaguid, g);
		uiText(12, y, S_SMALL, dim, "AAGUID %s", g);
		if (fi.firmware >= 0) uiTextRight(UI_W - 12, y, S_SMALL, dim, "fw %06X", fi.firmware);
		y += SMALL_H + 4;
	}
	if (!fi.ctap2) {
		y = row(y, "Version", *fi.u2f ? fi.u2f : "-", txt);
		snprintf(s, sizeof(s), "%04X %s", fi.infoSw, fi.infoStatus ? "(CTAP error)" : scSwName(fi.infoSw));
		row(y, "getInfo", s, dim);
		uiFooter(BTN_X " read again   " BTN_Y " save   " BTN_B " back");
		return;
	}

	// the PIN state up front: it decides what a site can ask of the key
	int pin = fidoOpt(&fi, "clientPin");
	uiRect(8, y, UI_W - 16, LINE_H + 2, uiCol[COL_PANEL]);
	if (pin < 0) snprintf(s, sizeof(s), "No PIN support");
	else if (!pin) snprintf(s, sizeof(s), "No PIN set: anyone holding the key can use it");
	else if (fi.pinRetries >= 0) snprintf(s, sizeof(s), "PIN set, %d tr%s left", fi.pinRetries, fi.pinRetries == 1 ? "y" : "ies");
	else snprintf(s, sizeof(s), "PIN set");
	uiText(14, y + 2, S_BODY, uiCol[pin == 1 ? COL_OK : pin == 0 ? COL_WARN : COL_TEXT], "%s", uiFit(s, UI_W - 28, S_BODY));
	y += LINE_H + 6;

	int o = 0;
	for (int i = 0; i < fi.nver; i++) o += snprintf(s + o, sizeof(s) - o, "%s%s", i ? ", " : "", fi.ver[i]);
	y = row(y, "Versions", o ? s : "-", txt);
	o = 0;
	for (int i = 0; i < fi.nopt; i++) {
		const char *t = optText(&fi.opt[i]);
		if (!t || !strcmp(fi.opt[i].name, "clientPin")) continue;
		if (*t) o += snprintf(s + o, sizeof(s) - o, "%s%s", o ? ", " : "", t);
		else o += snprintf(s + o, sizeof(s) - o, "%s%s %s", o ? ", " : "", fi.opt[i].name, fi.opt[i].on ? "yes" : "no");
	}
	y = row(y, "Options", o ? s : "-", txt);
	o = 0;
	for (int i = 0; i < fi.next; i++) o += snprintf(s + o, sizeof(s) - o, "%s%s", i ? ", " : "", fi.ext[i]);
	y = row(y, "Extensions", o ? s : "none", txt);
	o = 0;
	for (int i = 0; i < fi.nalg; i++) {
		const char *a = fidoAlgName(fi.alg[i]);
		o += a ? snprintf(s + o, sizeof(s) - o, "%s%s", i ? ", " : "", a)
			: snprintf(s + o, sizeof(s) - o, "%s%d", i ? ", " : "", fi.alg[i]);
	}
	y = row(y, "Algorithms", o ? s : "not listed (ES256)", txt);
	o = 0;
	for (int i = 0; i < fi.npin; i++) o += snprintf(s + o, sizeof(s) - o, "%s%d", i ? ", " : "", fi.pinProto[i]);
	y = row(y, "PIN protocols", o ? s : "-", txt);
	if (fi.ntrans) {
		o = 0;
		for (int i = 0; i < fi.ntrans; i++) o += snprintf(s + o, sizeof(s) - o, "%s%s", i ? ", " : "", fi.trans[i]);
		y = row(y, "Transports", s, txt);
	}
	o = 0;
	if (fi.remainingRk >= 0) o += snprintf(s + o, sizeof(s) - o, "%d passkey slots free", fi.remainingRk);
	if (fi.minPin >= 0) o += snprintf(s + o, sizeof(s) - o, "%sPIN %d+ digits", o ? ", " : "", fi.minPin);
	if (fi.forcePinChange) o += snprintf(s + o, sizeof(s) - o, "%sPIN change due", o ? ", " : "");
	if (fi.maxMsg >= 0) o += snprintf(s + o, sizeof(s) - o, "%smessages to %d bytes", o ? ", " : "", fi.maxMsg);
	if (fi.maxCredList >= 0) o += snprintf(s + o, sizeof(s) - o, "%s%d IDs a list", o ? ", " : "", fi.maxCredList);
	if (fi.maxCredIdLen >= 0) o += snprintf(s + o, sizeof(s) - o, "%sIDs to %d bytes", o ? ", " : "", fi.maxCredIdLen);
	if (o) y = row(y, "Limits", s, txt);
	bool u2fListed = false;
	for (int i = 0; i < fi.nver; i++) u2fListed |= !strcmp(fi.ver[i], fi.u2f);
	if (*fi.u2f && !u2fListed && y < UI_H - 30) row(y, "U2F", fi.u2f, dim);
	uiFooter(BTN_X " read again   " BTN_Y " save   " BTN_B " back");
}

static void fidoInput(u32 kDown, u32 kRepeat)
{
	(void)kRepeat;
	if (kDown & KEY_X) {
		appBack();
		fidoOpenTool();
	}
	if (kDown & KEY_Y) save();
	if (kDown & KEY_B) appBack();
}

static const Screen fidoScreen = { NULL, fidoInput, fidoDraw };
