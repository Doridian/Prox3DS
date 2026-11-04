// YubiKey OATH tool (oath.h): the accounts and their codes, by the console clock and a UTC offset (the
// 3DS has no time zone); HOTP and touch accounts on demand; adding / deleting accounts, the password.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "oath.h"
#include "probe.h"
#include "ui.h"

#define OATH_CFG APP_DIR "/oath.txt" // clock_offset=<seconds>: the console clock minus UTC

static OathInfo oi;
static s64 clockOffset; // seconds: the console clock minus UTC (time zone, or a clock set wrong)
static bool cfgLoaded;
static u8 pwKey[16], pwId[8]; // the password's key, for the device it was entered for
static bool pwKnown;
static UiList cl;

static const Screen oathScreen;

static void cfgLoad(void)
{
	if (cfgLoaded) return;
	cfgLoaded = true;
	FILE *f = fopen(OATH_CFG, "r");
	char line[64];
	while (f && fgets(line, sizeof(line), f))
		if (!strncmp(line, "clock_offset=", 13)) clockOffset = strtoll(line + 13, NULL, 10);
	if (f) fclose(f);
}

static void cfgSave(void)
{
	mkdir(APP_DIR, 0777);
	FILE *f = fopen(OATH_CFG, "w");
	if (!f) return;
	fprintf(f, "clock_offset=%lld\n", clockOffset);
	fclose(f);
}

u64 unixNow(void)
{
	cfgLoad();
	return (u64)time(NULL) - clockOffset;
}

// --- the operations ---

enum { OP_LIST, OP_CALC, OP_PUT, OP_DELETE, OP_SETPW, OP_CLEARPW };
static int op, opResult, opIdx;
static bool needPw;  // the card has a password we don't know (or the one entered was wrong)
static char opWhy[96];
static struct {
	char name[65];
	u8 type, alg, digits;
	u8 secret[64];
	u32 len;
	bool touch;
	u16 period;
	u32 counter;
} put;
static u8 newKey[16];

static void runOp(void)
{
	opResult = 0;
	*opWhy = 0;
	needPw = false;
	if (!cardWait()) return;
	static OathInfo o;
	int r = oathSelect(&o);
	if (r > 0 && o.locked) {
		if (!pwKnown || o.idLen != 8 || memcmp(pwId, o.id, 8)) {
			needPw = true;
			oi = o;
			r = 0;
			snprintf(opWhy, sizeof(opWhy), "This OATH applet has a password.");
		} else if ((r = oathValidate(&o, pwKey)) == 0) {
			needPw = true, pwKnown = false;
		}
	}
	u64 t = unixNow();
	char name[80];
	if (r > 0) {
		switch (op) {
		case OP_CALC:
			o.n = oi.n;
			memcpy(o.c, oi.c, sizeof(o.c));
			r = oathCalc(&o, opIdx, t);
			if (r > 0) oi.c[opIdx] = o.c[opIdx];
			oi.ver[0] = o.ver[0], oi.ver[1] = o.ver[1], oi.ver[2] = o.ver[2];
			goto out;
		case OP_PUT:
			if (put.type == OATH_TOTP && put.period != 30) snprintf(name, sizeof(name), "%d/%s", put.period, put.name);
			else snprintf(name, sizeof(name), "%s", put.name);
			r = oathPut(name, put.type, put.alg, put.digits, put.secret, put.len, put.touch, put.counter);
			break;
		case OP_DELETE:
			r = oathDelete(oi.c[opIdx].name);
			break;
		case OP_SETPW:
			r = oathSetCode(newKey);
			if (r > 0) memcpy(pwKey, newKey, 16), memcpy(pwId, o.id, 8), pwKnown = true;
			break;
		case OP_CLEARPW:
			r = oathSetCode(NULL);
			if (r > 0) pwKnown = false;
			break;
		}
		if (r > 0 || op == OP_LIST) {
			int l = oathList(&o, t);
			if (op == OP_LIST || r > 0) r = l;
		} else {
			snprintf(opWhy, sizeof(opWhy), "%s", oathWhy());
			oathList(&o, t);
			r = 0;
		}
		oi = o;
	}
out:
	if (r <= 0 && !*opWhy) snprintf(opWhy, sizeof(opWhy), "%s", oathWhy());
	opResult = r;
	iso14aParity(true);
}

static void pwEntered(void);

static void doneOp(void)
{
	if (opResult < 0) {
		msgBox("YubiKey OATH", "The chip stopped answering.\nTry again.");
		return;
	}
	if (mfCancel) return;
	if (needPw) {
		pwEntered();
		return;
	}
	if (!opResult && !*opWhy) return; // no card: cancelled
	if (!opResult && op == OP_LIST) {
		msgBox("YubiKey OATH", "%s", opWhy);
		return;
	}
	if (appTop() != &oathScreen) {
		cl = (UiList){ 0 };
		appScreen(&oathScreen);
	}
	if (cl.sel >= oi.n) cl = (UiList){ 0 };
	if (!opResult) msgBox("YubiKey OATH", "%s", opWhy);
	else if (op == OP_PUT) toast("Added %s", put.name);
	else if (op == OP_DELETE) toast("Deleted");
	else if (op == OP_SETPW) toast("Password set");
	else if (op == OP_CLEARPW) toast("Password removed");
}

static void startOp(int o)
{
	op = o;
	jobStart("YubiKey OATH", runOp, doneOp, true);
}

void oathOpenTool(void)
{
	cfgLoad();
	startOp(OP_LIST);
}

// The password: asked when the card wants one, its key kept for that device while the app runs.
static void pwDone(const char *pw)
{
	if (!*pw) return;
	oathKey(pw, &oi, pwKey);
	memcpy(pwId, oi.id, 8);
	pwKnown = true;
	startOp(op);
}

static void pwEntered(void)
{
	entryText("OATH password", pwKnown ? "The password (the one entered before did not work)." :
		"This applet has a password.", "", 127, ENTRY_HIDE, pwDone);
}

// --- the screen ---

#define ROWS 8

static void oathDraw(void)
{
	char hdr[32], s[96];
	snprintf(hdr, sizeof(hdr), "version %d.%d.%d", oi.ver[0], oi.ver[1], oi.ver[2]);
	uiHeader("YubiKey OATH", hdr);
	u64 t = unixNow();
	time_t tt = t;
	struct tm *tm = gmtime(&tt);
	char off[48];
	s64 a = clockOffset < 0 ? -clockOffset : clockOffset;
	if (a >= 86400) snprintf(off, sizeof(off), "console clock corrected");
	else snprintf(off, sizeof(off), "console clock %s%lld:%02lld", clockOffset < 0 ? "-" : "+", a / 3600, a / 60 % 60);
	uiText(12, 26, S_SMALL, uiCol[COL_DIM], "UTC %04d-%02d-%02d %02d:%02d:%02d (%s)", tm->tm_year + 1900, tm->tm_mon + 1,
		tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec, off);
	int left = 30 - t % 30;
	uiBar(UI_W - 112, 29, 70, 7, left / 30.0f, uiCol[left <= 5 ? COL_WARN : COL_ACCENT]);
	uiTextRight(UI_W - 12, 26, S_SMALL, uiCol[COL_DIM], "%2d s", left);
	if (!oi.n) {
		uiTextCenter(UI_W / 2, 100, S_BODY, uiCol[COL_DIM], "No accounts.");
		uiTextCenter(UI_W / 2, 118, S_SMALL, uiCol[COL_DIM], BTN_Y " adds one");
		uiFooter(BTN_X " refresh   " BTN_Y " menu   " BTN_B " back");
		return;
	}
	float y = 44;
	for (int i = 0; i < ROWS && cl.top + i < oi.n; i++, y += 20) {
		const OathCred *c = &oi.c[cl.top + i];
		if (cl.top + i == cl.sel) uiSel(8, y - 2, UI_W - 16, 19);
		const char *nm = c->name;
		const char *slash = strchr(nm, '/');
		if (c->period != 30 && slash) nm = slash + 1;
		snprintf(s, sizeof(s), "%s", nm);
		uiText(14, y, S_BODY, uiCol[COL_TEXT], "%s", uiFit(s, 230, S_BODY));
		bool stale = c->type == OATH_TOTP && c->hasCode && c->step != t / c->period;
		if (c->hasCode) {
			char code[12];
			oathFormat(c, code);
			uiTextRight(UI_W - 14, y - 2, 0.62f, uiCol[stale ? COL_DIM : COL_ACCENT], "%s", code);
		} else {
			uiTextRight(UI_W - 14, y + 1, S_SMALL, uiCol[COL_DIM], c->type == OATH_HOTP ? "HOTP: " BTN_A " for a code"
				: c->touch ? "touch: " BTN_A " for a code" : "-");
		}
		if (c->type == OATH_TOTP && c->period != 30) uiTextRight(UI_W - 104, y + 1, S_SMALL, uiCol[COL_DIM], "%d s", c->period);
	}
	if (oi.n > ROWS) uiTextRight(UI_W - 12, UI_H - 34, S_SMALL, uiCol[COL_DIM], "%d-%d of %d", cl.top + 1,
		cl.top + ROWS < oi.n ? cl.top + ROWS : oi.n, oi.n);
	uiFooter(BTN_A " code   " BTN_X " refresh   " BTN_Y " menu   " BTN_B " back");
}

// --- add an account ---

static const char *const algNames[] = { "", "SHA-1", "SHA-256", "SHA-512" };

static void fName(char *o) { snprintf(o, 64, "%.63s", *put.name ? put.name : "(none)"); }
static void fSecret(char *o)
{
	if (put.len) snprintf(o, 64, "%lu bytes", put.len);
	else strcpy(o, "(none)");
}
static void fType(char *o) { strcpy(o, put.type == OATH_TOTP ? "TOTP (time)" : "HOTP (counter)"); }
static void fAlg(char *o) { strcpy(o, algNames[put.alg]); }
static void fDigits(char *o) { sprintf(o, "%d", put.digits); }
static void fTouch(char *o) { strcpy(o, put.touch ? "required" : "no"); }
// the last row: the period for TOTP, the counter for HOTP
static void fLast(char *o)
{
	if (put.type == OATH_TOTP) sprintf(o, "%d s", put.period);
	else sprintf(o, "%lu", put.counter);
}

static void nameDone(const char *s)
{
	if (*s) snprintf(put.name, sizeof(put.name), "%s", s);
}

static void eName(void)
{
	entryText("Account name", "issuer:account, e.g. GitHub:me", put.name, 64, 0, nameDone);
}

static void secretDone(const char *s)
{
	if (!*s) return;
	int n = base32Decode(s, put.secret, sizeof(put.secret));
	if (n <= 0) msgBox("Secret", "Not base32: letters A-Z and digits 2-7 only (spaces don't matter), up to 64 bytes.");
	else put.len = n;
}

static void eSecret(void)
{
	entryText("Secret key", "Base32, as the site shows it (letters A-Z, digits 2-7; spaces don't matter).", "", 159,
		ENTRY_CAPS, secretDone);
}

static void eType(void) { put.type = put.type == OATH_TOTP ? OATH_HOTP : OATH_TOTP; }
static void eAlg(void) { put.alg = put.alg % 3 + 1; }
static void eDigits(void) { put.digits = put.digits == 6 ? 7 : put.digits == 7 ? 8 : 6; }
static void eTouch(void) { put.touch = !put.touch; }
static void counterSet(s64 v) { put.counter = v; }

static void eLast(void)
{
	if (put.type == OATH_TOTP) put.period = put.period == 30 ? 60 : put.period == 60 ? 15 : 30;
	else entryDec("Counter", "The HOTP counter to start at.", 0, 0x7FFFFFFF, put.counter, counterSet);
}

static const Field addFields[] = {
	{ "Name", fName, eName }, { "Secret", fSecret, eSecret }, { "Type", fType, eType }, { "Algorithm", fAlg, eAlg },
	{ "Digits", fDigits, eDigits }, { "Touch", fTouch, eTouch }, { "Period / counter", fLast, eLast },
};

static int addCount(void)
{
	return 7;
}

static void putGo(void)
{
	startOp(OP_PUT);
}

static void addRun(void)
{
	if (!*put.name || !put.len) {
		msgBox("Add account", "It needs a name and a secret.");
		return;
	}
	for (int i = 0; i < oi.n; i++) {
		const char *nm = oi.c[i].name, *slash = strchr(nm, '/');
		if (!strcmp(oi.c[i].period != 30 && slash ? slash + 1 : nm, put.name)) {
			confirm("Add account", putGo, "%s is on the card already: replace it? The old secret is gone for good.", put.name);
			return;
		}
	}
	putGo();
}

static void addAccount(void)
{
	memset(&put, 0, sizeof(put));
	put.type = OATH_TOTP, put.alg = OATH_SHA1, put.digits = 6, put.period = 30;
	formOpen("Add account", "Add to the card", "Codes come out right when the console clock is set and the UTC "
		"offset matches it (menu: Clock). Touch: the code only after a touch on USB; over NFC the tap counts.",
		addFields, addCount, addRun);
}

// --- delete, password, clock ---

static void delGo(void)
{
	startOp(OP_DELETE);
}

static void delAsk(void)
{
	if (!oi.n) return;
	opIdx = cl.sel;
	confirm("Delete account", delGo, "Delete %s from the card? Its secret is gone for good: the site's 2FA setup "
		"(or a backup code) is the only way back in.", oi.c[cl.sel].name);
}

static void newPwSet(void)
{
	startOp(OP_SETPW);
}

static char newPw[128];

static void setPw2(const char *b)
{
	if (strcmp(newPw, b)) {
		msgBox("Password", "The two didn't match.");
		return;
	}
	oathKey(newPw, &oi, newKey);
	confirm("Password", newPwSet, "Set this password? Every app reading the codes (Yubico Authenticator too) will "
		"ask for it.");
}

static void setPw1(const char *a)
{
	if (!*a) return;
	snprintf(newPw, sizeof(newPw), "%s", a);
	entryText("New OATH password", "The same password again.", "", 127, ENTRY_HIDE, setPw2);
}

static void setPw(void)
{
	entryText("New OATH password", "The password every app reading the codes will ask for.", "", 127, ENTRY_HIDE, setPw1);
}

static void clearPwGo(void)
{
	startOp(OP_CLEARPW);
}

static void clearPw(void)
{
	confirm("Password", clearPwGo, "Remove the password? The codes can then be read without one.");
}

static void offsetSet(s64 v)
{
	clockOffset = v * 60;
	cfgSave();
}

static void clockZone(void)
{
	entryDec("UTC offset", "Minutes the console clock is ahead of UTC (Berlin in winter: 60, New York in "
		"summer: -240). The 3DS keeps local time without a zone, and TOTP needs UTC.", -720, 840, clockOffset / 60, offsetSet);
}

// SNTP: one request to pool.ntp.org, its transmit time against the console clock.
static s64 ntpOffset;
static char ntpWhy[64];

static void runNtp(void)
{
	*ntpWhy = 0;
	struct hostent *h = gethostbyname("pool.ntp.org");
	if (!h || !h->h_addr_list[0]) {
		snprintf(ntpWhy, sizeof(ntpWhy), "pool.ntp.org not found (no wifi?)");
		return;
	}
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		snprintf(ntpWhy, sizeof(ntpWhy), "no socket");
		return;
	}
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(123) };
	memcpy(&sa.sin_addr, h->h_addr_list[0], 4);
	u8 pkt[48] = { 0x23 }; // LI 0, version 4, client
	for (int tries = 0; tries < 3 && !mfCancel; tries++) {
		sendto(fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, sizeof(sa));
		struct pollfd p = { fd, POLLIN, 0 };
		if (poll(&p, 1, 1500) <= 0) continue;
		u8 a[48];
		if (recv(fd, a, sizeof(a), 0) < 48) continue;
		u32 secs = a[40] << 24 | a[41] << 16 | a[42] << 8 | a[43];
		if (!secs) continue;
		s64 utc = (s64)secs - 2208988800LL; // NTP counts from 1900
		ntpOffset = (s64)time(NULL) - utc;
		close(fd);
		logp("NTP: console clock minus UTC = %lld s\n", ntpOffset);
		return;
	}
	close(fd);
	snprintf(ntpWhy, sizeof(ntpWhy), mfCancel ? "cancelled" : "no answer from pool.ntp.org");
}

static void doneNtp(void)
{
	if (*ntpWhy) {
		if (!mfCancel) msgBox("Clock", "%s", ntpWhy);
		return;
	}
	clockOffset = ntpOffset;
	cfgSave();
	toast("Clock set from the internet");
}

static void clockNtp(void)
{
	jobStart("Asking pool.ntp.org", runNtp, doneNtp, true);
}

static void oathMenu(void)
{
	static const MenuItem items[] = {
		{ "Add account", addAccount }, { "Delete account", delAsk }, { "Set password", setPw },
		{ "Remove password", clearPw }, { "Clock: from the internet", clockNtp }, { "Clock: UTC offset", clockZone },
	};
	popup("YubiKey OATH", items, 6);
}

static void oathInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&cl, oi.n, ROWS, kRepeat & (KEY_UP | KEY_DOWN));
	if ((kDown & KEY_A) && oi.n) {
		opIdx = cl.sel;
		startOp(OP_CALC);
	}
	if (kDown & KEY_X) startOp(OP_LIST);
	if (kDown & KEY_Y) oathMenu();
	if (kDown & KEY_B) appBack();
}

static const Screen oathScreen = { NULL, oathInput, oathDraw };
