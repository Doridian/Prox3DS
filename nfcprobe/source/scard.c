// Smart cards: the applet list and the scan, see scard.h.

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "app.h"
#include "probe.h"
#include "scard.h"

static char why[96];

const char *scInfoWhy(void)
{
	return why;
}

const ScApplet scApplets[] = {
	{ "GlobalPlatform ISD", "A000000151000000", "The issuer security domain: card data, and with its keys the "
		"applets and packages on the card, installing and deleting them.", gpOpenTool },
	{ "YubiKey OATH", "A0000005272101", "TOTP / HOTP codes (the YubiKey Authenticator's), adding and deleting "
		"accounts, the password.", oathOpenTool },
	{ "YubiKey management", "A000000527471117", "The YubiKey's firmware version (in the SELECT answer) and its "
		"configuration.", NULL },
	{ "YubiKey OTP", "A0000005272001", "Yubico OTP / static password / challenge-response slots.", NULL },
	{ "OpenPGP card", "D27600012401", "OpenPGP smart card (YubiKey, Nitrokey, SmartPGP): keys for signing, "
		"decryption and authentication.", NULL },
	{ "PIV", "A000000308", "NIST SP 800-73 personal identity verification: certificates and keys.", NULL },
	{ "FIDO U2F / FIDO2", "A0000006472F0001", "Security key for web logins (U2F, CTAP2): its versions, options, whether a PIN is set.", fidoOpenTool },
	{ "NDEF (Type 4 tag)", "D2760000850101", "An NFC Forum Type 4 tag: an NDEF message (URL, text, ...).", NULL },
	{ "Payment card (EMV)", "325041592E5359532E4444463031", "EMV contactless payment card (the PPSE directory): "
		"card number, expiry, cardholder, counters and the transaction log. Read only, nothing is paid.", emvOpenTool },
	{ "Passport (eMRTD)", "A0000002471001", "ICAO electronic passport / ID card (needs the MRZ to read).", NULL },
	{ "Calypso transit", "315449432E494341", "Calypso public transport card.", NULL },
	{ "Keycard", "A0000008040001", "Status Keycard (crypto wallet).", NULL },
	{ "nfcprobe test applet", "F0334453504D01", "javacard/ in the nfcprobe repository: echo, N bytes, slow "
		"commands (WTX), its name.", NULL },
};
const int scNumApplets = sizeof(scApplets) / sizeof(scApplets[0]);

const ScApplet *scAppletFor(const u8 *aid, u32 len)
{
	for (int i = 0; i < scNumApplets; i++) {
		u8 a[16];
		int n = scUnhex(scApplets[i].aid, a, sizeof(a));
		if (n > 0 && (u32)n <= len && !memcmp(a, aid, n)) return &scApplets[i];
	}
	return NULL;
}

static void addFound(ScInfo *s, const char *name, const u8 *aid, u32 len, u16 sw, const u8 *fci, u32 fciLen,
	const ScApplet *app)
{
	if (s->nfound >= SC_MAX_FOUND) return;
	ScFound *f = &s->found[s->nfound++];
	snprintf(f->name, sizeof(f->name), "%s", name);
	// a prefix SELECT: the full AID from the FCI (84) when the card tells it
	Tlv t;
	if (fciLen && tlvFind(fci, fciLen, 0x84, &t) && t.len >= len && t.len <= 16 && !memcmp(t.v, aid, len))
		aid = t.v, len = t.len;
	f->aidLen = len;
	memcpy(f->aid, aid, len);
	f->sw = sw;
	f->fciLen = fciLen < sizeof(f->fci) ? fciLen : sizeof(f->fci);
	memcpy(f->fci, fci, f->fciLen);
	f->app = app;
}

// SELECT one; a hit (9000, or 6283: there but locked) goes to the list. 1 = asked, -1 lost, -2 monitor.
static int try(ScInfo *s, const char *name, const u8 *aid, u32 len, const ScApplet *app)
{
	static u8 buf[SC_MAX_ANS];
	u16 sw;
	int n = scSelect(aid, len, buf, sizeof(buf), &sw);
	if (n < 0) return n;
	char h[40];
	scHex(h, aid, len);
	if (sw == 0x9000 || sw == 0x6283) {
		logp("applet %s (%s): %04X\n", name, h, sw);
		addFound(s, name, aid, len, sw, buf, n, app);
	}
	return 1;
}

int scReadInfo(ScInfo *s)
{
	memset(s, 0, sizeof(*s));
	int r = scActivate(s->ats, sizeof(s->ats));
	if (r < 0) {
		snprintf(why, sizeof(why), "monitor");
		return -1;
	}
	if (!r) {
		snprintf(why, sizeof(why), "%s", scWhy());
		return 0;
	}
	s->atsLen = s->ats[0] < sizeof(s->ats) ? s->ats[0] : sizeof(s->ats);
	r = gpSelect(&s->gp);
	if (r < 0) {
		snprintf(why, sizeof(why), "monitor");
		return -1;
	}
	s->hasGp = r > 0;
	for (int i = 0; i < scNumApplets; i++) {
		u8 aid[16];
		int n = scUnhex(scApplets[i].aid, aid, sizeof(aid));
		if (scApplets[i].open == gpOpenTool && s->hasGp) {
			// the ISD SELECT answered already (maybe under another AID)
			addFound(s, scApplets[i].name, s->gp.isd, s->gp.isdLen, 0x9000, NULL, 0, &scApplets[i]);
			continue;
		}
		if ((r = try(s, scApplets[i].name, aid, n, &scApplets[i])) < 0) break;
	}
	FILE *f = r < 0 ? NULL : fopen(SC_AIDS, "r");
	char line[160];
	while (f && fgets(line, sizeof(line), f)) {
		char *h = strchr(line, '#');
		if (h) *h = 0;
		char *sp = strpbrk(line, " \t");
		if (!sp) continue;
		*sp++ = 0;
		while (*sp == ' ' || *sp == '\t') sp++;
		for (char *e = sp + strlen(sp); e > sp && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' '); ) *--e = 0;
		u8 aid[16];
		int n = scUnhex(line, aid, sizeof(aid));
		if (n < 5) continue;
		if ((r = try(s, *sp ? sp : line, aid, n, NULL)) < 0) break;
	}
	if (f) fclose(f);
	if (r == -2) {
		snprintf(why, sizeof(why), "monitor");
		return -1;
	}
	if (r == -1) {
		snprintf(why, sizeof(why), "%s", scWhy());
		return 0;
	}
	logp("smart card: %d applet%s found%s\n", s->nfound, s->nfound == 1 ? "" : "s", s->hasGp ? ", GlobalPlatform" : "");
	return 1;
}

bool scSaveInfo(const ScInfo *s, const Card *c, char *path, u32 pathMax)
{
	char uid[32], h[300];
	uidHex(c, uid, "");
	mkdir(MF_DIR, 0777);
	mkdir(SC_DIR, 0777);
	struct stat st;
	for (int i = 1; i < 1000; i++) {
		if (i == 1) snprintf(path, pathMax, SC_DIR "/%s.txt", uid);
		else snprintf(path, pathMax, SC_DIR "/%s-%d.txt", uid, i);
		if (stat(path, &st)) break;
	}
	FILE *f = fopen(path, "w");
	if (!f) return false;
	fprintf(f, "UID %s  ATQA %02X%02X  SAK %02X\n", uid, c->atqa[1], c->atqa[0], c->sak);
	scHex(h, s->ats, s->atsLen);
	fprintf(f, "ATS %s\n", h);
	char d[512];
	scAtsDesc(s->ats, s->atsLen, d, sizeof(d));
	fprintf(f, "%s\n", d);
	if (s->hasGp) {
		scHex(h, s->gp.isd, s->gp.isdLen);
		fprintf(f, "\nGlobalPlatform ISD %s\n", h);
		gpCrdDesc(&s->gp, d, sizeof(d));
		fprintf(f, "%s\n", d);
		gpCplcDesc(&s->gp, d, sizeof(d));
		fprintf(f, "%s\n", d);
		scHex(h, s->gp.cplc, s->gp.cplcLen);
		fprintf(f, "CPLC %s\n", h);
		scHex(h, s->gp.crd, s->gp.crdLen);
		fprintf(f, "CRD  %s\n", h);
		if (s->gp.kinfoLen) scHex(h, s->gp.kinfo, s->gp.kinfoLen), fprintf(f, "key information %s\n", h);
		if (s->gp.hasSeq) fprintf(f, "sequence counter %lu\n", s->gp.seq);
	}
	fprintf(f, "\n%d applet%s answered SELECT\n", s->nfound, s->nfound == 1 ? "" : "s");
	for (int i = 0; i < s->nfound; i++) {
		const ScFound *a = &s->found[i];
		scHex(h, a->aid, a->aidLen);
		fprintf(f, "%-32s %s  SW %04X\n", h, a->name, a->sw);
		if (a->fciLen) scHex(h, a->fci, a->fciLen), fprintf(f, "  FCI %s\n", h);
	}
	fclose(f);
	return true;
}
