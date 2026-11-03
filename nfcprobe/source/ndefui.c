// NDEF screen for Ultralight / NTAG (Type 2): the message's records, and writing a URL, a text or an
// empty message onto the card it was read from.

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "mfu.h"
#include "ndef.h"
#include "probe.h"
#include "ui.h"

static MfuDump nd, ndJob; // nd: what the screen shows (UI thread only); ndJob: the job's read, copied in when done
static Card ndCard, ndJobCard;
static int ndResult; // job result: 1 ok, 0 refused, -1 chip, -2 no card / cancelled, -3 another card, -4 another type
static bool ndWriting;
static u8 ndTlv[1024];
static u32 ndTlvLen;
static char ndWhat[300]; // what is being written, for the dialogs

// The parsed message, from nd
static u8 mem[1024];
static u32 memLen, msgOff, msgLen;
static int tlvState; // 1 message, 0 none, -1 broken TLVs
static NdefRec recs[NDEF_MAX_RECS];
static int nrec;
static UiList rl;

static void parse(void)
{
	const MfuType *t = nd.info.type;
	memLen = 0;
	for (int p = 4; p < t->userEnd && nd.valid[p] && memLen + 4 <= sizeof(mem); p++, memLen += 4)
		memcpy(mem + memLen, nd.data[p], 4);
	nrec = 0;
	tlvState = ndefFindTlv(mem, memLen, &msgOff, &msgLen);
	if (tlvState > 0) nrec = ndefParse(mem + msgOff, msgLen, recs, NDEF_MAX_RECS);
	rl.sel = rl.top = 0;
}

static bool sameCard(void)
{
	return card.uidLen == ndJobCard.uidLen && !memcmp(card.uid, ndJobCard.uid, card.uidLen);
}

static void runNdef(void)
{
	ndResult = -2;
	if (!cardWait()) return;
	if (ndWriting) { // only onto the card it was read from, and as the same type
		MfuInfo now;
		u8 cc[16];
		if (!sameCard()) {
			ndResult = -3;
			return;
		}
		if ((ndResult = mfuIdentify(&now)) <= 0) goto out;
		if (now.type != ndJob.info.type) {
			ndResult = -4;
			goto out;
		}
		if ((ndResult = mfuRead(3, cc)) <= 0) goto out;
		ndResult = mfuNdefWrite(now.type, cc, ndTlv, ndTlvLen);
		logp("ndef write %lu bytes: %s\n", (unsigned long)ndTlvLen, ndResult > 0 ? "ok" : mfuWhy());
		if (ndResult <= 0) goto out;
	}
	ndJobCard = card;
	{
		int r = mfuDumpCard(&ndJob, NULL);
		if (r <= 0 || !ndWriting) ndResult = r; // a write's result stays, unless the read-back failed
	}
out:
	iso14aParity(true);
}

static const Screen ndefScreen;

static void doneNdef(void)
{
	if (ndResult == -2) return;
	if (ndResult == -3) {
		msgBox("NDEF", "This is not the card the NDEF screen was opened for: nothing was written.");
		return;
	}
	if (ndResult == -4) {
		msgBox("NDEF", "The card now identifies as another type than when it was read: nothing was written.\n"
			"Read it again (" BTN_A ") first.");
		return;
	}
	if (ndResult < 0) {
		msgBox("NDEF", "The chip stopped answering.");
		return;
	}
	if (ndResult == 0) {
		msgBox("NDEF", ndWriting ? "Not written: %s" : "No Ultralight / NTAG answer: %s", mfuWhy());
		if (!ndWriting) return;
	}
	if (ndResult > 0) {
		nd = ndJob;
		ndCard = ndJobCard;
		parse();
	}
	if (appTop() != &ndefScreen) appScreen(&ndefScreen);
	if (ndWriting && ndResult > 0) toast("Written and read back: %s", ndWhat);
}

static void start(bool write)
{
	ndWriting = write;
	if (!write) memset(&ndJobCard, 0, sizeof(ndJobCard)); // a fresh read: any card
	else ndJob = nd, ndJobCard = ndCard;                   // a write: only onto the card shown
	jobStart(write ? "Writing NDEF" : "Reading NDEF", runNdef, doneNdef, !write);
}

static void writeGo(void)
{
	start(true);
}

static void writeAsk(const u8 *msg, u32 len, bool empty)
{
	if (!len && !empty) {
		msgBox("NDEF", "That is too long for an NDEF record here.");
		return;
	}
	ndTlvLen = ndefTlv(msg, len, ndTlv, sizeof(ndTlv));
	const u8 *cc = nd.data[3];
	u32 room = nd.valid[3] && cc[0] == 0xE1 ? cc[2] * 8 : 0;
	if (!ndTlvLen || ndTlvLen > room) {
		msgBox("NDEF", room ? "That takes %lu bytes; the tag holds %lu." : "This tag has no NDEF capability container.",
			(unsigned long)ndTlvLen, (unsigned long)room);
		return;
	}
	char uid[32];
	uidHex(&ndCard, uid, "");
	confirm("Write NDEF", writeGo, "Write onto %s (UID %s)?\n%s\nIt replaces the current message (%lu bytes).",
		nd.info.type->name, uid, ndWhat, (unsigned long)ndTlvLen);
}

static void urlDone(const char *s)
{
	u8 msg[600];
	if (!*s) return;
	snprintf(ndWhat, sizeof(ndWhat), "URI %.250s", s);
	writeAsk(msg, ndefUri(s, msg, sizeof(msg)), false);
}

static void writeUrl(void)
{
	entryText("Write a URL", "https://..., tel:..., mailto:...", "https://", 511, 0, urlDone);
}

static void textDone(const char *s)
{
	u8 msg[600];
	if (!*s) return;
	snprintf(ndWhat, sizeof(ndWhat), "Text (en) %.250s", s);
	writeAsk(msg, ndefText("en", s, msg, sizeof(msg)), false);
}

static void writeText(void)
{
	entryText("Write text", "A text record (language en).", "", 511, 0, textDone);
}

static void writeEmpty(void)
{
	snprintf(ndWhat, sizeof(ndWhat), "an empty NDEF message");
	writeAsk(NULL, 0, true);
}

static void emulate(void)
{
	emuStartNdef(tlvState > 0 ? mem + msgOff : NULL, tlvState > 0 ? msgLen : 0);
}

static void actions(void)
{
	static const MenuItem items[] = {
		{ "Write a URL", writeUrl },
		{ "Write text", writeText },
		{ "Erase (empty message)", writeEmpty },
		{ "Emulate this message", emulate },
	};
	popup("NDEF", items, 4);
}

#define VIS 5

static void ndefInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&rl, nrec, VIS, kRepeat);
	if (kDown & KEY_A) start(false);
	if (kDown & KEY_X) actions();
	if (kDown & KEY_B) appBack();
}

static void ndefDraw(void)
{
	char uid[32], s[200];
	uidHex(&ndCard, uid, " ");
	uiHeader("NDEF", uid);
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	float y = 28;
	const u8 *cc = nd.data[3];
	uiText(12, y, S_BODY, txt, "%s", nd.info.type->name);
	if (nd.valid[3] && cc[0] == 0xE1)
		uiTextRight(UI_W - 12, y + 2, S_SMALL, txt, "CC %02X%02X%02X%02X: NDEF %d.%d, %d bytes, %s", cc[0], cc[1], cc[2], cc[3],
			cc[1] >> 4, cc[1] & 0xF, cc[2] * 8, cc[3] >> 4 ? "read-only" : "read/write");
	else
		uiTextRight(UI_W - 12, y + 2, S_SMALL, uiCol[COL_WARN], "No NDEF capability container (page 3)");
	y += LINE_H + 6;
	if (tlvState < 0) uiText(12, y, S_SMALL, uiCol[COL_ERR], "The TLVs in user memory are broken");
	else if (tlvState == 0) uiText(12, y, S_SMALL, dim, "No NDEF message (no 03 TLV before the terminator)");
	else if (nrec < 0) uiText(12, y, S_SMALL, uiCol[COL_ERR], "NDEF message of %lu bytes: malformed records", (unsigned long)msgLen);
	else uiText(12, y, S_SMALL, dim, "NDEF message: %lu bytes, %d record%s", (unsigned long)msgLen, nrec, nrec == 1 ? "" : "s");
	y += SMALL_H + 4;
	for (int i = rl.top; i < nrec && i < rl.top + VIS; i++) {
		bool sel = i == rl.sel;
		if (sel) uiRect(8, y - 1, UI_W - 16, 2 * SMALL_H + 2, uiCol[COL_SEL]);
		ndefDescribe(&recs[i], s, sizeof(s));
		uiText(14, y, S_SMALL, txt, "%s", uiFit(s, UI_W - 28, S_SMALL));
		const NdefRec *r = &recs[i];
		uiText(14, y + SMALL_H, S_SMALL, dim, "TNF %d, type %lu, id %lu, payload %lu bytes%s", r->tnf, (unsigned long)r->typeLen,
			(unsigned long)r->idLen, (unsigned long)r->payloadLen, r->chunk ? ", chunked" : "");
		y += 2 * SMALL_H + 4;
	}
	uiFooter(BTN_A " read again   " BTN_X " write, emulate   " BTN_B " back");
}

static const Screen ndefScreen = { NULL, ndefInput, ndefDraw };

void ndefOpenMfu(void)
{
	start(false);
}
