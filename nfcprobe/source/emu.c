// Card emulation over the ROM's NCI listen mode, see emu.h and NOTES.md "Card mode".

#include <stdio.h>
#include <string.h>

#include "emu.h"
#include "mfc.h"
#include "mon.h"
#include "nfchw.h"
#include "probe.h"

EmuState emu;

static const u8 fieldInfo[]   = { NCI_HCIT, 0x20, 0x02, 0x04, 0x01, 0x80, 0x01, 0x01 }; // RF_FIELD_INFO NTFs on
static const u8 discoverMap[] = { NCI_HCIT, 0x21, 0x00, 0x04, 0x01, 0x04, 0x02, 0x02 }; // ISO-DEP, listen, ISO-DEP intf
static const u8 listenA[]     = { NCI_HCIT, 0x21, 0x03, 0x03, 0x01, 0x80, 0x01 };       // RF_DISCOVER listen A
static const u8 deactivate[]  = { NCI_HCIT, 0x21, 0x06, 0x01, 0x00 };

// A command and its response (GID / OID); false if it failed or never came.
static bool nciOk(const u8 *cmd, u32 len)
{
	u8 pkt[4 + 0x100];
	if (R_FAILED(i2cNfcWrite(cmd, len))) return false;
	for (int n = 0; n < 8; n++) {
		u32 rlen = nciRecv(pkt, sizeof(pkt), 26, false);
		if (!rlen) return false;
		if (rlen >= 5 && pkt[1] == (0x40 | (cmd[1] & 0xF)) && pkt[2] == cmd[2]) return pkt[4] == 0;
	}
	return false;
}

#define REARM_MS 100 // sooner (0 or 20 ms) and the chip never activates again
static u32 credits, maxPayload;
static u64 rearmAt; // when to listen again after a deactivation to idle, 0 = not pending

// The NTFs around a session. A deactivation to idle (field gone) stops listening: listen again.
static void control(const u8 *p, u32 len, EmuApdu fn)
{
	if (len < 5) return;
	if (p[1] == 0x61 && p[2] == 0x05 && len >= 10) { // RF_INTF_ACTIVATED: id intf proto mode max credits
		maxPayload = p[8] ? p[8] : 0xFF;
		credits = p[9];
		emu.active = true;
		emu.sessions++;
		fn(NULL, 0, NULL, 0);
		logp("emu: session %lu\n", (unsigned long)emu.sessions);
	} else if (p[1] == 0x61 && p[2] == 0x06) {
		emu.active = false;
		if (p[4] == 0) rearmAt = osGetTime() + REARM_MS;
	} else if (p[1] == 0x61 && p[2] == 0x07) {
		emu.field = p[4];
		emu.fields += p[4] != 0;
	} else if (p[1] == 0x60 && p[2] == 0x06 && len >= 7) { // CORE_CONN_CREDITS: n, (conn, credits)...
		credits += p[6];
	}
}

// The answer as NCI DATA on the static RF connection, segmented to the max payload, a credit per packet.
static void sendData(const u8 *d, u32 len, EmuApdu fn)
{
	u8 pkt[4 + 0x100];
	do {
		u32 n = len > maxPayload ? maxPayload : len;
		for (u64 t0 = osGetTime(); !credits && emu.active && osGetTime() - t0 < 500;) {
			u32 rl = nciRecv(pkt, sizeof(pkt), 2, false);
			if (rl) control(pkt, rl, fn);
		}
		if (!credits || !emu.active) return;
		pkt[0] = NCI_HCIT;
		pkt[1] = len > n ? 0x10 : 0x00; // PBF: more to come
		pkt[2] = 0;
		pkt[3] = n;
		memcpy(pkt + 4, d, n);
		i2cNfcWrite(pkt, 4 + n);
		credits--;
		d += n;
		len -= n;
	} while (len);
}

static void logApdu(const u8 *c, u32 clen, const u8 *r, u32 rlen)
{
	char *s = emu.log[emu.nlog++ % EMU_LOG_N];
	int o = sprintf(s, "> ");
	for (u32 i = 0; i < clen && i < 12; i++) o += sprintf(s + o, "%02X", c[i]);
	if (clen > 12) o += sprintf(s + o, "..");
	sprintf(s + o, "  < %s%02X%02X", rlen > 2 ? ".. " : "", r[rlen - 2], r[rlen - 1]);
	logp("emu: %s\n", s);
}

bool emuRun(EmuApdu fn)
{
	static u8 cmd[0x400], resp[0x200];
	u8 pkt[4 + 0x100];
	u32 r = svcGetSystemTick() ^ osGetTime() * 2654435761u;
	memset(&emu, 0, sizeof(emu));
	emu.uid[0] = 0x08; // random UID (ISO14443-3)
	for (int i = 1; i < 4; i++) emu.uid[i] = r >> (8 * i);
	// LA_BIT_FRAME_SDD 04 (ATQA 0004), LA_PLATFORM_CONFIG 00, LA_SEL_INFO 20 (ISO-DEP), LA_NFCID1
	u8 laConfig[] = { NCI_HCIT, 0x20, 0x02, 0x10, 0x04, 0x30, 0x01, 0x04, 0x31, 0x01, 0x00, 0x32, 0x01, 0x20,
		0x33, 0x04, emu.uid[0], emu.uid[1], emu.uid[2], emu.uid[3] };
	// The memrw monitor stays loaded but unused: it doesn't get in the way. (The ROM's FRAME_LOG does:
	// with it on, our DATA answers never go out.)
	if (!chipEnsure()) {
		logp("NFC takeover failed\n");
		return false;
	}
	if (!monLoad()) return false;
	if (!nciOk(laConfig, sizeof(laConfig)) || !nciOk(fieldInfo, sizeof(fieldInfo)) ||
		!nciOk(discoverMap, sizeof(discoverMap)) || !nciOk(listenA, sizeof(listenA))) {
		logp("emu: listen setup refused\n");
		return false;
	}
	logp("emu: listening as %02X%02X%02X%02X\n", emu.uid[0], emu.uid[1], emu.uid[2], emu.uid[3]);
	u32 clen = 0;
	bool over = false;
	rearmAt = 0;
	while (!mfCancel) {
		if (rearmAt && osGetTime() >= rearmAt) {
			i2cNfcWrite(listenA, sizeof(listenA)); // its RSP comes through control(), ignored
			rearmAt = 0;
		}
		u32 len = nciRecv(pkt, sizeof(pkt), 5, false);
		if (len < 4 || pkt[0] != NCI_HCIT) continue;
		if (pkt[1] >> 5) {
			control(pkt, len, fn);
			continue;
		}
		// DATA, conn 0: an APDU, maybe in segments (PBF)
		u32 n = pkt[3];
		if (clen + n > sizeof(cmd)) over = true;
		else memcpy(cmd + clen, pkt + 4, n), clen += n;
		if (pkt[1] & 0x10) continue;
		u32 rlen = over ? 0 : fn(cmd, clen, resp, sizeof(resp));
		if (rlen < 2) {
			resp[0] = over ? 0x67 : 0x6F; // wrong length / no precise diagnosis
			resp[1] = 0;
			rlen = 2;
		}
		emu.apdus++;
		logApdu(cmd, clen, resp, rlen);
		sendData(resp, rlen, fn);
		clen = 0;
		over = false;
	}
	nciOk(deactivate, sizeof(deactivate));
	emu.active = emu.field = false;
	return true;
}

// --- NFC Forum Type 4 tag ---

#define T4T_MLE 0xF0 // READ BINARY answers fit one NCI packet
static const u8 ndefAid[] = { 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
static const u8 cc[15] = { 0x00, 0x0F, 0x20, 0x00, T4T_MLE, 0x00, T4T_MLE, // CCLEN, mapping 2.0, MLe, MLc
	0x04, 0x06, 0xE1, 0x04, (EMU_NDEF_MAX + 2) >> 8, (EMU_NDEF_MAX + 2) & 0xFF, 0x00, 0x00 }; // NDEF file, r/w
static u8 ndefFile[2 + EMU_NDEF_MAX]; // NLEN (big-endian), then the message
static u32 writes;
static enum { SEL_NONE, SEL_APP, SEL_CC, SEL_NDEF } sel;

void emuNdefSet(const u8 *msg, u32 len)
{
	if (len > EMU_NDEF_MAX) len = EMU_NDEF_MAX;
	memset(ndefFile, 0, sizeof(ndefFile));
	ndefFile[0] = len >> 8;
	ndefFile[1] = len;
	memcpy(ndefFile + 2, msg, len);
	writes = 0;
}

const u8 *emuNdefGet(u32 *len)
{
	u32 n = ndefFile[0] << 8 | ndefFile[1];
	*len = n > EMU_NDEF_MAX ? EMU_NDEF_MAX : n;
	return ndefFile + 2;
}

u32 emuNdefWrites(void)
{
	return writes;
}

static u32 sw(u8 *resp, u32 at, u16 s)
{
	resp[at] = s >> 8;
	resp[at + 1] = s;
	return at + 2;
}

u32 emuNdefApdu(const u8 *c, u32 len, u8 *resp, u32 max)
{
	if (!c) { // a new session
		sel = SEL_NONE;
		return 0;
	}
	if (len < 4) return sw(resp, 0, 0x6700);
	if (c[0] != 0x00) return sw(resp, 0, 0x6E00);
	u32 lc = len > 5 ? c[4] : 0, p12 = c[2] << 8 | c[3];
	if (len > 5 && len < 5 + lc) return sw(resp, 0, 0x6700);
	switch (c[1]) {
	case 0xA4: // SELECT
		if (c[2] == 0x04) { // by name
			bool ndef = lc == sizeof(ndefAid) && !memcmp(c + 5, ndefAid, lc);
			sel = ndef ? SEL_APP : SEL_NONE;
			return sw(resp, 0, ndef ? 0x9000 : 0x6A82);
		}
		if (c[2] == 0x00 && lc == 2 && sel != SEL_NONE) { // by file ID
			u32 fid = c[5] << 8 | c[6];
			if (fid == 0xE103) sel = SEL_CC;
			else if (fid == 0xE104) sel = SEL_NDEF;
			else return sw(resp, 0, 0x6A82);
			return sw(resp, 0, 0x9000);
		}
		return sw(resp, 0, 0x6A82);
	case 0xB0: { // READ BINARY
		const u8 *f = sel == SEL_CC ? cc : ndefFile;
		u32 size = sel == SEL_CC ? sizeof(cc) : sizeof(ndefFile);
		if (sel != SEL_CC && sel != SEL_NDEF) return sw(resp, 0, 0x6986);
		if (p12 > size) return sw(resp, 0, 0x6B00);
		u32 le = len == 5 ? c[4] : 0;
		if (!le || le > T4T_MLE) le = T4T_MLE;
		if (le > size - p12) le = size - p12;
		if (le + 2 > max) le = max - 2;
		memcpy(resp, f + p12, le);
		return sw(resp, le, 0x9000);
	}
	case 0xD6: // UPDATE BINARY
		if (sel == SEL_CC) return sw(resp, 0, 0x6982);
		if (sel != SEL_NDEF) return sw(resp, 0, 0x6986);
		if (len < 5 || p12 + lc > sizeof(ndefFile)) return sw(resp, 0, 0x6A84);
		memcpy(ndefFile + p12, c + 5, lc);
		writes++;
		return sw(resp, 0, 0x9000);
	}
	return sw(resp, 0, 0x6D00);
}
