// Card emulation over the ROM's NCI listen mode, see emu.h and docs/NOTES.md "Card mode".

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "dfcrypto.h"
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

static u32 credits, maxPayload;

// The NTFs around a session. After a deactivation to idle (field gone) the chip listens again by itself
// (chip/rearm.h), 1 ms later: a host RF_DISCOVER takes far longer than readers that reselect wait.
static void control(const u8 *p, u32 len, EmuApdu fn)
{
	if (len < 5) return;
	if (p[1] == 0x61 && p[2] == 0x05 && len >= 10) { // RF_INTF_ACTIVATED: id intf proto mode max credits
		maxPayload = p[8] ? p[8] : 0xFF;
		credits = p[9];
		emu.active = true;
		emu.sessions++;
		if (fn) fn(NULL, 0, NULL, 0);
		logp("emu: session %lu\n", (unsigned long)emu.sessions);
	} else if (p[1] == 0x61 && p[2] == 0x06) {
		emu.active = false;
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
	if (rlen < 2) sprintf(s + o, "  < %02X", r[0]); // a native DESFire status
	else sprintf(s + o, "  < %s%02X%02X", rlen > 2 ? ".. " : "", r[rlen - 2], r[rlen - 1]);
	logp("emu: %s\n", s);
}

void emuUidHex(const EmuId *id, char *out)
{
	for (int i = 0; i < id->uidLen; i++) out += sprintf(out, "%02X", id->uid[i]);
	*out = 0;
}

// The ATQA bytes as the LA_* parameters take them; id NULL: a random ISO-DEP card.
static void setId(const EmuId *id)
{
	if (id) emu.id = *id;
	else { // random UID (ISO14443-3: 08 first), an ISO-DEP card
		u32 r = svcGetSystemTick() ^ osGetTime() * 2654435761u;
		emu.id = (EmuId){ { 0x08, r >> 8, r >> 16, r >> 24 }, 4, { 0x04, 0x00 }, 0x20 };
	}
}

enum { CM_MFU = 1, CM_MFC = 3 };

static bool chipUp(int chipImage) // 0: the monitor, else CM_MFU / CM_MFC's image
{
	if (!chipEnsure()) {
		logp("NFC takeover failed\n");
		return false;
	}
	// For APDUs the reader image stays loaded but unused: it doesn't get in the way. (The ROM's FRAME_LOG
	// does: with it on, our DATA answers never go out.)
	return chipImage ? monLoadEmu(chipImage == CM_MFC) : monLoad();
}

// struct emu in the chip image (chip/emu.c): keep in step. It and the frame log are in the chip's AON
// RAM, the page / block memory in the image (Classic blocks 64-172 and 173-255 in two more places);
// MON_EMU gives the five addresses.
enum { CE_MODE = 0, CE_NPAGES = 1, CE_FLAGS = 2, CE_VERSION = 4, CE_SIG = 12, CE_CNT = 44, CE_PACK = 53, CE_PWD = 56,
	CE_FRAMES = 60, CE_WRITES = 64, CE_NLOG = 68, CE_SIZE = 72 };
#define CE_LOG_N 16
static u32 chipBase, chipLog, chipMem, chipMem2, chipMem3; // 0 = APDUs answered here
static u32 chipMode;
static u32 chipSeen, chipNlog; // log entries shown so far / there

// A frame from the chip's log in words, for the job view.
static void chipLogLine(const u8 *e)
{
	char *s = emu.log[emu.nlog++ % EMU_LOG_N];
	const u8 *f = e + 2;
	u32 n = e[1];
	bool dec = e[0] & 0x80; // Classic: decrypted on the chip
	if (chipMode == CM_MFC) {
		if (n == 8 && !dec) sprintf(s, "{nr}{ar}");
		else if (n == 18) sprintf(s, "  data %02X%02X%02X%02X%02X%02X..", f[0], f[1], f[2], f[3], f[4], f[5]);
		else if (n == 4 && (f[0] == 0x60 || f[0] == 0x61))
			sprintf(s, "%sAUTH %c %d", dec ? "nested " : "", f[0] == 0x60 ? 'A' : 'B', f[1]);
		else if (n == 4 && dec && f[0] == 0x30) sprintf(s, "READ %d", f[1]);
		else if (n == 4 && dec && f[0] == 0xA0) sprintf(s, "WRITE %d", f[1]);
		else if (n == 4 && (f[0] == 0x50)) sprintf(s, "HALT");
		else if (n == 1) sprintf(s, "%s", f[0] == 0x26 ? "REQA" : "WUPA");
		else goto raw;
		return;
	}
	switch (n >= 1 ? f[0] : 0) {
	case 0x30: sprintf(s, "READ %02X", f[1]); break;
	case 0x3A: sprintf(s, "FAST_READ %02X-%02X", f[1], f[2]); break;
	case 0x60: sprintf(s, "GET_VERSION"); break;
	case 0x3C: sprintf(s, "READ_SIG"); break;
	case 0x39: sprintf(s, "READ_CNT %d", f[1]); break;
	case 0x1B: sprintf(s, "PWD_AUTH %02X%02X%02X%02X", f[1], f[2], f[3], f[4]); break;
	case 0xA2: sprintf(s, "WRITE %02X: %02X%02X%02X%02X", f[1], f[2], f[3], f[4], f[5]); break;
	case 0xA0: sprintf(s, "COMPATIBILITY_WRITE %02X", f[1]); break;
	case 0x50: sprintf(s, "HLTA"); break;
	case 0x26: case 0x52: sprintf(s, "%s", f[0] == 0x26 ? "REQA" : "WUPA"); break;
	default:
		goto raw;
	}
	return;
raw: {
	int o = sprintf(s, "%s", dec ? "dec " : "");
	for (u32 i = 0; i < n && i < 6; i++) o += sprintf(s + o, "%02X", f[i]);
	if (n > 6) sprintf(s + o, "..");
	}
}

// The chip's counters, then its log (two READ8s), sent without waiting: the answers come in the loop with
// the NTFs (monDo would drop those) and tell themselves apart by length.
static void chipRead8(u32 a, u8 n)
{
	u8 req[] = { NCI_HCIT, 0x2F, 0x2C, 6, MON_READ8, a, a >> 8, a >> 16, a >> 24, n };
	i2cNfcWrite(req, sizeof(req));
}

static void chipPoll(void)
{
	chipRead8(chipBase + CE_FRAMES, CE_SIZE - CE_FRAMES);
	chipRead8(chipLog, CE_LOG_N * 8);
}

static u32 get32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24);
}

static void chipStats(const u8 *p, u32 len)
{
	if (len < 5 || p[4]) return;
	const u8 *d = p + 5;
	if (len == 5 + CE_SIZE - CE_FRAMES) {
		emu.frames = get32(d);
		emu.writes = get32(d + CE_WRITES - CE_FRAMES);
		chipNlog = get32(d + CE_NLOG - CE_FRAMES);
	} else if (len == 5 + CE_LOG_N * 8) {
		if (chipNlog - chipSeen > CE_LOG_N) chipSeen = chipNlog - CE_LOG_N;
		for (; chipSeen < chipNlog; chipSeen++) chipLogLine(d + (chipSeen % CE_LOG_N) * 8);
	}
}

#define POLL_MS 300

// Listens as emu.id until mfCancel; APDUs go to fn, or (fn NULL, chipBase) the chip answers by itself.
static bool listenAs(EmuApdu fn)
{
	static u8 cmd[0x800], resp[0x810]; // Java Card extended APDUs (jccard.h JC_EXT)
	u8 pkt[4 + 0x100];
	const EmuId *e = &emu.id;
	// LA_BIT_FRAME_SDD and LA_PLATFORM_CONFIG: the ATQA (the ROM adds the UID size bits), LA_SEL_INFO: the
	// SAK, LA_NFCID1: the UID (4, 7 or 10 bytes)
	u8 laConfig[4 + 12 + 10] = { NCI_HCIT, 0x20, 0x02, 12 + e->uidLen, 0x04, 0x30, 0x01, e->atqa[0] & 0x1F, 0x31, 0x01,
		e->atqa[1] & 0x0F, 0x32, 0x01, e->sak, 0x33, e->uidLen };
	memcpy(laConfig + 4 + 12, e->uid, e->uidLen);
	if (!nciOk(laConfig, 4 + 12 + e->uidLen) || !nciOk(fieldInfo, sizeof(fieldInfo)) ||
		!nciOk(discoverMap, sizeof(discoverMap)) || !nciOk(listenA, sizeof(listenA))) {
		logp("emu: listen setup refused\n");
		return false;
	}
	char u[32];
	emuUidHex(e, u);
	logp("emu: listening as %s, ATQA %02X%02X, SAK %02X\n", u, e->atqa[1], e->atqa[0], e->sak);
	u32 clen = 0;
	bool over = false;
	u64 pollAt = osGetTime() + POLL_MS;
	while (!mfCancel) {
		if (chipBase && osGetTime() >= pollAt) {
			chipPoll();
			pollAt = osGetTime() + POLL_MS;
		}
		u32 len = nciRecv(pkt, sizeof(pkt), 5, false);
		if (len < 4 || pkt[0] != NCI_HCIT) continue;
		if (pkt[1] == 0x4F && pkt[2] == 0x2C) {
			chipStats(pkt, len);
			continue;
		}
		if (pkt[1] >> 5) {
			control(pkt, len, fn);
			continue;
		}
		if (!fn) continue;
		// DATA, conn 0: an APDU, maybe in segments (PBF)
		u32 n = pkt[3];
		if (clen + n > sizeof(cmd)) over = true;
		else memcpy(cmd + clen, pkt + 4, n), clen += n;
		if (pkt[1] & 0x10) continue;
		u32 rlen = over ? 0 : fn(cmd, clen, resp, sizeof(resp));
		if (!rlen) { // (a native DESFire status is one byte)
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

bool emuRun(const EmuId *id, EmuApdu fn)
{
	memset(&emu, 0, sizeof(emu));
	setId(id);
	chipBase = chipMode = 0;
	return chipUp(0) && listenAs(fn);
}

// Loads the emulation image, puts hdr (struct emu, mode left 0) and mem in, starts the mode, listens as
// emu.id until mfCancel; afterwards the final counters and, if readers wrote, mem as it is now.
// mem's bytes from off to the chip (or back): bytes 0-1023 in the image, then chipMem2 / chipMem3 (chip/emu.c blk()).
static bool chipMemIo(u8 *mem, u32 memLen, bool write)
{
	for (u32 off = 0; off < memLen;) {
		u32 at = off < 1024 ? chipMem + off : off < 173 * 16 ? chipMem2 + off - 1024 : chipMem3 + off - 173 * 16;
		u32 end = off < 1024 ? 1024 : off < 173 * 16 ? 173 * 16 : 256 * 16;
		u32 n = (end < memLen ? end : memLen) - off;
		if (!(write ? monWrite(at, mem + off, n) : monRead(at, mem + off, n))) return false;
		off += n;
	}
	return true;
}

// extra: written at the image's fourth address (Ultralight: the UL-C 3DES subkeys), NULL = none.
static bool chipRun(u8 *hdr, u8 *mem, u32 memLen, u32 mode, const void *extra, u32 extraLen)
{
	if (!chipUp(mode)) return false;
	u8 a[20];
	if (monDo(MON_EMU, 0, NULL, 0, a, 20) != 20) return false;
	chipBase = get32(a), chipLog = get32(a + 4), chipMem = get32(a + 8), chipMem2 = get32(a + 12), chipMem3 = get32(a + 16);
	chipMode = mode;
	chipSeen = chipNlog = 0;
	// The mode byte last: the chip starts answering with everything in place.
	if (!monWrite(chipBase + 1, hdr + 1, CE_SIZE - 1) || !chipMemIo(mem, memLen, true)) return false;
	if (extra && !monWrite(chipMem2, extra, extraLen)) return false;
	u8 m = mode;
	if (!monWrite(chipBase + CE_MODE, &m, 1)) return false;
	if (!listenAs(NULL)) return false;
	u8 st[5 + CE_SIZE - CE_FRAMES] = { 0 };
	if (monRead(chipBase + CE_FRAMES, st + 5, CE_SIZE - CE_FRAMES)) chipStats(st, sizeof(st));
	return !emu.writes || chipMemIo(mem, memLen, false);
}

bool emuRunMfu(MfuDump *d)
{
	static u8 hdr[CE_SIZE], mem[4 * 255], ks[2][16][8];
	const MfuType *t = d->info.type;
	bool ulc = t == &mfuTypeULC;
	int np = d->pages > 255 ? 255 : d->pages;
	if (ulc && np > 0x2C) np = 0x2C; // the key pages can't be read: READ rolls over before them
	memset(&emu, 0, sizeof(emu));
	EmuId id = { .uidLen = 7, .atqa = { 0x44, 0x00 }, .sak = 0x00 };
	memcpy(id.uid, d->data[0], 3);
	memcpy(id.uid + 3, d->data[1], 4);
	setId(&id);
	emu.chipPages = np;
	memset(hdr, 0, sizeof(hdr));
	hdr[CE_NPAGES] = np;
	hdr[CE_FLAGS] = (d->info.hasVersion ? 1 : 0) | (d->info.hasSig ? 2 : 0);
	memcpy(hdr + CE_VERSION, d->info.version, 8);
	if (!d->info.hasVersion && t && mfuVersionForType(t, hdr + CE_VERSION)) hdr[CE_FLAGS] |= 1; // a dump without one
	memcpy(hdr + CE_SIG, d->info.sig, 32);
	for (int i = 0; i < 3; i++) memcpy(hdr + CE_CNT + 3 * i, d->info.cnt[i], 3);
	for (int p = 0; p < np; p++) {
		if (d->valid[p]) memcpy(mem + 4 * p, d->data[p], 4);
		else memset(mem + 4 * p, 0, 4);
	}
	int cfg = t && t->pwd ? t->cfg : 0;
	if (cfg && cfg + 3 < np) { // PWD and PACK: answers, not memory (they read as zeros)
		if (d->valid[cfg + 2] && d->pwdOk) {
			memcpy(hdr + CE_PWD, d->data[cfg + 2], 4);
			hdr[CE_FLAGS] |= 4; // a known password: only that one gets the PACK
		}
		if (d->valid[cfg + 3]) memcpy(hdr + CE_PACK, d->data[cfg + 3], 2);
		memset(mem + 4 * (cfg + 2), 0, 8);
	}
	if (ulc) { // 3DES AUTH with the dump's key
		u8 key[16];
		mfuUlcDumpKey(d, key);
		dfDesSubkeys(key, ks[0]);
		dfDesSubkeys(key + 8, ks[1]);
		hdr[CE_FLAGS] |= 8;
	}
	if (!chipRun(hdr, mem, 4 * np, CM_MFU, ulc ? ks : NULL, sizeof(ks))) return false;
	// What readers wrote goes back into the dump (PWD / PACK stay as they were).
	if (emu.writes)
		for (int p = 2; p < np; p++) {
			if (cfg && (p == cfg + 2 || p == cfg + 3)) continue;
			if (memcmp(d->data[p], mem + 4 * p, 4) || !d->valid[p]) {
				memcpy(d->data[p], mem + 4 * p, 4);
				d->valid[p] = true;
				emu.changed++;
			}
		}
	return true;
}

int emuMfcBlocks(const MfDump *d)
{
	return d->sectors == 5 ? 20 : d->sectors == 16 ? 64 : d->sectors == 32 ? 128 : d->sectors == 40 ? 256 : 0;
}

bool emuRunMfc(MfDump *d)
{
	static u8 hdr[CE_SIZE], mem[16 * 256];
	int nb = emuMfcBlocks(d);
	if (!nb) return false;
	memset(&emu, 0, sizeof(emu));
	const u8 *b0 = d->data[0];
	EmuId id = { .sak = 0x08, .atqa = { 0x04, 0x00 } };
	if ((b0[0] ^ b0[1] ^ b0[2] ^ b0[3]) == b0[4]) { // 4-byte UID: BCC, SAK, ATQA
		id.uidLen = 4;
		id.sak = b0[5];
		memcpy(id.atqa, b0 + 6, 2);
	} else { // 7-byte UID: SAK, ATQA after it
		id.uidLen = 7;
		id.sak = b0[7];
		memcpy(id.atqa, b0 + 8, 2);
	}
	memcpy(id.uid, b0, id.uidLen);
	if (id.sak & 0x20 || !id.sak) // no ISO-DEP: the ROM would answer RATS
		id.sak = nb == 20 ? 0x09 : nb == 128 ? 0x19 : nb == 256 ? 0x18 : 0x08;
	setId(&id);
	emu.chipPages = nb;
	memset(hdr, 0, sizeof(hdr));
	hdr[CE_NPAGES] = nb & 0xFF; // 4K: 0
	memcpy(hdr + CE_VERSION, id.uid + id.uidLen - 4, 4); // Crypto1 takes the last 4 UID bytes
	for (int i = 0; i < nb; i++) {
		if (d->valid[i]) memcpy(mem + 16 * i, d->data[i], 16);
		else memset(mem + 16 * i, 0, 16);
	}
	for (int sec = 0; sec < d->sectors; sec++) { // the trailers with the keys the dump found (unknown: zeros, never opens)
		int i = mfFirstBlock(sec) + mfSectorBlocks(sec) - 1;
		memcpy(mem + 16 * i, d->keyFound[sec][0] ? d->keys[sec][0] : (const u8 *)"\0\0\0\0\0\0", 6);
		memcpy(mem + 16 * i + 10, d->keyFound[sec][1] ? d->keys[sec][1] : (const u8 *)"\0\0\0\0\0\0", 6);
	}
	if (!chipRun(hdr, mem, 16 * nb, CM_MFC, NULL, 0)) return false;
	if (emu.writes)
		for (int i = 1; i < nb; i++) {
			if (i == (i < 128 ? i | 3 : i | 15)) continue; // trailers: the keys stay as the dump has them
			if (memcmp(d->data[i], mem + 16 * i, 16) || !d->valid[i]) {
				memcpy(d->data[i], mem + 16 * i, 16);
				d->valid[i] = true;
				emu.changed++;
			}
		}
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

// --- APDU log ---

#define LOG_RULES 64
static struct {
	u8 cmd[32], resp[64];
	u8 clen, rlen;
} rules[LOG_RULES];
static int nrules;
static FILE *apduLog;

static int unhex(const char *s, u8 *out, int max)
{
	int n = 0;
	while (*s && n < max) {
		unsigned v;
		while (*s == ' ' || *s == ':') s++;
		if (!*s || sscanf(s, "%2x", &v) != 1 || !s[1] || s[1] == ' ') break;
		out[n++] = v;
		s += 2;
	}
	return n;
}

int emuLogLoad(void)
{
	char line[256];
	nrules = 0;
	FILE *f = fopen(EMU_RULES, "r");
	while (f && fgets(line, sizeof(line), f) && nrules < LOG_RULES) {
		char *c = strchr(line, '#'), a[128], b[160];
		if (c) *c = 0;
		if (sscanf(line, "%127s %159s", a, b) != 2) continue;
		rules[nrules].clen = unhex(a, rules[nrules].cmd, sizeof(rules[0].cmd));
		rules[nrules].rlen = unhex(b, rules[nrules].resp, sizeof(rules[0].resp));
		if (rules[nrules].rlen >= 2) nrules++;
	}
	if (f) fclose(f);
	return nrules;
}

static void logHexLine(char dir, const u8 *d, u32 len)
{
	if (!apduLog) return;
	fputc(dir, apduLog);
	fputc(' ', apduLog);
	for (u32 i = 0; i < len; i++) fprintf(apduLog, "%02X", d[i]);
	fputc('\n', apduLog);
}

u32 emuLogApdu(const u8 *c, u32 len, u8 *resp, u32 max)
{
	if (!c) { // a new session: the log file gets a header, opened on the first one
		if (!apduLog) {
			mkdir(EMU_DIR, 0777);
			apduLog = fopen(EMU_APDU_LOG, "a");
		}
		if (apduLog) fprintf(apduLog, "# session %lu\n", (unsigned long)emu.sessions);
		return 0;
	}
	u32 n = 0;
	for (int i = 0; i < nrules && !n; i++)
		if (rules[i].clen <= len && !memcmp(c, rules[i].cmd, rules[i].clen) && rules[i].rlen <= max)
			memcpy(resp, rules[i].resp, n = rules[i].rlen);
	if (!n) { // no rule: no such applet / file for a SELECT, else instruction not supported
		resp[0] = len >= 2 && c[1] == 0xA4 ? 0x6A : 0x6D;
		resp[1] = len >= 2 && c[1] == 0xA4 ? 0x82 : 0x00;
		n = 2;
	}
	logHexLine('>', c, len);
	logHexLine('<', resp, n);
	if (apduLog) fflush(apduLog);
	return n;
}

void emuLogClose(void)
{
	if (apduLog) fclose(apduLog);
	apduLog = NULL;
}
