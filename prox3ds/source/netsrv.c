// TCP server exposing the raw controller primitives, so the PC side (tools/nfcnet.py)
// can run experiments without rebuilding the app. One client at a time.
//
// Request:  op u8, len u16 LE, payload
// Response: op u8, result u32 LE, len u16 LE, payload

#include <arpa/inet.h>
#include <malloc.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amiibo.h"
#include "desfire.h"
#include "emu.h"
#include "eid.h"
#include "emrtd.h"
#include "emv.h"
#include "mfc.h"
#include "isodep.h"
#include "mfu.h"
#include "iclass.h"
#include "ndef.h"
#include "nfchw.h"
#include "probe.h"
#include "ui.h"

#define SOC_BUFFERSIZE 0x100000
#define MS(x)          ((s64)(x) * 1000000LL)

enum {
	OP_PING     = 0x00, // -> "Prox3DS"
	OP_TAKEOVER = 0x01, // kill the nfc module, open gpio/i2c, bind the IRQ (no-op if already ours)
	OP_POWER    = 0x02, // u8: 0 = REG_PU low, 1 = power cycle (low, 20 ms, WAKE low, high, 100 ms)
	OP_WRITE    = 0x03, // bytes -> I2C write
	OP_READ     = 0x04, // u16 timeout ms -> one packet (NCI or HCI event), empty on timeout
	OP_XFER     = 0x05, // u16 timeout ms, bytes -> write, then one packet like OP_READ
	OP_GPIO     = 0x06, // u32 value, u32 mask (mask 0 = only read) -> u32 data of the NFC pins
	OP_RELEASE  = 0x07, // power off, unbind the IRQ, close gpio/i2c
	// Self-update, for debugging: chunks of a new .3dsx go to <app>.new; DONE checks the size, swaps
	// it in and has the app exit (chip handed back as usual) and relaunch itself (main.c).
	OP_UPDATE      = 0x08, // offset u32 (0 = start over), data
	OP_UPDATE_DONE = 0x09, // size u32
	OP_PUT_FILE    = 0x0A, // offset u32 (0 = new file), path length u8, path (under sdmc:/prox3ds/, no
	                       // ".."), data: a file onto the SD card (CAP files to install, key lists)
	// High-level card ops (mfc.c); they take over the chip themselves. Result 0 = ok,
	// 1 = no card / auth refused, -1 = chip monitor error.
	OP_14A_START  = 0x10, // load the monitor, activate a card -> ATQA[2] SAK uidLen uid
	OP_14A_PARITY = 0x11, // u8 on
	OP_14A_TX     = 0x12, // code u8 (0 = whole bytes, FF = data mode: HW parity + CRC), frame
	                      // -> per answer: len u8, raw bytes
	OP_MF_READ    = 0x13, // block u8, keyB u8, key[6], count u8 -> per block: ok u8, data[16]
	OP_MF_DUMP    = 0x14, // sectors u8 (0 = from SAK), keys[6]... (+ keys.txt + defaults), saved to SD
	                      // -> sectors u8, per sector: found u8 (1 = A, 2 = B) keyA[6] keyB[6],
	                      //    per block: ok u8, data[16]
	OP_GEN1A_WRITE = 0x15, // block u8, data[16] -> empty ok; on failure payload = reason. WRITES CARD
	OP_MF_WRITE   = 0x16, // block u8, keyB u8, key[6], data[16] -> empty ok (read back); on failure
	                      // payload = reason. Encrypted WRITE (docs/NOTES.md). WRITES THE CARD
	OP_MF_NESTED  = 0x17, // knownBlock u8, knownKeyB u8, knownKey[6], tgtBlock u8, tgtKeyB u8
	                      // -> recovered key[6]; on failure payload = reason (nested attack, docs/NOTES.md)
	OP_MF_MAGIC   = 0x18, // gen2 u8 (1 = also test Gen2: ATS, block 0 WRITE ACK, nothing written), [pwd[4]]
	                      // -> flags u8 (1 = Gen1a, 2 = Gen2, 4 = Gen4 GTU, 8 = USCUID), Gen4 config
	                      //    len u8, Gen4 config, USCUID config[16] (zeros without the flag)
	OP_GEN4_READ  = 0x19, // pwd[4], block u8, count u8 -> per block: ok u8, data[16]
	OP_GEN4_WRITE = 0x1A, // pwd[4], block u8, data[16] -> empty ok (read back); on failure payload
	                      // = reason. WRITES THE CARD
	OP_GEN4_CONFIG = 0x1B, // pwd[4], [config[30]] -> config read; with config: write it (F0, only
	                       // shadow mode / ATS / ATQA / SAK may change), read back; on failure payload
	                       // = reason. WRITES THE CARD CONFIG
	OP_USC_CONFIG  = 0x1C, // [config[16]] -> USCUID config read; with config: write it (guarded,
	                       // mfc.h), read back; on failure payload = reason. WRITES THE CARD CONFIG
	OP_MF_CLONE    = 0x1D, // force u8, per block: valid u8, data[16] -> empty ok; on failure payload =
	                       // reason (mfCloneToMagic). WRITES THE CARD
	OP_MFU_DUMP    = 0x1E, // [pwd[4] / UL-C key[16]] -> Ultralight / NTAG dump (mfu.c, also saved to SD): pm3 header[56],
	                       // pwdOk u8, per page: valid u8, data[4], then type name len u8, name
	OP_MFU_WRITE   = 0x1F, // page u8, data[4] -> empty ok (read back); on failure payload = reason.
	                       // User memory pages only. WRITES THE CARD
	// UI debugging, served without hwLock (they work while a job runs):
	OP_SHOT        = 0x20, // offset u32 -> up to OUT_MAX bytes of the top framebuffer (240x400 BGR8,
	                       // column-major from the bottom left), empty past the end
	OP_KEYS        = 0x21, // keys u32 (KEY_*) -> pressed for one frame of the UI loop
	// More card ops:
	OP_MFU_CLONE   = 0x22, // Ultralight / NTAG dump (pm3 .bin) -> empty ok (read back); on failure
	                       // payload = reason (mfuCloneToGtu). WRITES THE CARD AND ITS CONFIG
	OP_ISODEP      = 0x23, // activate u8, [INF (an APDU)] -> with activate: ATS (TL first), then the
	                       // answer; on failure payload = reason (isodep.c)
	// UI debugging, served without hwLock:
	OP_LOG         = 0x24, // lines u32 -> the last that many log lines (fewer if OUT_MAX fills), \n each
	// More card ops:
	OP_DF          = 0x25, // DESFire (desfire.c), action u8 + args -> status u8 + data; on a lost card /
	                       // monitor error payload = reason. Actions: 0 auth (EV1; 4: EV2; 5: EV2 NonFirst): keyNo, type
	                       // (dfcrypto.h), key; 1 command: comm, hdr, command bytes -> status, answer; 2 ChangeKey:
	                       // keyNo, picc, ver, type, key, [old type, old key]; 3 info: keys u8 -> the
	                       // saved info file's text. MAY WRITE THE CARD
	OP_MF_CHK      = 0x26, // block u8, keyB u8, keys[6]... -> u16 index of the key that worked (FFFF none);
	                       // on-chip check (mfChkKeys). On failure payload = reason.
	OP_MFU_NDEF    = 0x28, // kind u8: 0 read, 1 write raw message, 2 write URI, 3 write text (en); then the
	                       // message / string -> tlv state i8 (1 message, 0 none, -1 broken), message bytes
	                       // read back. Writes through mfuNdefWrite (ndefui.c's path). MAY WRITE THE CARD
	OP_AMIIBO      = 0x29, // [1, set, (template: version[8] + 540 bytes, else the card on the reader): a fresh
	                       // signed copy -> version[8] + 540 tag bytes; nothing written] [2, lock, 540 bytes:
	                       // mfuAmiiboWrite onto the NTAG215, PERMANENT] [3, fresh, source version[8] + 540, target
	                       // pages 0-2 (12): amiiboImage -> 540 bytes; nothing written]
	                       // -> the Amiibo on the reader decrypted with the console's keys (amiibo.h): ok u8 (HMACs
	                       // check), set u8, charId[8], writes u16, setup u16, written u16, appId u32 (BE), flags
	                       // u8 (1 registered, 2 app data), nickname (UTF-8). On failure payload = reason
	OP_MF_DARKSIDE = 0x2A, // block u8, keyB u8 -> key[6] (darkside: cards with the NACK bug, no key needed);
	                       // on failure payload = reason
	OP_ICLASS      = 0x2B, // [key[8], kind u8 (0 std, 1 elite, 2 diversified)] -> iClass read (iclassrw.c, saved
	                       // to SD): csn[8], kdKnown u8, kcKnown u8, kd[8], kc[8], kdKind u8, kcKind u8, keysTried
	                       // u16, nblocks u16, per block: have u8 + data[8]; then credential: bits u8, value u64,
	                       // fc u32, cn u32, parityOk u8, encrypted u8, format (len u8 + text). 1 = no card
	OP_EMV         = 0x2C, // -> EMV payment card read (emv.c, read only; GPO counts the ATC up), saved to SD:
	                       // the saved file's text (full card number). On failure payload = reason
	OP_MFU_TEAR    = 0x2D, // sub u8, args (mfuTearNet: 0 write scan, 1 EV1 counter reset) -> text. WRITES THE CARD
	OP_MF_VALUE    = 0x27, // op u8 (C0 dec, C1 inc, C2 restore), block u8, delta s32 LE, dest u8, keyB u8,
	                       // key[6] -> dest block read back[16]; on failure payload = reason. WRITES THE CARD
	// APDU relay: the 3DS listens as an ISO-DEP card and the PC answers every APDU (tools/jcvm: a Java
	// Card VM). Request: 0, [uidLen u8, uid, ATQA[2], SAK] (none: a random UID). Until stopped the server
	// sends events, replies with result 1: an APDU (empty = a new session, no answer wanted); each APDU
	// wants a request 1 + the answer (data + SW). Request 2 stops, final reply result 0: fields u32,
	// sessions u32, APDUs u32. A PC that answers nothing for RELAY_WAIT_MS gets 6F00 sent for it.
	OP_RELAY       = 0x2E,
	OP_EID         = 0x2F, // [CAN digits] -> ID document (eid.c): EF.CardAccess in words, EF.DIR, PIN state; with a
	                       // CAN also PACE and an SM SELECT of the ePass application. Text; on failure the reason
};

#define OUT_MAX 0x2000

char netAddr[32];
volatile u32 netKeys;

static u32 *socBuf;
static int listenFd = -1;
static Thread netThread;
static volatile bool netQuit;

// Waits until fd is readable, in short steps so netStop never has to break a blocked socket
// call (that hangs soc:U, and the system with it).
static bool waitReadable(int fd)
{
	while (!netQuit) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int r = poll(&pfd, 1, 100);
		if (r < 0) return false;
		if (r > 0) return true;
	}
	return false;
}

static bool recvAll(int fd, void *buf, u32 len)
{
	u8 *p = buf;
	while (len) {
		if (!waitReadable(fd)) return false;
		int n = recv(fd, p, len, 0);
		if (n <= 0) return false;
		p += n;
		len -= n;
	}
	return true;
}

static bool sendReply(int fd, u8 op, Result res, const void *payload, u16 len)
{
	u8 hdr[7] = { op, res, res >> 8, res >> 16, res >> 24, len, len >> 8 };
	if (send(fd, hdr, sizeof(hdr), 0) != sizeof(hdr)) return false;
	return !len || send(fd, payload, len, 0) == len;
}

static u32 readPacket(u8 *out, u32 max, u32 timeoutMs)
{
	int tries = timeoutMs / 20 + 1;
	return nciRecv(out, max, tries, false);
}

// The card from the last op may have been swapped since: SELECT it again (the cached UID), and on
// silence activate whatever is there now. Not for ISO-DEP / DESFire, whose session a SELECT would end.
static bool cardReady(void)
{
	if (card.active && iso14aParity(true) && iso14aSelect() >= 0) return true;
	return iso14aStart();
}

static Result handleCard(u8 op, const u8 *in, u32 inLen, u8 *out, u16 *outLen)
{
	switch (op) {
	case OP_14A_START:
		if (!iso14aStart()) return 1;
		memcpy(out, card.atqa, 2);
		out[2] = card.sak;
		out[3] = card.uidLen;
		memcpy(out + 4, card.uid, card.uidLen);
		*outLen = 4 + card.uidLen;
		return 0;
	case OP_14A_PARITY:
		if (inLen < 1) return -3;
		return iso14aParity(in[0]) ? 0 : -1;
	case OP_14A_TX: {
		if (inLen < 2) return -3;
		MonFrame f[8];
		int n = in[0] == 0xFF ? iso14aDataTx(in + 1, inLen - 1, f, 8, 10) : iso14aTx(in + 1, inLen - 1, in[0], f, 8);
		if (n < 0) return -1;
		for (int i = 0; i < n; i++) {
			out[*outLen] = f[i].len;
			memcpy(out + *outLen + 1, f[i].data, f[i].len);
			*outLen += 1 + f[i].len;
		}
		return 0;
	}
	case OP_MF_CHK: {
		if (inLen < 8 || (inLen - 2) % 6) return -3;
		int r = mfChkKeys(in[0], in[1], (const u8 (*)[6])(in + 2), (inLen - 2) / 6);
		if (r < -1) {
			*outLen = strlen(mfWhy());
			memcpy(out, mfWhy(), *outLen);
			return r == -3 ? -1 : 1;
		}
		out[0] = r < 0 ? 0xFF : r, out[1] = r < 0 ? 0xFF : r >> 8;
		*outLen = 2;
		return 0;
	}
	case OP_MF_VALUE: {
		if (inLen != 14) return -3;
		if (!cardReady()) return 1;
		s32 delta = in[2] | in[3] << 8 | in[4] << 16 | (u32)in[5] << 24;
		int r = mfValue(in[0], in[1], delta, in[6], in + 8, in[7], out);
		iso14aParity(true);
		if (r <= 0) {
			*outLen = strlen(mfWhy());
			memcpy(out, mfWhy(), *outLen);
			return r ? -1 : 1;
		}
		*outLen = 16;
		return 0;
	}
	case OP_MF_READ: {
		if (inLen < 9 || in[8] > 64) return -3;
		Crypto1 c;
		int r = mfAuth(in[0], in + 2, in[1], &c);
		if (r <= 0) { // payload: the reason
			*outLen = strlen(mfWhy());
			memcpy(out, mfWhy(), *outLen);
			iso14aParity(true);
			return r ? -1 : 1;
		}
		for (int i = 0; i < in[8]; i++) {
			u8 *p = out + 17 * i;
			r = mfReadBlock(&c, in[0] + i, p + 1);
			if (r < 0) return -1;
			p[0] = r;
			if (!r) memset(p + 1, 0, 16);
		}
		*outLen = 17 * in[8];
		iso14aParity(true);
		return 0;
	}
	case OP_MF_DUMP: {
		static MfDump d;
		static u8 keys[MF_MAX_KEYS][6];
		if (inLen < 1) return -3;
		if (!cardReady()) return 1; // also the current SAK
		int sectors = in[0] ? in[0] : mfSectorsFromSak(card.sak);
		if (sectors > 40) return -3;
		int nkeys = mfKeyList(keys, MF_MAX_KEYS, (const u8 (*)[6])(in + 1), (inLen - 1) / 6);
		logp("net: dump %d sectors, %d keys\n", sectors, nkeys);
		int got = mfDumpCard(&d, sectors, (const u8 (*)[6])keys, nkeys);
		iso14aParity(true);
		if (got < 0) return -1;
		char path[64];
		if (mfSaveDump(&d, path, sizeof(path))) logp("net: saved %s\n", path);
		u8 *p = out;
		*p++ = sectors;
		for (int s = 0; s < sectors; s++) {
			*p++ = d.keyFound[s][0] | d.keyFound[s][1] << 1;
			memcpy(p, d.keys[s][0], 6);
			memcpy(p + 6, d.keys[s][1], 6);
			p += 12;
		}
		for (int b = 0; b < mfFirstBlock(sectors); b++) {
			*p++ = d.valid[b];
			memcpy(p, d.data[b], 16);
			p += 16;
		}
		*outLen = p - out;
		return 0;
	}
	case OP_GEN1A_WRITE: {
		if (inLen < 17) return -3;
		if (!cardReady()) return 1;
		int r = mfGen1aWrite(in[0], in + 1);
		iso14aParity(true);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_WRITE: {
		if (inLen < 24) return -3;
		if (!cardReady()) return 1;
		int r = mfWrite(in[0], in + 2, in[1], in + 8);
		iso14aParity(true);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_MAGIC: {
		if (inLen < 1) return -3;
		if (!cardReady()) return 1;
		MfMagic m;
		int r = mfMagicDetect(inLen >= 5 ? in + 1 : mfGen4DefaultPwd, in[0], &m);
		iso14aParity(true);
		if (r < 0) return -1;
		out[0] = m.flags;
		out[1] = m.cfgLen;
		memcpy(out + 2, m.cfg, m.cfgLen);
		memcpy(out + 2 + m.cfgLen, m.usc, MF_USC_CFG);
		*outLen = 2 + m.cfgLen + MF_USC_CFG;
		return 0;
	}
	case OP_GEN4_READ: {
		if (inLen < 6 || in[5] > 64) return -3;
		if (!cardReady()) return 1;
		for (int i = 0; i < in[5]; i++) {
			u8 *p = out + 17 * i;
			int r = mfGen4Read(in, in[4] + i, p + 1);
			if (r < 0) return -1;
			p[0] = r;
			if (!r) memset(p + 1, 0, 16);
		}
		*outLen = 17 * in[5];
		return 0;
	}
	case OP_GEN4_WRITE: {
		if (inLen < 21) return -3;
		if (!cardReady()) return 1;
		int r = mfGen4Write(in, in[4], in + 5);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_GEN4_CONFIG: {
		if (inLen != 4 && inLen != 4 + MF_GEN4_CFG) return -3;
		if (!cardReady()) return 1;
		int r = inLen == 4 ? mfGen4Config(in, out, 32) : mfGen4SetConfig(in, in + 4);
		if (inLen == 4 && r > 0) {
			*outLen = r;
			return 0;
		}
		if (inLen != 4 && r == 1) return 0; // written and verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_USC_CONFIG: {
		if (inLen != 0 && inLen != MF_USC_CFG) return -3;
		if (!cardReady()) return 1;
		int r = inLen ? mfUscuidSetConfig(in) : mfUscuidConfig(out);
		iso14aParity(true);
		if (r == 1) {
			*outLen = inLen ? 0 : MF_USC_CFG;
			return 0;
		}
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_CLONE: {
		static u8 data[MF_MAX_BLOCKS][16];
		static bool valid[MF_MAX_BLOCKS];
		int nb = (inLen - 1) / 17;
		if (inLen < 1 || (inLen - 1) % 17 || nb > MF_MAX_BLOCKS) return -3;
		for (int b = 0; b < nb; b++) {
			valid[b] = in[1 + 17 * b];
			memcpy(data[b], in + 2 + 17 * b, 16);
		}
		if (!cardReady()) return 1;
		int r = mfCloneToMagic((const u8 (*)[16])data, valid, nb, in[0]);
		iso14aParity(true);
		if (r == 1) return 0;
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_ICLASS: {
		if (inLen != 0 && inLen != 9) return -3;
		IcCard *c = &icCard;
		if (!icWait(c->csn, 6000)) return 1;
		int r = icReadCard(c, inLen ? in : NULL, inLen ? in[8] : 0);
		if (r <= 0) return r < 0 ? -1 : 1;
		char path[80];
		if (icSaveDump(c, path, sizeof(path))) logp("net: saved %s\n", path);
		u8 *p = out;
		memcpy(p, c->csn, 8), p += 8;
		*p++ = c->kdKnown, *p++ = c->kcKnown;
		memcpy(p, c->kd, 8), memcpy(p + 8, c->kc, 8), p += 16;
		*p++ = c->kdKind, *p++ = c->kcKind;
		*p++ = c->keysTried, *p++ = c->keysTried >> 8;
		*p++ = c->nblocks, *p++ = c->nblocks >> 8;
		for (int b = 0; b < c->nblocks; b++, p += 9) {
			p[0] = c->have[b];
			memcpy(p + 1, c->blocks[b], 8);
		}
		const IcCredential *cr = &c->cred;
		*p++ = cr->bits;
		for (int i = 0; i < 8; i++) *p++ = cr->value >> (8 * i);
		for (int i = 0; i < 4; i++) *p++ = cr->fc >> (8 * i);
		for (int i = 0; i < 4; i++) *p++ = cr->cn >> (8 * i);
		*p++ = cr->parityOk, *p++ = cr->encrypted;
		*p = strlen(cr->format);
		memcpy(p + 1, cr->format, *p);
		*outLen = p + 1 + *p - out;
		icStop();
		return 0;
	}
	case OP_MFU_TEAR: {
		if (!cardReady()) return 1;
		int r = mfuTearNet(in, inLen, (char *)out, OUT_MAX);
		iso14aParity(true);
		if (r < 0) return -1;
		*outLen = r;
		return 0;
	}
	case OP_EMV: {
		if (!card.active && !iso14aStart()) return 1;
		static EmvCard e;
		char path[128];
		int r = emvRead(&e);
		iso14aParity(true);
		if (r <= 0) {
			*outLen = strlen(emvWhy());
			memcpy(out, emvWhy(), *outLen);
			return r < 0 ? -1 : 1;
		}
		if (!emvSave(&e, path, sizeof(path))) return -1;
		logp("net: saved %s\n", path);
		FILE *f = fopen(path, "r");
		*outLen = f ? fread(out, 1, OUT_MAX, f) : 0;
		if (f) fclose(f);
		return 0;
	}
	case OP_EID: {
		if (!card.active && !iso14aStart()) return 1;
		static EidCard e;
		static EidSm sm;
		char *o = (char *)out, can[16];
		int r = eidRead(&e), k = 0;
		if (r <= 0) {
			iso14aParity(true);
			*outLen = strlen(eidWhy());
			memcpy(out, eidWhy(), *outLen);
			return r < 0 ? -1 : 1;
		}
		char h[80];
		scHex(h, e.ats, e.atsLen);
		k += snprintf(o + k, OUT_MAX - k, "ATS %s\nEF.CardAccess: %u bytes, %d entries\n", h, e.accessLen, e.ninfo);
		for (int i = 0; i < e.ninfo; i++) {
			eidInfoText(&e.info[i], h, sizeof(h));
			k += snprintf(o + k, OUT_MAX - k, "  %s%s\n", h, i == e.pace ? "  <- used" : "");
		}
		for (int i = 0; i < e.napps; i++) {
			const char *n = eidAppName(e.app[i].aid, e.app[i].aidLen);
			scHex(h, e.app[i].aid, e.app[i].aidLen);
			k += snprintf(o + k, OUT_MAX - k, "EF.DIR: %s %s %s\n", h, n ? n : "", e.app[i].label);
		}
		u32 col;
		const char *pin = eidPinText(e.pinSw, &col);
		k += snprintf(o + k, OUT_MAX - k, "extended length %lu / %lu\nPIN state %04X %s\n", e.extIn, e.extOut,
			e.pinSw, pin ? pin : "");
		if (inLen && inLen < 40 && (memchr(in, ',', inLen) || (in[0] == 'r' && inLen > 1 && in[1] != 'b'))) {
			// read the LDS: "DOC,YYMMDD,YYMMDD" (MRZ) or "r" + CAN
			static MrtdDoc d;
			char a[40], *b1, *b2;
			u8 key[20];
			memcpy(a, in, inLen);
			a[inLen] = 0;
			u64 t0 = osGetTime();
			if (a[0] == 'r') {
				r = mrtdRead(&e, EID_CAN, (const u8 *)a + 1, strlen(a + 1), &d);
			} else {
				// "b" first: BAC even when the chip has PACE
				char *doc = a[0] == 'b' ? a + 1 : a;
				if (a[0] == 'b') e.pace = -1;
				b1 = strchr(doc, ','), *b1++ = 0, b2 = strchr(b1, ',');
				if (!b2) return -3;
				*b2++ = 0;
				eidMrzSecret(doc, b1, b2, key);
				r = mrtdRead(&e, EID_MRZ, key, 20, &d);
			}
			iso14aParity(true);
			k += snprintf(o + k, OUT_MAX - k, "read: %d %s (%llu ms), access %s\n", r, r == 1 ? "" : mrtdWhy(),
				osGetTime() - t0, d.access);
			if (r < 0) return -1;
			for (int i = 0; i < MRTD_FILES; i++) {
				if (!d.f[i].data && !d.f[i].sw) continue;
				k += snprintf(o + k, OUT_MAX - k, "  %s%d: %lu bytes, %04X\n", i == MRTD_COM ? "COM" : i == MRTD_SOD ? "SOD" : "DG",
					i == MRTD_COM || i == MRTD_SOD ? 0 : i, d.f[i].len, d.f[i].sw);
			}
			k += snprintf(o + k, OUT_MAX - k, "DG1: %s %s %s / %s, %s, born %s, %c, expires %s\n", d.docType, d.issuer,
				d.surname, d.given, d.number, d.birth, d.sex ? d.sex : '?', d.expiry);
			k += snprintf(o + k, OUT_MAX - k, "PA: hash %d, listed %lX ok %lX bad %lX, attrs %d, sig %d %s\n  DS %s\n  "
				"issuer %s\n  valid %s - %s %s\nphoto %s %lu bytes at %lu\n", d.hashLen, d.listed, d.ok, d.bad,
				d.attrs, d.sig, d.sigAlg, d.dsSubject, d.dsIssuer, d.dsFrom, d.dsTo, d.paWhy, d.photoJp2 ? "jp2" : "jpg",
				d.photoLen, d.photoOff);
			char path[128];
			if (r == 1 && mrtdSave(&d, path, sizeof(path))) k += snprintf(o + k, OUT_MAX - k, "saved %s\n", path);
			*outLen = k;
			return 0;
		}
		if (inLen && inLen < sizeof(can)) {
			memcpy(can, in, inLen);
			can[inLen] = 0;
			u64 t0 = osGetTime();
			r = eidPace(&e, EID_CAN, (const u8 *)can, strlen(can), &sm);
			k += snprintf(o + k, OUT_MAX - k, "PACE: %d %s (%llu ms)\n", r, r == 1 ? "ok" : eidWhy(), osGetTime() - t0);
			if (r == 1) {
				static const u8 epass[] = { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
				u8 b[16];
				u16 sw = 0;
				int n = eidSmCmd(&sm, 0xA4, 0x04, 0x0C, epass, sizeof(epass), -1, b, sizeof(b), &sw);
				k += snprintf(o + k, OUT_MAX - k, "SM SELECT ePass: %d, %04X %s\n", n, sw, n < 0 ? eidWhy() : "");
				n = eidSmCmd(&sm, 0xB0, 0x81, 0, NULL, 0, 0, b, sizeof(b), &sw);
				k += snprintf(o + k, OUT_MAX - k, "SM READ DG1: %d, %04X %s\n", n, sw, n < 0 ? eidWhy() : "");
			}
			if (r < 0) {
				iso14aParity(true);
				return -1;
			}
		}
		iso14aParity(true);
		*outLen = k;
		return 0;
	}
	case OP_MFU_DUMP: {
		static MfuDump d;
		u8 key[16] = { 0 };
		if (inLen != 0 && inLen != 4 && inLen != 16) return -3;
		memcpy(key, in, inLen);
		if (!cardReady()) return 1;
		int r = mfuDumpCard(&d, inLen ? key : NULL);
		if (r <= 0) {
			*outLen = strlen(mfuWhy());
			memcpy(out, mfuWhy(), *outLen);
			return r < 0 ? -1 : 1;
		}
		char path[64];
		if (mfuSaveDump(&d, path, sizeof(path))) logp("net: saved %s\n", path);
		u8 *p = out;
		memcpy(p, d.info.version, 8);
		memset(p + 8, 0, 3);
		p[11] = d.pages - 1;
		memcpy(p + 12, d.info.sig, 32);
		memcpy(p + 44, d.info.cnt, 12);
		p += MFU_HDR;
		*p++ = d.pwdOk;
		for (int i = 0; i < d.pages; i++, p += 5) {
			p[0] = d.valid[i];
			memcpy(p + 1, d.data[i], 4);
		}
		*p = strlen(d.info.type->name);
		memcpy(p + 1, d.info.type->name, *p);
		*outLen = p + 1 + *p - out;
		return 0;
	}
	case OP_MFU_WRITE: {
		if (inLen != 5) return -3;
		if (!cardReady()) return 1;
		MfuInfo info;
		int r = mfuIdentify(&info);
		if (r > 0) r = mfuWritePage(info.type, in[0], in + 1);
		if (r == 1) return 0;
		*outLen = strlen(mfuWhy());
		memcpy(out, mfuWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MFU_NDEF: {
		static MfuDump d;
		static u8 msg[1024], tlv[1100], mem[1024];
		if (inLen < 1 || in[0] > 3 || inLen - 1 >= 900) return -3;
		if (!cardReady()) return 1;
		MfuInfo info;
		u8 cc[16];
		int r = mfuIdentify(&info);
		if (r > 0 && in[0]) {
			char str[900];
			memcpy(str, in + 1, inLen - 1);
			str[inLen - 1] = 0;
			u32 n = in[0] == 1 ? (memcpy(msg, in + 1, inLen - 1), inLen - 1)
			      : in[0] == 2 ? ndefUri(str, msg, sizeof(msg)) : ndefText("en", str, msg, sizeof(msg));
			u32 t = n || in[0] == 1 ? ndefTlv(msg, n, tlv, sizeof(tlv)) : 0; // a record that didn't build: nothing
			if (!t) {
				static const char e[] = "record too long";
				memcpy(out, e, *outLen = sizeof(e) - 1);
				return 1;
			}
			if ((r = mfuRead(3, cc)) > 0) r = mfuNdefWrite(info.type, cc, tlv, t);
		}
		if (r > 0) r = mfuDumpCard(&d, NULL);
		iso14aParity(true);
		if (r <= 0) {
			*outLen = strlen(mfuWhy());
			memcpy(out, mfuWhy(), *outLen);
			return r < 0 ? -1 : 1;
		}
		u32 n = 0, off = 0, len = 0;
		for (int p = 4; p < d.info.type->userEnd && d.valid[p] && n + 4 <= sizeof(mem); p++, n += 4) memcpy(mem + n, d.data[p], 4);
		int st = ndefFindTlv(mem, n, &off, &len);
		out[0] = st;
		if (st > 0) memcpy(out + 1, mem + off, len);
		*outLen = 1 + (st > 0 ? len : 0);
		return 0;
	}
	case OP_AMIIBO: {
		static MfuDump d;
		static Amiibo a;
		static u8 tag[AMIIBO_TAG];
		if (!amiiboKeysLoad()) {
			*outLen = strlen(amiiboWhy());
			memcpy(out, amiiboWhy(), *outLen);
			return 1;
		}
		if (inLen == 2 + AMIIBO_TAG && in[0] == 2) { // write the image onto the NTAG215: in[1] 0 data, 1 lock
			if (!cardReady()) return 1;
			int r = mfuAmiiboWrite(in + 2, in[1]);
			iso14aParity(true);
			logp("amiibo write (%s): %s\n", in[1] ? "lock" : "data", r > 0 ? "ok" : mfuWhy());
			if (r > 0) return 0;
			*outLen = strlen(mfuWhy());
			memcpy(out, mfuWhy(), *outLen);
			return r < 0 ? -1 : 1;
		}
		if (inLen == 2 + 8 + AMIIBO_TAG + 12 && in[0] == 3) { // copy image: source version[8] + 540, target pages 0-2
			amiiboUnpack(in + 10, &a);
			if (!amiiboImage(&a, in + 10 + AMIIBO_TAG, in[1], out)) {
				*outLen = strlen(amiiboWhy());
				memcpy(out, amiiboWhy(), *outLen);
				return 1;
			}
			*outLen = AMIIBO_TAG;
			return 0;
		}
		if (inLen == 2 + 8 + AMIIBO_TAG && in[0] == 1) { // a template given: version[8] + 540 bytes, no card
			memcpy(d.info.version, in + 2, 8);
			memcpy(tag, in + 10, AMIIBO_TAG);
		} else {
			if (!cardReady()) return 1;
			int r = mfuDumpCard(&d, NULL);
			iso14aParity(true);
			if (r <= 0) {
				*outLen = strlen(mfuWhy());
				memcpy(out, mfuWhy(), *outLen);
				return r < 0 ? -1 : 1;
			}
			for (int p = 0; p < AMIIBO_TAG / 4; p++) memcpy(tag + 4 * p, d.data[p], 4);
		}
		if (in[0] == 1 && inLen >= 2) { // a fresh signed copy with key set in[1]: version[8] + the 540 bytes
			if (!amiiboFresh(tag, in[1], out + 8)) {
				*outLen = strlen(amiiboWhy());
				memcpy(out, amiiboWhy(), *outLen);
				return 1;
			}
			memcpy(out, d.info.version, 8);
			*outLen = 8 + AMIIBO_TAG;
			return 0;
		}
		amiiboUnpack(tag, &a);
		u8 *o = out;
		*o++ = a.ok, *o++ = a.set | a.hmacBits << 4;
		memcpy(o, a.charId, 8), o += 8;
		*o++ = a.writes >> 8, *o++ = a.writes, *o++ = a.setupDate >> 8, *o++ = a.setupDate;
		*o++ = a.writeDate >> 8, *o++ = a.writeDate;
		*o++ = a.appId >> 24, *o++ = a.appId >> 16, *o++ = a.appId >> 8, *o++ = a.appId;
		*o++ = a.registered | a.hasAppData << 1;
		u32 nl = strlen(a.nickname);
		memcpy(o, a.nickname, nl), o += nl;
		*outLen = o - out;
		return 0;
	}
	case OP_MFU_CLONE: {
		static MfuDump d;
		if (!mfuParseDump(&d, in, inLen)) return -3;
		if (!cardReady()) return 1;
		int r = mfuCloneToGtu(&d);
		iso14aParity(true);
		if (r == 1) return 0;
		*outLen = strlen(mfuWhy());
		memcpy(out, mfuWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_ISODEP: {
		if (inLen < 1 || inLen - 1 > OUT_MAX - 64) return -3;
		if (!card.active && !iso14aStart()) return 1;
		u32 o = 0;
		int r = 1;
		if (in[0]) {
			r = isoDepActivate(out, 32);
			o = r > 0 ? out[0] : 0;
		}
		if (r > 0 && inLen > 1) {
			r = isoDepTx(in + 1, inLen - 1, out + o, OUT_MAX - o);
			o += r > 0 ? r : 0;
		}
		if (r > 0) {
			*outLen = o;
			return 0;
		}
		*outLen = strlen(isoDepWhy());
		memcpy(out, isoDepWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_DF: {
		if (inLen < 2) return -3;
		if (!card.active && !iso14aStart()) return 1;
		u8 st = 0;
		int r;
		DfKey k = { true }, old = { true };
		if ((in[0] == 0 || in[0] == 4 || in[0] == 5 || in[0] == 6) && inLen >= 4) {
			k.type = in[2];
			if (k.type > DF_AES || inLen != 3 + dfKeyLen(k.type)) return -3;
			memcpy(k.key, in + 3, dfKeyLen(k.type));
			r = in[0] == 5 ? dfAuthEv2NonFirst(in[1], &k, &st) : dfAuth(in[1], &k, in[0] == 4 ? DF_AUTH_EV2 :
				in[0] == 6 ? DF_AUTH_D40 : DF_AUTH_EV1, &st);
			*outLen = 1;
		} else if (in[0] == 1 && inLen >= 4) {
			r = dfCmd(in + 3, inLen - 3, in[2], in[1], out + 1, OUT_MAX - 1, &st);
			*outLen = r > 0 ? 1 + r : 1;
			r = r == -2 ? -1 : r == -1 ? 0 : 1;
			if (!r) goto dfFail;
		} else if (in[0] == 2 && inLen >= 5) {
			k.type = in[4];
			if (k.type > DF_AES || inLen < 5 + dfKeyLen(k.type)) return -3;
			memcpy(k.key, in + 5, dfKeyLen(k.type));
			u32 o = 5 + dfKeyLen(k.type);
			if (inLen > o) {
				old.type = in[o];
				if (old.type > DF_AES || inLen != o + 1 + dfKeyLen(old.type)) return -3;
				memcpy(old.key, in + o + 1, dfKeyLen(old.type));
			}
			r = dfChangeKey(in[1], &k, in[3], &old, in[2], &st);
			*outLen = 1;
		} else if (in[0] == 3) {
			static DfInfo di;
			char path[128];
			r = dfReadInfo(&di, in[1]);
			iso14aParity(true);
			if (r <= 0) goto dfFail;
			if (!dfSaveInfo(&di, path, sizeof(path))) return -1;
			FILE *f = fopen(path, "r");
			*outLen = f ? fread(out, 1, OUT_MAX, f) : 0;
			if (f) fclose(f);
			return 0;
		} else {
			return -3;
		}
		if (r < 0) goto dfFail;
		out[0] = st;
		return 0;
	dfFail:
		*outLen = strlen(dfWhy());
		memcpy(out, dfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_DARKSIDE: {
		if (inLen < 2) return -3;
		if (!cardReady()) return 1;
		u8 key[6];
		int r = mfDarkside(in[0], in[1], key);
		iso14aParity(true);
		if (r == 1) {
			memcpy(out, key, 6);
			*outLen = 6;
			return 0;
		}
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_NESTED: {
		if (inLen < 10) return -3;
		if (!cardReady()) return 1;
		u8 key[6];
		int r = mfNestedRecover(in[0], in + 2, in[1], in[8], in[9], key);
		iso14aParity(true);
		if (r == 1) {
			memcpy(out, key, 6);
			*outLen = 6;
			return 0;
		}
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	}
	return -4;
}

static Result handleDebug(u8 op, const u8 *in, u32 inLen, u8 *out, u16 *outLen)
{
	if (inLen < 4) return -3;
	u32 v;
	memcpy(&v, in, 4);
	if (op == OP_KEYS) {
		netKeys |= v;
		return 0;
	}
	if (op == OP_LOG) {
		int n = uiLogCount(), i = n - (int)v < 0 ? 0 : n - (int)v;
		char line[128];
		for (; i < n; i++) {
			uiLogLine(i, line, sizeof(line));
			u32 k = strlen(line);
			if (*outLen + k + 1 > OUT_MAX) break;
			memcpy(out + *outLen, line, k);
			*outLen += k;
			out[(*outLen)++] = '\n';
		}
		return 0;
	}
	u16 w, h;
	u8 *fb = gfxGetFramebuffer(GFX_TOP, GFX_LEFT, &w, &h);
	u32 size = w * h * 3;
	if (v < size) {
		*outLen = size - v < OUT_MAX ? size - v : OUT_MAX;
		GSPGPU_InvalidateDataCache(fb + v, *outLen);
		memcpy(out, fb + v, *outLen);
	}
	return 0;
}

// --- APDU relay: the emulation on a worker thread, the PC's socket here ---

#define RELAY_WAIT_MS 10000

static struct {
	LightEvent toNet, fromNet; // an event for the PC waits / its answer (or a stop) is in
	const u8 *cmd;             // the APDU, NULL: a new session
	u32 len;
	u8 resp[0x200];
	u32 rlen; // 0: no answer
	EmuId id;
	bool idSet, ok;
} relay;

static u32 relayApdu(const u8 *cmd, u32 len, u8 *resp, u32 max)
{
	relay.cmd = cmd, relay.len = len, relay.rlen = 0;
	LightEvent_Clear(&relay.fromNet); // a late answer to the last APDU
	LightEvent_Signal(&relay.toNet);
	if (LightEvent_WaitTimeout(&relay.fromNet, MS(cmd ? RELAY_WAIT_MS : 1000)) && cmd)
		logp("relay: no answer from the PC\n");
	if (!cmd || relay.rlen > max) return 0;
	memcpy(resp, relay.resp, relay.rlen);
	return relay.rlen;
}

static void relayThread(void *arg)
{
	relay.ok = emuRun(relay.idSet ? &relay.id : NULL, relayApdu);
}

static Result handleRelay(int fd, const u8 *in, u32 inLen, u8 *out, u16 *outLen)
{
	relay.idSet = inLen > 1;
	if (relay.idSet) {
		u32 n = in[1];
		if ((n != 4 && n != 7 && n != 10) || inLen != 2 + n + 3) return -3;
		memcpy(relay.id.uid, in + 2, n);
		relay.id.uidLen = n;
		memcpy(relay.id.atqa, in + 2 + n, 2);
		relay.id.sak = in[2 + n + 2];
	}
	LightEvent_Init(&relay.toNet, RESET_ONESHOT);
	LightEvent_Init(&relay.fromNet, RESET_ONESHOT);
	mfCancel = false;
	Thread t = threadCreate(relayThread, NULL, 0x8000, 0x30, -2, false);
	if (!t) return -1;
	bool waiting = false, alive = true; // an APDU at the PC
	while (alive) {
		if (LightEvent_TryWait(&relay.toNet)) {
			alive = sendReply(fd, OP_RELAY, 1, relay.cmd, relay.cmd ? relay.len : 0);
			if (relay.cmd) waiting = true;
			else LightEvent_Signal(&relay.fromNet);
			continue;
		}
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int r = poll(&pfd, 1, 2);
		if (r < 0 || netQuit) break;
		if (!r) continue;
		static u8 msg[3 + 1 + sizeof(relay.resp)];
		if (!recvAll(fd, msg, 3)) break;
		u32 len = msg[1] | (msg[2] << 8);
		if (msg[0] != OP_RELAY || len < 1 || len > sizeof(msg) - 3 || !recvAll(fd, msg + 3, len)) break;
		if (msg[3] == 2) break;
		if (msg[3] == 1 && waiting) {
			relay.rlen = len - 1;
			memcpy(relay.resp, msg + 4, relay.rlen);
			waiting = false;
			LightEvent_Signal(&relay.fromNet);
		}
	}
	mfCancel = true;
	LightEvent_Signal(&relay.fromNet);
	threadJoin(t, U64_MAX);
	threadFree(t);
	mfCancel = false;
	u32 st[3] = { emu.fields, emu.sessions, emu.apdus };
	memcpy(out, st, sizeof(st));
	*outLen = sizeof(st);
	return relay.ok ? 0 : -1;
}

static Result handleUpdate(u8 op, const u8 *in, u32 inLen)
{
	char tmp[sizeof(appPath) + 4];
	snprintf(tmp, sizeof(tmp), "%s.new", appPath);
	if (inLen < 4) return -3;
	u32 n;
	memcpy(&n, in, 4);
	if (op == OP_UPDATE) {
		FILE *f = fopen(tmp, n ? "r+b" : "wb");
		if (!f) return -5;
		bool ok = !fseek(f, n, SEEK_SET) && fwrite(in + 4, 1, inLen - 4, f) == inLen - 4;
		return fclose(f) || !ok ? -5 : 0;
	}
	struct stat st;
	if (stat(tmp, &st) || st.st_size != n) return -6;
	remove(appPath);
	if (rename(tmp, appPath)) return -5;
	logp("net: app updated (%lu bytes), restarting\n", n);
	restartRequested = true;
	return 0;
}

static Result handlePutFile(const u8 *in, u32 inLen)
{
	if (inLen < 5 || inLen < 5u + in[4]) return -3;
	u32 off;
	memcpy(&off, in, 4);
	char path[256];
	memcpy(path, in + 5, in[4]);
	path[in[4]] = 0;
	if (strncmp(path, APP_DIR "/", strlen(APP_DIR "/")) || strstr(path, "..")) return -3;
	// its directories first
	for (char *p = path + strlen(APP_DIR "/"); (p = strchr(p, '/')); p++) {
		*p = 0;
		mkdir(path, 0777);
		*p = '/';
	}
	FILE *f = fopen(path, off ? "r+b" : "wb");
	if (!f) return -5;
	u32 n = inLen - 5 - in[4];
	bool ok = !fseek(f, off, SEEK_SET) && fwrite(in + 5 + in[4], 1, n, f) == n;
	return fclose(f) || !ok ? -5 : 0;
}

// Handles one request; out/outLen is the reply payload.
static Result handle(u8 op, const u8 *in, u32 inLen, u8 *out, u16 *outLen)
{
	*outLen = 0;
	if (op == OP_PING) {
		memcpy(out, "Prox3DS", 7);
		*outLen = 7;
		return 0;
	}
	if (op == OP_UPDATE || op == OP_UPDATE_DONE) return handleUpdate(op, in, inLen);
	if (op == OP_PUT_FILE) return handlePutFile(in, inLen);
	if (op == OP_TAKEOVER) return chipEnsure() ? 0 : -1;
	if (op == OP_RELEASE) {
		if (irqEvent) chipRelease();
		nfchwExit();
		return 0;
	}
	if (op >= OP_14A_START) {
		if (!chipEnsure()) return -2;
		return handleCard(op, in, inLen, out, outLen);
	}
	if (!irqEvent) return -2; // TAKEOVER first

	switch (op) {
	case OP_POWER:
		if (inLen < 1) return -3;
		return in[0] ? chipPowerUp() : gpioNfcSetData(0, NFC_GPIO_REG_PU);
	case OP_WRITE:
		return i2cNfcWrite(in, inLen);
	case OP_XFER:
	case OP_READ: {
		if (inLen < 2) return -3;
		u32 timeout = in[0] | (in[1] << 8);
		if (op == OP_XFER) {
			Result res = i2cNfcWrite(in + 2, inLen - 2);
			if (R_FAILED(res)) return res;
		}
		*outLen = readPacket(out, 4 + 0x100, timeout);
		return 0;
	}
	case OP_GPIO: {
		if (inLen < 8) return -3;
		u32 value, mask, data = 0;
		memcpy(&value, in, 4);
		memcpy(&mask, in + 4, 4);
		if (mask) {
			Result res = gpioNfcSetData(value, mask);
			if (R_FAILED(res)) return res;
		}
		Result res = gpioNfcGetData(NFC_GPIO_REG_PU | NFC_GPIO_WAKE | NFC_GPIO_IRQ, &data); // all-ones mask is rejected (E0E033EA)
		memcpy(out, &data, 4);
		*outLen = 4;
		return res;
	}
	}
	return -4; // unknown op
}

volatile bool netCardOp; // a network request is using the chip

static void serveClient(int fd)
{
	static u8 in[0x8000], out[OUT_MAX];
	for (;;) {
		u8 hdr[3];
		if (!recvAll(fd, hdr, 3)) return;
		u32 len = hdr[1] | (hdr[2] << 8);
		if (len > sizeof(in) || !recvAll(fd, in, len)) return;
		u16 outLen = 0;
		Result res;
		if (hdr[0] == OP_SHOT || hdr[0] == OP_KEYS || hdr[0] == OP_LOG) {
			res = handleDebug(hdr[0], in, len, out, &outLen);
		} else if (hdr[0] == OP_PING || hdr[0] == OP_UPDATE || hdr[0] == OP_UPDATE_DONE || hdr[0] == OP_PUT_FILE) {
			// no chip access: these answer while a job runs (an emulation holds hwLock until stopped), every
			// client starts with a ping
			res = handle(hdr[0], in, len, out, &outLen);
		} else if (hdr[0] == OP_RELAY) {
			LightLock_Lock(&hwLock);
			res = len && in[0] == 0 && chipEnsure() ? handleRelay(fd, in, len, out, &outLen) : -3;
			LightLock_Unlock(&hwLock);
		} else {
			LightLock_Lock(&hwLock);
			mfCancel = false, netCardOp = true; // B on the 3DS stops it (app.c), as for a job
			res = handle(hdr[0], in, len, out, &outLen);
			netCardOp = false, mfCancel = false;
			LightLock_Unlock(&hwLock);
		}
		if (!sendReply(fd, hdr[0], res, out, outLen)) return;
	}
}

static void netMain(void *arg)
{
	while (!netQuit) {
		struct sockaddr_in client;
		socklen_t clen = sizeof(client);
		if (!waitReadable(listenFd)) continue;
		int fd = accept(listenFd, (struct sockaddr *)&client, &clen);
		if (fd < 0) {
			svcSleepThread(MS(100));
			continue;
		}
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
		logp("net: client %s\n", inet_ntoa(client.sin_addr));
		serveClient(fd);
		close(fd);
		if (card.active) { // a card op left the field on: off, or the touchscreen stays dead
			LightLock_Lock(&hwLock);
			chipIdle();
			LightLock_Unlock(&hwLock);
		}
		logp("net: client gone\n");
	}
}

void netStart(void)
{
	socBuf = memalign(0x1000, SOC_BUFFERSIZE);
	if (!socBuf || R_FAILED(socInit(socBuf, SOC_BUFFERSIZE))) {
		logp("net: socInit failed (no wifi?)\n");
		free(socBuf);
		socBuf = NULL;
		return;
	}
	listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(NET_PORT), .sin_addr.s_addr = INADDR_ANY };
	if (listenFd < 0 || bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) || listen(listenFd, 1)) {
		logp("net: can't listen on %d\n", NET_PORT);
		return;
	}
	fcntl(listenFd, F_SETFL, fcntl(listenFd, F_GETFL, 0) | O_NONBLOCK);
	struct in_addr ip = { .s_addr = gethostid() };
	snprintf(netAddr, sizeof(netAddr), "%s:%d", inet_ntoa(ip), NET_PORT);
	logp("net: listening on %s\n", netAddr);
	netThread = threadCreate(netMain, NULL, 0x8000, 0x30, -2, false);
}

void netStop(void)
{
	if (!socBuf) return;
	netQuit = true;
	// The thread notices within 100 ms, or once a request still running on the chip is done.
	if (netThread) threadJoin(netThread, U64_MAX), threadFree(netThread);
	if (listenFd >= 0) close(listenFd);
	socExit();
	free(socBuf);
	socBuf = NULL;
}
