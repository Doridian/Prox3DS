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

#include "desfire.h"
#include "mfc.h"
#include "isodep.h"
#include "mfu.h"
#include "nfchw.h"
#include "probe.h"
#include "ui.h"

#define SOC_BUFFERSIZE 0x100000
#define MS(x)          ((s64)(x) * 1000000LL)

enum {
	OP_PING     = 0x00, // -> "nfcprobe"
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
	                      // payload = reason. Encrypted WRITE (NOTES.md). WRITES THE CARD
	OP_MF_NESTED  = 0x17, // knownBlock u8, knownKeyB u8, knownKey[6], tgtBlock u8, tgtKeyB u8
	                      // -> recovered key[6]; on failure payload = reason (nested attack, NOTES.md)
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
		if (!card.active && !iso14aStart()) return 1;
		if (!in[0] && iso14aSelect() < 0 && !iso14aStart()) return 1; // current SAK
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
		if (!card.active && !iso14aStart()) return 1;
		int r = mfGen1aWrite(in[0], in + 1);
		iso14aParity(true);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_WRITE: {
		if (inLen < 24) return -3;
		if (!card.active && !iso14aStart()) return 1;
		int r = mfWrite(in[0], in + 2, in[1], in + 8);
		iso14aParity(true);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MF_MAGIC: {
		if (inLen < 1) return -3;
		if (!card.active && !iso14aStart()) return 1;
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
		if (!card.active && !iso14aStart()) return 1;
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
		if (!card.active && !iso14aStart()) return 1;
		int r = mfGen4Write(in, in[4], in + 5);
		if (r == 1) return 0; // verified
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_GEN4_CONFIG: {
		if (inLen != 4 && inLen != 4 + MF_GEN4_CFG) return -3;
		if (!card.active && !iso14aStart()) return 1;
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
		if (!card.active && !iso14aStart()) return 1;
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
		if (!card.active && !iso14aStart()) return 1;
		int r = mfCloneToMagic((const u8 (*)[16])data, valid, nb, in[0]);
		iso14aParity(true);
		if (r == 1) return 0;
		*outLen = strlen(mfWhy());
		memcpy(out, mfWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MFU_DUMP: {
		static MfuDump d;
		u8 key[16] = { 0 };
		if (inLen != 0 && inLen != 4 && inLen != 16) return -3;
		memcpy(key, in, inLen);
		if (!card.active && !iso14aStart()) return 1;
		if (iso14aSelect() < 0 && !iso14aStart()) return 1;
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
		if (!card.active && !iso14aStart()) return 1;
		MfuInfo info;
		int r = iso14aSelect() < 0 ? 0 : mfuIdentify(&info);
		if (r > 0) r = mfuWritePage(info.type, in[0], in + 1);
		if (r == 1) return 0;
		*outLen = strlen(mfuWhy());
		memcpy(out, mfuWhy(), *outLen);
		return r < 0 ? -1 : 1;
	}
	case OP_MFU_CLONE: {
		static MfuDump d;
		if (!mfuParseDump(&d, in, inLen)) return -3;
		if (!card.active && !iso14aStart()) return 1;
		if (iso14aSelect() < 0 && !iso14aStart()) return 1;
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
		if ((in[0] == 0 || in[0] == 4 || in[0] == 5) && inLen >= 4) {
			k.type = in[2];
			if (k.type > DF_AES || inLen != 3 + dfKeyLen(k.type)) return -3;
			memcpy(k.key, in + 3, dfKeyLen(k.type));
			r = in[0] == 5 ? dfAuthEv2NonFirst(in[1], &k, &st) : dfAuth(in[1], &k, in[0] == 4, &st);
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
	case OP_MF_NESTED: {
		if (inLen < 10) return -3;
		if (!card.active && !iso14aStart()) return 1;
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

// Handles one request; out/outLen is the reply payload.
static Result handle(u8 op, const u8 *in, u32 inLen, u8 *out, u16 *outLen)
{
	*outLen = 0;
	if (op == OP_PING) {
		memcpy(out, "nfcprobe", 8);
		*outLen = 8;
		return 0;
	}
	if (op == OP_UPDATE || op == OP_UPDATE_DONE) return handleUpdate(op, in, inLen);
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
		} else {
			LightLock_Lock(&hwLock);
			res = handle(hdr[0], in, len, out, &outLen);
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
