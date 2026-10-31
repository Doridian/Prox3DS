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
#include <unistd.h>

#include "mfc.h"
#include "nfchw.h"
#include "probe.h"

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
	// High-level card ops (mfc.c); they take over the chip themselves. Result 0 = ok,
	// 1 = no card / auth refused, -1 = chip monitor error.
	OP_14A_START  = 0x10, // load the monitor, activate a card -> ATQA[2] SAK uidLen uid
	OP_14A_PARITY = 0x11, // u8 on
	OP_14A_TX     = 0x12, // code u8 (0 = whole bytes), frame -> per answer: len u8, raw bytes
	OP_MF_READ    = 0x13, // block u8, keyB u8, key[6], count u8 -> per block: ok u8, data[16]
	OP_MF_DUMP    = 0x14, // sectors u8 (0 = from SAK), keys[6]... (+ keys.txt + defaults), saved to SD
	OP_GEN1A_WRITE = 0x15, // block u8, data[16] -> empty ok; on failure payload = reason. WRITES CARD
	OP_MF_WRITE   = 0x16, // block u8, keyB u8, key[6], data[16] -> empty ok (read back); on failure
	                      // payload = reason. Encrypted WRITE (NOTES.md). WRITES THE CARD
	                      // -> sectors u8, per sector: found u8 (1 = A, 2 = B) keyA[6] keyB[6],
	                      //    per block: ok u8, data[16]
};

#define OUT_MAX 0x2000

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
		int n = iso14aTx(in + 1, inLen - 1, in[0], f, 8);
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
	}
	return -4;
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
	static u8 in[0x400], out[OUT_MAX];
	for (;;) {
		u8 hdr[3];
		if (!recvAll(fd, hdr, 3)) return;
		u32 len = hdr[1] | (hdr[2] << 8);
		if (len > sizeof(in) || !recvAll(fd, in, len)) return;
		u16 outLen;
		LightLock_Lock(&hwLock);
		Result res = handle(hdr[0], in, len, out, &outLen);
		LightLock_Unlock(&hwLock);
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
		printf("net: client %s\n", inet_ntoa(client.sin_addr));
		serveClient(fd);
		close(fd);
		printf("net: client gone\n");
	}
}

void netStart(void)
{
	socBuf = memalign(0x1000, SOC_BUFFERSIZE);
	if (!socBuf || R_FAILED(socInit(socBuf, SOC_BUFFERSIZE))) {
		printf("net: socInit failed (no wifi?)\n");
		free(socBuf);
		socBuf = NULL;
		return;
	}
	listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(NET_PORT), .sin_addr.s_addr = INADDR_ANY };
	if (listenFd < 0 || bind(listenFd, (struct sockaddr *)&addr, sizeof(addr)) || listen(listenFd, 1)) {
		printf("net: can't listen on %d\n", NET_PORT);
		return;
	}
	fcntl(listenFd, F_SETFL, fcntl(listenFd, F_GETFL, 0) | O_NONBLOCK);
	struct in_addr ip = { .s_addr = gethostid() };
	printf("net: listening on %s:%d\n\n", inet_ntoa(ip), NET_PORT);
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
