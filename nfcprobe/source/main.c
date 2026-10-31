// nfcprobe: probe of the New3DS NFC controller (BCM20791B5).
// Kills the nfc sysmodule, takes over its GPIO/I2C, and either just queries the
// controller or loads our own patch (chip/memrw.c) and runs card operations through it.
// Reboot afterwards to get the nfc sysmodule back.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "nfchw.h"
#include "mfc.h"
#include "probe.h"

#define LOG_PATH     "sdmc:/nfcprobe.log"
#define MS(x)        ((s64)(x) * 1000000LL)

static FILE *logFile;

void logp(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	if (logFile) {
		va_start(va, fmt);
		vfprintf(logFile, fmt, va);
		va_end(va);
		fflush(logFile);
	}
}

static void logHex(const char *prefix, const u8 *buf, u32 len)
{
	logp("%s", prefix);
	for (u32 i = 0; i < len; i++) {
		if (i && (i % 16) == 0) logp("\n%*s", (int)strlen(prefix), "");
		logp("%02X ", buf[i]);
	}
	logp("\n");
}

static void logAscii(const u8 *buf, u32 len)
{
	logp("  ascii: ");
	for (u32 i = 0; i < len; i++) logp("%c", (buf[i] >= 0x20 && buf[i] < 0x7F) ? buf[i] : '.');
	logp("\n");
}

u32 irqLevel(void)
{
	u32 v = 0;
	if (R_FAILED(gpioNfcGetData(NFC_GPIO_IRQ, &v))) return 0xFFFFFFFF;
	return (v & NFC_GPIO_IRQ) ? 1 : 0;
}

Handle irqEvent; // our own binding of NFC_GPIO_IRQ, replacing the dead module's

// Reads one NCI packet (HCIT 0x10 + 3 byte header, then payload) or BT HCI event
// (HCIT 0x04 + 2 byte header, then payload). Without our IRQ binding it polls: reads while
// the controller has nothing return FF FF FF FF; those are retried silently.
// Returns total length incl. HCIT, 0 on timeout (~20 ms per try).
u32 nciRecv(u8 *pkt, u32 maxLen, int tries, bool verbose)
{
	Result lastErr = 0;
	int errs = 0, empty = 0;
	for (int t = 0; t < tries; t++) {
		// With the IRQ ours, read only while the chip signals a pending packet: a read racing
		// with the chip queueing its next packet loses that packet (one monitor reply every
		// ~5-10 s while polling blind).
		if (irqEvent && irqLevel() == 0) {
			svcWaitSynchronization(irqEvent, MS(20));
			if (irqLevel() == 0) {
				empty++;
				continue;
			}
		}
		Result res = i2cNfcRead(pkt, 4);
		if (R_FAILED(res)) {
			errs++;
			lastErr = res;
		} else if (pkt[0] == HCI_HCIT_EVT) {
			// 4 bytes read = HCIT, event code, length, first payload byte.
			u32 len = pkt[2];
			if (3 + len > maxLen) len = maxLen - 3;
			if (len > 1) {
				res = i2cNfcRead(pkt + 4, len - 1);
				if (R_FAILED(res)) logp("  rd payload (%lu): res=%08lX\n", len - 1, res);
			}
			return 3 + (len ? len : 1);
		} else if (pkt[0] != NCI_HCIT) {
			empty++;
		} else {
			u32 len = pkt[3];
			if (4 + len > maxLen) len = maxLen - 4;
			if (len) {
				res = i2cNfcRead(pkt + 4, len);
				if (R_FAILED(res)) logp("  rd payload (%lu): res=%08lX\n", len, res);
			}
			return 4 + len;
		}
	}
	if (verbose) logp("  nothing: %d empty reads, %d errors (last %08lX), irq=%ld\n", empty, errs, lastErr, irqLevel());
	return 0;
}

static void nciSend(const char *name, const u8 *pkt, u32 len)
{
	logp("> %s\n", name);
	logHex("  tx: ", pkt, len);
	Result res = i2cNfcWrite(pkt, len);
	if (R_FAILED(res)) logp("  write failed: %08lX\n", res);
}

static void describe(const u8 *pkt, u32 len)
{
	if (len < 4) return;
	if (pkt[0] == HCI_HCIT_EVT) {
		logp("  HCI event %02X len %u", pkt[1], pkt[2]);
		if (pkt[1] == 0x0E && len >= 7) logp(" cmd complete opcode %04X status %02X", pkt[4] | (pkt[5] << 8), pkt[6]);
		logp("\n");
		return;
	}
	u8 mt = pkt[1] >> 5, gid = pkt[1] & 0xF, oid = pkt[2] & 0x3F;
	const u8 *p = pkt + 4;
	u32 plen = len - 4;
	static const char *mts[] = { "DATA", "CMD", "RSP", "NTF" };
	logp("  %s gid=%X oid=%02X len=%lu\n", mt < 4 ? mts[mt] : "?", gid, oid, plen);

	if (mt == 2 && gid == 0 && oid == 0 && plen >= 3)
		logp("  CORE_RESET_RSP status=%02X nci_ver=%X.%X cfg=%02X\n", p[0], p[1] >> 4, p[1] & 0xF, p[2]);
	else if (mt == 3 && gid == 0 && oid == 0)
		logAscii(p, plen);
	else if (mt == 2 && gid == 0 && oid == 1 && plen >= 6) {
		logp("  CORE_INIT_RSP status=%02X features=%02X%02X%02X%02X n_ifaces=%u\n",
			p[0], p[1], p[2], p[3], p[4], p[5]);
		u32 o = 6 + p[5];
		if (o + 10 <= plen)
			logp("  max_conns=%u max_route=%u max_ctrl_payload=%u max_large_param=%u\n"
				"  manuf_id=%02X manuf_info=%02X %02X %02X %02X\n",
				p[o], p[o + 1] | (p[o + 2] << 8), p[o + 3], p[o + 4] | (p[o + 5] << 8),
				p[o + 6], p[o + 7], p[o + 8], p[o + 9], p[o + 10]);
	} else if (gid == 0xF && oid == 0x2D && mt == 2 && plen >= 24) {
		logp("  PATCH_VERSION status? proj=%04X chip=%.16s ver=%u.%u\n",
			p[0] | (p[1] << 8), (const char *)p + 4, p[20] | (p[21] << 8), p[22] | (p[23] << 8));
	} else if (gid == 0xF && oid == 0x2E)
		logp("  SPD %s status=%02X\n", mt == 2 ? "rsp" : "ntf", plen ? p[0] : 0xFF);
	else if (gid == 0xF)
		logAscii(p, plen);
}

static void exchange(const char *name, const u8 *cmd, u32 cmdLen)
{
	u8 pkt[4 + 0x100];
	nciSend(name, cmd, cmdLen);
	svcSleepThread(MS(30));
	// Collect the response plus any notifications that follow it.
	for (int n = 0; n < 4; n++) {
		u32 len = nciRecv(pkt, sizeof(pkt), n == 0 ? 25 : 5, n == 0);
		if (!len) {
			if (n == 0) logp("  no response\n");
			break;
		}
		logHex("  rx: ", pkt, len);
		describe(pkt, len);
	}
}

// Logs before a call so a hang shows exactly which call never returned.
#define STEP(what, call) ({ logp("  .. %s\n", what); Result _r = (call); logp("  %s: %08lX\n", what, _r); _r; })

// Luma3DS extends svcGetProcessInfo: 0x10000 = process name, 0x10001 = title ID.
// Finds a process by name. The New3DS nfc module (0004013020004002 on NAND) runs
// as program ID 0004013000004002, so look up the live title ID instead of hardcoding it.
static bool findProcess(const char *want, u32 *pid, u64 *tid)
{
	u32 pids[64];
	s32 n = 0;
	if (R_FAILED(svcGetProcessList(&n, pids, 64))) return false;
	for (s32 i = 0; i < n; i++) {
		Handle h;
		char name[9] = { 0 };
		if (R_FAILED(svcOpenProcess(&h, pids[i]))) continue;
		svcGetProcessInfo((s64 *)name, h, 0x10000);
		svcGetProcessInfo((s64 *)tid, h, 0x10001);
		svcCloseHandle(h);
		if (!strcmp(name, want)) {
			*pid = pids[i];
			return true;
		}
	}
	return false;
}

static u64 nfcTid; // program ID of the nfc module we killed, to relaunch it on exit

void stepTerminate(void)
{
	u32 pid;
	u64 tid;
	if (!findProcess("nfc", &pid, &tid)) {
		logp("nfc not running\n");
		return;
	}
	logp("nfc: pid %lu tid %016llX\n", pid, tid);
	nfcTid = tid;
	STEP("pmAppInit", pmAppInit());
	STEP("PMAPP_TerminateTitle(nfc)", PMAPP_TerminateTitle(tid, MS(3000)));
	logp("  .. pmAppExit\n");
	pmAppExit();
	logp("  pmAppExit done\n");

	u32 pid2;
	if (findProcess("nfc", &pid2, &tid) && pid2 == pid) {
		Handle h;
		logp("nfc still alive, killing pid %lu directly\n", pid);
		if (R_SUCCEEDED(STEP("svcOpenProcess", svcOpenProcess(&h, pid)))) {
			STEP("svcTerminateProcess", svcTerminateProcess(h));
			svcCloseHandle(h);
		}
	}
	svcSleepThread(MS(500));
}

bool stepOpen(int tries)
{
	Result resGpio = -1, resI2c = -1;
	for (int t = 0; t < tries; t++) {
		if (R_FAILED(resGpio)) resGpio = STEP("open gpio:NFC", nfchwOpenGpio());
		if (R_FAILED(resI2c)) resI2c = STEP("open i2c::NFC", nfchwOpenI2c());
		if (R_SUCCEEDED(resGpio) && R_SUCCEEDED(resI2c)) return true;
		svcSleepThread(MS(200));
	}
	return false;
}

static const u8 coreReset[] = { NCI_HCIT, 0x20, 0x00, 0x01, 0x01 }; // reset config
static const u8 coreInit[]  = { NCI_HCIT, 0x20, 0x01, 0x00 };
static const u8 patchVer[]  = { NCI_HCIT, 0x2F, 0x2D, 0x00 };       // Broadcom GET_PATCH_VERSION

static void drain(const char *what)
{
	u8 pkt[4 + 0x100];
	logp("> drain (%s)\n", what);
	for (int n = 0; n < 8; n++) {
		u32 len = nciRecv(pkt, sizeof(pkt), 5, n == 0);
		if (!len) break;
		logHex("  rx: ", pkt, len);
		describe(pkt, len);
	}
}

void chipTakeover(void)
{
	// The killed module left its event bound to the IRQ pin; gpio crashes signalling it.
	// Mask the interrupt, drop the stale binding and bind our own event instead.
	STEP("irq mask off", gpioNfcSetInterruptMask(0, NFC_GPIO_IRQ));
	STEP("create event", svcCreateEvent(&irqEvent, RESET_ONESHOT));
	STEP("unbind stale irq", gpioNfcUnbindInterrupt(NFC_GPIO_IRQ, irqEvent));
	STEP("bind irq", gpioNfcBindInterrupt(NFC_GPIO_IRQ, irqEvent, 8));
	STEP("irq mask on", gpioNfcSetInterruptMask(NFC_GPIO_IRQ, NFC_GPIO_IRQ));

	// Same pin directions as the module's GPIO init: REG_PU/WAKE out, IRQ in.
	STEP("dir out", gpioNfcSetDirection(NFC_GPIO_REG_PU | NFC_GPIO_WAKE, NFC_GPIO_REG_PU | NFC_GPIO_WAKE));
	STEP("dir in", gpioNfcSetDirection(0, NFC_GPIO_IRQ));
}

// Power cycle like the module's boot path: REG_PU low -> high, 50 ms settle; WAKE asserted (low).
static void chipPowerCycle(void)
{
	STEP("reg_pu low", gpioNfcSetData(0, NFC_GPIO_REG_PU));
	svcSleepThread(MS(20));
	STEP("wake low", gpioNfcSetData(0, NFC_GPIO_WAKE));
	STEP("reg_pu high", gpioNfcSetData(NFC_GPIO_REG_PU, NFC_GPIO_REG_PU));
	svcSleepThread(MS(100));
	drain("after power-up");
}

// Quiet power cycle for the network server and the monitor loader.
Result chipPowerUp(void)
{
	Result res = gpioNfcSetData(0, NFC_GPIO_REG_PU);
	svcSleepThread(MS(20));
	if (R_SUCCEEDED(res)) res = gpioNfcSetData(0, NFC_GPIO_WAKE);
	if (R_SUCCEEDED(res)) res = gpioNfcSetData(NFC_GPIO_REG_PU, NFC_GPIO_REG_PU);
	svcSleepThread(MS(100));
	return res;
}

// Kill the nfc module and take its pins, unless we own the chip already.
bool chipEnsure(void)
{
	if (irqEvent) return true;
	stepTerminate();
	if (!stepOpen(5)) return false;
	chipTakeover();
	return true;
}

// Back to the system's state: pins released (a dangling IRQ binding takes gpio down with it once
// our event is gone) and the nfc module running again (the HOME menu and other processes talk to
// it, and hang while it is missing).
static void chipGiveBack(void)
{
	if (irqEvent) chipRelease();
	nfchwExit();
	if (!nfcTid) return;
	u32 pid;
	u64 tid;
	if (findProcess("nfc", &pid, &tid)) return;
	FS_ProgramInfo pi = { .programId = nfcTid, .mediaType = MEDIATYPE_NAND };
	if (R_SUCCEEDED(pmAppInit())) {
		logp("  .. relaunch nfc %016llX\n", nfcTid);
		Result res = PMAPP_LaunchTitle(&pi, 0);
		logp("relaunch nfc %016llX: %08lX\n", nfcTid, res);
		pmAppExit();
	}
}

static void chipInfo(void)
{
	exchange("CORE_RESET", coreReset, sizeof(coreReset));
	exchange("CORE_INIT", coreInit, sizeof(coreInit));
	exchange("GET_PATCH_VERSION", patchVer, sizeof(patchVer));
}

// Leave the pins like the module's shutdown path, and gpio without a binding.
void chipRelease(void)
{
	STEP("reg_pu low (power off)", gpioNfcSetData(0, NFC_GPIO_REG_PU));
	STEP("irq mask off", gpioNfcSetInterruptMask(0, NFC_GPIO_IRQ));
	STEP("unbind irq", gpioNfcUnbindInterrupt(NFC_GPIO_IRQ, irqEvent));
	svcCloseHandle(irqEvent);
	irqEvent = 0;
}

// Sends an SPD patch (.ncd: pre-framed "10 2F 2E len type ..." records) record by record,
// like AOSP nfc_hal_prm: each record must get a 4F 2E response with status 0; after the
// signature record the controller reports authentication and then resets.
bool spdDownload(const u8 *ncd, u32 size, bool verbose)
{
	u8 pkt[4 + 0x100];
	int rec = 0;
	for (u32 o = 0; o + 5 <= size; rec++) {
		u32 len = 4 + ncd[o + 3];
		u8 type = ncd[o + 4];
		Result res = i2cNfcWrite(ncd + o, len);
		if (R_FAILED(res)) {
			if (verbose) logp("  rec %d: write failed %08lX\n", rec, res);
			return false;
		}
		int status = -1;
		for (int n = 0; n < 4 && status < 0; n++) {
			u32 rlen = nciRecv(pkt, sizeof(pkt), 50, verbose);
			if (!rlen) break;
			if (pkt[1] == 0x4F && (pkt[2] & 0x3F) == 0x2E && rlen >= 5) {
				status = pkt[4];
				if (verbose && rlen > 5) logHex("  rsp: ", pkt, rlen);
			} else if (verbose) {
				logHex("  other: ", pkt, rlen);
				describe(pkt, rlen);
			}
		}
		if (verbose || status) logp("  rec %2d type %02X len %3lu -> status %d\n", rec, type, len - 5, status);
		if (status != 0) return false;
		o += len;
	}

	// Authentication result and reset notification (B4+ resets after a good patch).
	if (verbose) logp("> waiting for auth/reset\n");
	for (int n = 0; n < 8; n++) {
		u32 rlen = nciRecv(pkt, sizeof(pkt), 100, verbose && n == 0);
		if (!rlen) break;
		if (verbose) {
			logHex("  rx: ", pkt, rlen);
			describe(pkt, rlen);
		}
		if (pkt[1] == 0x60 && pkt[2] == 0x00) break; // reset notification ends the download
	}
	return true;
}

enum { JOB_PROBE, JOB_SCAN, JOB_MF_DUMP };
static const char *jobNames[] = { "probe", "scan", "Mifare Classic dump" };

LightLock hwLock; // held by a job or a network request while it touches the chip
static volatile bool jobRunning;

static bool scanCard(void)
{
	logp("hold a card to the touch screen...\n");
	if (!iso14aStart()) {
		logp("no card\n");
		return false;
	}
	logp("ATQA %02X%02X SAK %02X UID ", card.atqa[1], card.atqa[0], card.sak);
	for (int i = 0; i < card.uidLen; i++) logp("%02X", card.uid[i]);
	logp("\n");
	return true;
}

static void runMfDump(void)
{
	static MfDump d;
	static u8 keys[MF_MAX_KEYS][6];
	if (!scanCard()) return;
	int sectors = mfSectorsFromSak(card.sak);
	int nkeys = mfKeyList(keys, MF_MAX_KEYS, NULL, 0);
	logp("%d sectors, %d keys (defaults + %s)\n", sectors, nkeys, MF_KEYS);
	int got = mfDumpCard(&d, sectors, (const u8 (*)[6])keys, nkeys);
	iso14aParity(true);
	if (got < 0) {
		logp("card lost\n");
		return;
	}
	char path[64];
	logp("%d/%d blocks read\n", got, mfFirstBlock(sectors));
	if (got && mfSaveDump(&d, path, sizeof(path))) logp("saved %s\n", path);
}

// Card jobs keep the chip (and the loaded monitor) so the network side can carry on with it;
// the probe starts from a fresh takeover and gives it back.
static void jobThread(void *arg)
{
	int job = (int)arg;
	logFile = fopen(LOG_PATH, "a");
	logp("--- nfcprobe: %s ---\n", jobNames[job]);
	LightLock_Lock(&hwLock);
	if (job == JOB_SCAN || job == JOB_MF_DUMP) {
		if (chipEnsure()) {
			if (job == JOB_SCAN) scanCard();
			else runMfDump();
		}
	} else {
		if (irqEvent) chipRelease(); // a network client still had the chip
		nfchwExit();
		stepTerminate();
		if (stepOpen(5)) {
			chipTakeover();
			chipPowerCycle();
			chipInfo();
			chipRelease();
		}
		nfchwExit();
	}
	LightLock_Unlock(&hwLock);
	logp("--- done ---\n");
	if (logFile) fclose(logFile);
	logFile = NULL;
	jobRunning = false;
}

int main(int argc, char *argv[])
{
	gfxInitDefault();
	consoleInit(GFX_TOP, NULL);

	printf("nfcprobe - BCM20791B5\n");
	printf("HOME/sleep are off while running; exit with START.\n\n");
	printf("A: scan card\n");
	printf("X: dump Mifare Classic (keys: defaults + %s)\n", MF_KEYS);
	printf("L+A: chip probe   START: exit\n");
	printf("log: %s\n\n", LOG_PATH);

	LightLock_Init(&hwLock);
	netStart();
	// While we own the chip the nfc module is gone, and the HOME menu hangs waiting for it.
	aptSetHomeAllowed(false);
	aptSetSleepAllowed(false);

	Thread worker = NULL;
	while (aptMainLoop()) {
		gspWaitForVBlank();
		gfxSwapBuffers();
		hidScanInput();
		if (aptCheckHomePressRejected()) printf("HOME is off while NFC is ours: START to exit\n");
		u32 kDown = hidKeysDown();
		if (kDown & KEY_START) break;
		if (jobRunning) continue;
		int job = -1;
		if (hidKeysHeld() & KEY_L)
			job = (kDown & KEY_A) ? JOB_PROBE : -1;
		else
			job = (kDown & KEY_A) ? JOB_SCAN : (kDown & KEY_X) ? JOB_MF_DUMP : -1;
		if (job < 0) continue;
		if (worker) threadJoin(worker, U64_MAX), threadFree(worker);
		jobRunning = true;
		worker = threadCreate(jobThread, (void *)job, 0x8000, 0x30, -2, false);
	}

	printf("exiting: giving NFC back...\n");
	gfxSwapBuffers();
	gspWaitForVBlank();
	netStop();
	// A worker stuck in IPC can't be joined; only clean up a finished one.
	for (int i = 0; i < 100 && jobRunning; i++) svcSleepThread(MS(100));
	if (worker && !jobRunning) threadJoin(worker, U64_MAX), threadFree(worker);
	logFile = fopen(LOG_PATH, "a");
	logp("--- exit: net stopped, job %s ---\n", jobRunning ? "STILL RUNNING" : "done");
	LightLock_Lock(&hwLock);
	chipGiveBack();
	logp("--- exit: NFC given back ---\n");
	LightLock_Unlock(&hwLock);
	if (logFile) fclose(logFile);
	logFile = NULL;
	aptSetHomeAllowed(true);
	aptSetSleepAllowed(true);
	gfxExit();
	return 0;
}
