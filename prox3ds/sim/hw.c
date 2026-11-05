// Stand-ins for main.c (chip takeover, log, network) and mon.c (the chip monitor): no chip here, so
// every card operation fails right away. Scenes put card state in directly (hook_*.c).

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "../source/field.h"
#include "../source/mon.h"
#include "../source/probe.h"
#include "../source/ui.h"

Handle irqEvent;
LightLock hwLock = PTHREAD_MUTEX_INITIALIZER;
char appPath[256];
volatile bool restartRequested;
char netAddr[32] = "192.0.2.132:8020";
volatile u32 netKeys;
volatile bool netCardOp;

void logp(const char *fmt, ...)
{
	char s[512];
	va_list va;
	va_start(va, fmt);
	vsnprintf(s, sizeof(s), fmt, va);
	va_end(va);
	uiLogAppend(s);
}

u32 irqLevel(void) { return 0; }
u32 nciRecv(u8 *pkt, u32 maxLen, int tries, bool verbose) { return 0; }
void stepTerminate(void) {}
bool stepOpen(int tries) { return false; }
void chipTakeover(void) {}
void chipRelease(void) {}
Result chipPowerUp(void) { return -1; }
bool chipEnsure(void) { return false; }
void chipIdle(void) {}
void chipProbe(void) { logp("no chip in the simulator\n"); }
bool spdDownload(const u8 *ncd, u32 size, bool verbose) { return false; }
void netStart(void) {}
void netStop(void) {}

// The field meter: scenes set what it shows (bars -1 = none).
int simFieldBars = -1;
bool simFieldLive;
float simFieldGauge;
void fieldArm(void) {}
void fieldDisarm(void) {}
void fieldPoll(void) {}
void fieldJobEnd(void) {}
bool fieldTuneSample(void) { return false; }
void fieldCardPresent(bool present) {}
bool fieldMeasureEmpty(char *msg, u32 max) { return false; }
int fieldBars(bool *live) { if (live) *live = simFieldLive; return simFieldBars; }
float fieldGauge(bool *live) { if (live) *live = simFieldLive; return simFieldGauge; }
float fieldLevel(float *empty) { if (empty) *empty = 166; return 166 - 25 * simFieldGauge; }

bool monLoad(void) { return false; }
bool monLoadEmu(bool classic) { return false; }
int monDo(u8 op, u32 addr, const void *data, u32 len, u8 *out, u32 outMax) { return MON_NO_ANSWER; }
bool monRead(u32 addr, void *buf, u32 len) { return false; }
bool monWrite(u32 addr, const void *buf, u32 len) { return false; }
bool monWrite32(u32 addr, u32 value) { return false; }
bool monCapture(bool on) { return false; }
int monFrames(MonFrame *out, int max) { return -1; }
bool monTxraw(const u8 *data, u32 len, u8 code, u8 r570, u8 r574, u8 r55c) { return false; }
bool monTxsched(const u8 *data, u32 len, u8 code, const MonStore *st, u32 n) { return false; }
bool monTxschedRegs(const u8 *data, u32 len, u8 code, u8 r570, u8 r574, u8 r55c, const MonStore *st, u32 n) { return false; }
int monAuth(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code, u32 nrarTx, u32 *nt, u32 *odd,
	u32 *even) { return -1; }
int monChkKeys(const u8 *arg, u32 len, u32 nrarTx, u8 out[3]) { return -1; }
int monDarkside(const u8 *arg, u32 len, u32 nrarTx, int nslot, u8 *out) { return -1; }
int monNested(const u8 key[6], u32 uid, u32 nr, const u8 *frame, u32 flen, u8 code, const u8 nestedCmd[4],
	u32 nrarTx, u32 *nt0) { return -1; }

Result i2cNfcWrite(const void *buf, u32 size) { return -1; }

// main.c's progress state, without a clock (osGetTime is 0 here): scenes set prog directly
Progress prog;

void progJob(void)
{
	memset(&prog, 0, sizeof(prog));
}

void progOp(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vsnprintf(prog.op, sizeof(prog.op), fmt, va);
	va_end(va);
	prog.done = prog.total = prog.eta = 0;
}

void progEta(u32 done, u32 total, u32 etaMs)
{
	prog.done = done, prog.total = total, prog.eta = etaMs;
}

void progStep(u32 done, u32 total)
{
	progEta(done, total, 0);
}

u32 progLeft(void)
{
	return prog.eta;
}
