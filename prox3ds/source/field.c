// Field level meter: the carrier amplitude at the RX, the way the ROM's ANTENNA_SELF_TEST (2F 10,
// 0x1A374 -> 0x1E3C8) measures it: field on, then the sum of I^2 + Q^2 over a few reads of one of three
// I/Q readouts (0xD87A / 0xD88A / 0xD8B0). We use the 10-bit one, 0x5C420-0x5C42C = I hi, I lo, Q hi,
// Q lo (each - 1024), and check it against the 8-bit one at 0x5C454 / 0x5C458 (each - 128, 1/8 scale):
// with the field off or the RF block down they disagree (junk), with the field on they match.
//
// The phase of the I/Q vector is random per field-on (each power-up and every 0x5C360 toggle picks
// another), so only its length tells anything. Around a fixed DC offset (~ +1, +8 here): measured by
// toggling the field ~14 times and fitting a circle to the points (radius sd ~1.5). A card on the
// reader loads the field and shortens the vector: empty 166, an NTAG well placed 145-150, badly 160,
// a bigger card down to ~90
// (docs/NOTES.md, tools/exp/rssi/). Bars = how much shorter than the empty field (learned: the
// largest steady reading seen, which is the field with nothing on it), like the pm3's volts dropping.

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "field.h"
#include "mfc.h"
#include "mon.h"
#include "probe.h"

#define FIELD_FILE APP_DIR "/field.txt" // "offI offQ empty", learned
#define POLL_MS    250
#define SHOW_MS    10000 // the last reading stays (dim) this long after the field went off
#define LIVE_MS    1500
#define EMPTY_MIN  130.0f // plausible empty levels (166 on the test console)
#define EMPTY_MAX  210.0f
#define DEADZONE   8.0f  // loading that is just the empty field drifting
#define FULL_LOAD  85.0f // the gauge's full scale, in vector length below the empty field

static float offI = 1.3f, offQ = 7.6f, empty = 166.0f; // the test console's values until learned
static bool loaded, calibrated, dirty, inPoll;
static volatile bool armed;
static float level; // smoothed vector length, 0 = no reading since armed
static float med[5];
static int medN;
static volatile int bars = -1;
static volatile float loadFrac;
static volatile u32 lastMs;

static u32 nowMs(void)
{
	return (u32)osGetTime();
}

static void load(void)
{
	if (loaded) return;
	loaded = true;
	FILE *f = fopen(FIELD_FILE, "r");
	if (!f) return;
	float a, b, c;
	if (fscanf(f, "%f %f %f", &a, &b, &c) == 3 && fabsf(a) < 40 && fabsf(b) < 40 && c >= EMPTY_MIN && c <= EMPTY_MAX) {
		offI = a;
		offQ = b;
		empty = c;
	}
	fclose(f);
}

static void save(void)
{
	if (!dirty) return;
	dirty = false;
	mkdir(APP_DIR, 0777);
	FILE *f = fopen(FIELD_FILE, "w");
	if (!f) return;
	fprintf(f, "%.2f %.2f %.2f\n", offI, offQ, empty);
	fclose(f);
}

// One raw I/Q read (offset not removed). false = no field / junk.
static bool readIQ(float *i, float *q)
{
	u8 b[15 * 4];
	u8 words = 15; // 0x5C420 .. 0x5C458
	if (monDo(MON_READ32, 0x5C420, &words, 1, b, sizeof(b)) != sizeof(b)) return false;
	u32 ih = b[0], il = b[4], qh = b[8], ql = b[12], i8 = b[13 * 4], q8 = b[14 * 4];
	if (ih > 7 || qh > 7) return false;
	float fi = (float)((ih << 8 | il)) - 1024, fq = (float)((qh << 8 | ql)) - 1024;
	// the 8-bit readout (offset-free, 1/8 scale) must agree: field-off junk doesn't
	if (fabsf(fi - offI - 8.0f * ((int)i8 - 128)) > 20 || fabsf(fq - offQ - 8.0f * ((int)q8 - 128)) > 20) return false;
	*i = fi;
	*q = fq;
	return true;
}

static void publish(void)
{
	// below DEADZONE it's the empty field drifting (166-174 between sessions, +-2 within one, nothing near:
	// the surroundings), not a card. Then a square-root scale: an NTAG well placed (16-21) about a third,
	// a big card (~72) about 90 %.
	float l = empty - level - DEADZONE;
	float fr = l > 0 ? sqrtf(l / (FULL_LOAD - DEADZONE)) : 0;
	loadFrac = fr > 1 ? 1 : fr;
	static const float steps[FIELD_BARS] = { 0.05f, 0.3f, 0.5f, 0.7f, 0.9f };
	int n = 0;
	while (n < FIELD_BARS && loadFrac >= steps[n]) n++;
	bars = n;
	lastMs = nowMs();
}

// The empty field, learned in Tuning only: the card stopped answering (lifted), then 1 s of steady
// readings within 3 s of that. Not "the largest reading ever": a pm3 lying on the 3DS (its antenna is a
// tuned 13.56 MHz coil) pushes the level both ways, 53 tight and 174 at some distance (2026-11-04).
#define HIST       64
static struct {
	float r;
	u32 t;
} hist[HIST];
static int histN;
static bool cardGone, learned;
static u32 goneAt;

static void learnEmpty(float r)
{
	u32 now = nowMs();
	hist[histN % HIST].r = r, hist[histN % HIST].t = now;
	histN++;
	if (!cardGone || learned || now - goneAt < 1000 || now - goneAt > 3000) return;
	float lo = 1e9f, hi = 0, sum = 0;
	int n = 0;
	for (int k = 0; k < HIST && k < histN; k++) {
		int i = (histN - 1 - k) % HIST;
		if (now - hist[i].t > 1000) break;
		if (hist[i].t < goneAt) return;
		lo = fminf(lo, hist[i].r), hi = fmaxf(hi, hist[i].r), sum += hist[i].r, n++;
	}
	if (n < 8 || hi - lo > 3) return;
	float e = sum / n;
	learned = true;
	if (e < EMPTY_MIN || e > EMPTY_MAX) {
		logp("field: %.0f with no card is no empty field, kept %.0f\n", e, empty);
		return;
	}
	if (fabsf(e - empty) < 1) return;
	empty = e;
	dirty = true;
	logp("field: baseline now %.0f\n", empty);
}

bool fieldMeasureEmpty(char *msg, u32 max)
{
	if (!armed) {
		snprintf(msg, max, "No field: put a card on first");
		return false;
	}
	float lo = 1e9f, hi = 0, sum = 0;
	int n = 0;
	inPoll = true;
	for (int k = 0; k < 40 && n < 25; k++) {
		float i, q;
		if (readIQ(&i, &q)) {
			float r = sqrtf((i - offI) * (i - offI) + (q - offQ) * (q - offQ));
			lo = fminf(lo, r), hi = fmaxf(hi, r), sum += r, n++;
		}
		svcSleepThread(40 * 1000000LL);
	}
	inPoll = false;
	if (n < 15) {
		snprintf(msg, max, "No steady reading: baseline kept");
		logp("field: %s\n", msg);
		return false;
	}
	float e = sum / n;
	if (hi - lo > 4) {
		snprintf(msg, max, "Not steady (%.0f-%.0f): baseline kept", lo, hi);
		logp("field: %s\n", msg);
		return false;
	}
	if (e < EMPTY_MIN || e > EMPTY_MAX) {
		snprintf(msg, max, "%.0f: a card near? Baseline kept", e);
		logp("field: %s\n", msg);
		return false;
	}
	empty = e;
	learned = true;
	dirty = true;
	save();
	snprintf(msg, max, "Baseline set to %.0f", empty);
	logp("field: %s\n", msg);
	return true;
}

void fieldCardPresent(bool present)
{
	if (present) {
		cardGone = learned = false;
	} else if (!cardGone) {
		cardGone = true;
		goneAt = nowMs();
	}
}

static bool sample(void)
{
	float i, q;
	if (!readIQ(&i, &q)) return false;
	float r = sqrtf((i - offI) * (i - offI) + (q - offQ) * (q - offQ));
	if (r < 40 || r > 600) return false;
	learnEmpty(r);
	// median of the last 5, then smoothed: single noisy reads (Q jumps by ~6 now and then) dip the length
	// by a few units and flicked the gauge
	med[medN++ % 5] = r;
	int m = medN < 5 ? medN : 5;
	float t[5];
	memcpy(t, med, sizeof(t));
	for (int a = 1; a < m; a++)
		for (int b = a; b > 0 && t[b] < t[b - 1]; b--) {
			float x = t[b];
			t[b] = t[b - 1], t[b - 1] = x;
		}
	float mr = t[m / 2];
	level = level ? 0.6f * level + 0.4f * mr : mr;

	publish();
	return true;
}

void fieldArm(void)
{
	load();
	level = 0;
	medN = 0;
	cardGone = learned = false;
	armed = true;
	inPoll = true;
	bool ok = sample();
	inPoll = false;
#ifndef PROX3DS_RELEASE
	if (ok) logp("field: level %.0f, empty %.0f: %d/%d\n", level, empty, bars, FIELD_BARS);
#else
	(void)ok;
#endif
}

void fieldDisarm(void)
{
	armed = false;
}

void fieldPoll(void)
{
	if (!armed || inPoll || nowMs() - lastMs < POLL_MS) return;
	inPoll = true;
	sample();
	inPoll = false;
}

bool fieldTuneSample(void)
{
	if (!armed) return false;
	inPoll = true;
	bool ok = sample();
	inPoll = false;
	return ok;
}

// Kasa circle fit: x^2 + y^2 = 2 a x + 2 b y + c, least squares (3x3 normal equations, Cramer).
static bool circleFit(const float *x, const float *y, int n, float *a, float *b, float *r)
{
	double m[3][3] = { { 0 } }, v[3] = { 0 };
	for (int k = 0; k < n; k++) {
		double row[3] = { 2 * x[k], 2 * y[k], 1 }, rhs = (double)x[k] * x[k] + (double)y[k] * y[k];
		for (int i = 0; i < 3; i++) {
			for (int j = 0; j < 3; j++) m[i][j] += row[i] * row[j];
			v[i] += row[i] * rhs;
		}
	}
	double det = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1]) - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0]) +
		m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);
	if (fabs(det) < 1e-9) return false;
	double s[3];
	for (int c = 0; c < 3; c++) {
		double t[3][3];
		memcpy(t, m, sizeof(t));
		for (int i = 0; i < 3; i++) t[i][c] = v[i];
		s[c] = (t[0][0] * (t[1][1] * t[2][2] - t[1][2] * t[2][1]) - t[0][1] * (t[1][0] * t[2][2] - t[1][2] * t[2][0]) +
			t[0][2] * (t[1][0] * t[2][1] - t[1][1] * t[2][0])) / det;
	}
	double rr = s[2] + s[0] * s[0] + s[1] * s[1];
	if (rr <= 0) return false;
	*a = s[0];
	*b = s[1];
	*r = sqrt(rr);
	return true;
}

#define CAL_POINTS 14

void fieldJobEnd(void)
{
	if (armed && !calibrated) {
		inPoll = true;
		float x[CAL_POINTS], y[CAL_POINTS];
		int n = 0;
		double ux = 0, uy = 0;
		for (int k = 0; k < CAL_POINTS + 6 && n < CAL_POINTS; k++) {
			if (!monWrite32(0x5C360, 0)) break;
			svcSleepThread(3 * 1000000LL);
			if (!monWrite32(0x5C360, 6)) break;
			svcSleepThread(15 * 1000000LL);
			float i1, q1, i2, q2;
			if (!readIQ(&i1, &q1) || !readIQ(&i2, &q2) || fabsf(i1 - i2) > 4 || fabsf(q1 - q2) > 4) continue;
			x[n] = (i1 + i2) / 2;
			y[n] = (q1 + q2) / 2;
			float l = sqrtf(x[n] * x[n] + y[n] * y[n]);
			if (l > 1) {
				ux += x[n] / l;
				uy += y[n] / l;
			}
			n++;
		}
		inPoll = false;
		float a, b, r;
		// points spread around the circle (random phases), else the center is a guess
		if (n >= 10 && sqrt(ux * ux + uy * uy) / n < 0.6 && circleFit(x, y, n, &a, &b, &r) && fabsf(a) < 40 &&
			fabsf(b) < 40) {
			double e = 0;
			for (int k = 0; k < n; k++) {
				float d = sqrtf((x[k] - a) * (x[k] - a) + (y[k] - b) * (y[k] - b)) - r;
				e += d * d;
			}
			e = sqrt(e / n);
			if (e < 4) {
				offI = a;
				offQ = b;
				calibrated = dirty = true;
				logp("field: I/Q offset %.1f %.1f, level %.0f (fit sd %.1f)\n", a, b, r, e);
			}
		}
	}
	armed = false;
	save();
}

int fieldBars(bool *live)
{
	int b = bars;
	u32 age = nowMs() - lastMs;
	if (b < 0 || age > SHOW_MS) return -1;
	if (live) *live = armed && age < LIVE_MS;
	return b;
}

float fieldGauge(bool *live)
{
	if (live) *live = armed && bars >= 0 && nowMs() - lastMs < LIVE_MS;
	return loadFrac;
}

float fieldLevel(float *emptyOut)
{
	if (emptyOut) *emptyOut = empty;
	return level;
}
