#include <math.h>
// Host stand-ins for libctru / citro2d (include/), and the scripted main loop: aptMainLoop() runs the
// scene's next step each frame, C3D_FrameEnd() writes the frame's draw list when the step asked for
// a shot. render.py turns the lists into PNGs and checks them.

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <citro2d.h>

#include "metrics.h"
#include "sim.h"

// --- threads: jobs run to completion right away (the hardware stubs fail fast) ---

struct SimThread { int dummy; };
static struct SimThread theThread;

Thread threadCreate(ThreadFunc entry, void *arg, size_t stack, int prio, int core, bool detached)
{
	entry(arg);
	return &theThread;
}
Result threadJoin(Thread t, u64 timeout) { return 0; }
void threadFree(Thread t) {}
void svcSleepThread(s64 ns) {}
u64 osGetTime(void) { return 0; }

Result archive_getmtime(const char *path, u64 *mtime)
{
	struct stat st;
	if (stat(path, &st)) return -1;
	*mtime = st.st_mtime;
	return 0;
}

// --- script ---

static const SimStep *step;
static u32 keys;
static char shotName[64];
static FILE *shot;
static const char *outDir = "shots";

void simSetOutDir(const char *dir) { outDir = dir; }

void simScript(const SimStep *s)
{
	step = s;
}

bool aptMainLoop(void)
{
	keys = 0;
	*shotName = 0;
	while (step && step->kind == SIM_CALL) (step++)->fn();
	if (!step || step->kind == SIM_END) return false;
	if (step->kind == SIM_KEYS) keys = step->keys;
	else snprintf(shotName, sizeof(shotName), "%s", step->name);
	step++;
	return true;
}

bool aptCheckHomePressRejected(void) { return false; }
void hidScanInput(void) {}
u32 hidKeysDown(void) { return keys; }
u32 hidKeysDownRepeat(void) { return keys; }
void hidSetRepeatParameters(u32 delay, u32 interval) {}

// --- citro2d ---

struct C3D_RenderTarget { int dummy; };
static C3D_RenderTarget theTarget;
struct SimTextBuf { char *buf; size_t used, size; };

bool C3D_Init(size_t n) { return true; }
void C3D_Fini(void) {}
bool C2D_Init(size_t n) { return true; }
void C2D_Fini(void) {}
void C2D_Prepare(void) {}
C3D_RenderTarget *C2D_CreateScreenTarget(gfxScreen_t s, gfx3dSide_t side) { return &theTarget; }
void C2D_SceneBegin(C3D_RenderTarget *t) {}
void C2D_TextOptimize(const C2D_Text *t) {}

bool C3D_FrameBegin(u8 flags)
{
	if (*shotName) {
		char path[256];
		snprintf(path, sizeof(path), "%s/%s.txt", outDir, shotName);
		shot = fopen(path, "w");
		if (!shot) perror(path);
	}
	return true;
}

void C3D_FrameEnd(u8 flags)
{
	if (shot) fclose(shot);
	shot = NULL;
}

void C2D_TargetClear(C3D_RenderTarget *t, u32 color)
{
	if (shot) fprintf(shot, "R 0 0 400 240 %08lX\n", color);
}

bool C2D_DrawRectSolid(float x, float y, float z, float w, float h, u32 clr)
{
	if (shot) fprintf(shot, "R %g %g %g %g %08lX\n", x, y, w, h, clr);
	return true;
}

// Lines and triangles drawn as their bounding boxes: enough for layout checks
bool C2D_DrawLine(float x0, float y0, u32 clr0, float x1, float y1, u32 clr1, float thickness, float depth)
{
	float x = x0 < x1 ? x0 : x1, y = y0 < y1 ? y0 : y1, w = x0 < x1 ? x1 - x0 : x0 - x1, h = y0 < y1 ? y1 - y0 : y0 - y1;
	return C2D_DrawRectSolid(x - thickness / 2, y - thickness / 2, depth, w + thickness, h + thickness, clr0);
}

bool C2D_DrawTriangle(float x0, float y0, u32 clr0, float x1, float y1, u32 clr1, float x2, float y2, u32 clr2, float depth)
{
	float lx = fminf(x0, fminf(x1, x2)), hx = fmaxf(x0, fmaxf(x1, x2));
	float ly = fminf(y0, fminf(y1, y2)), hy = fmaxf(y0, fmaxf(y1, y2));
	return C2D_DrawRectSolid(lx, ly, depth, hx - lx, hy - ly, clr0);
}

C2D_TextBuf C2D_TextBufNew(size_t maxGlyphs)
{
	C2D_TextBuf b = calloc(1, sizeof(*b));
	b->size = maxGlyphs * 8;
	b->buf = malloc(b->size);
	return b;
}

void C2D_TextBufDelete(C2D_TextBuf b)
{
	free(b->buf);
	free(b);
}

void C2D_TextBufClear(C2D_TextBuf b) { b->used = 0; }

// UTF-8 code point at *p, advancing it
static u32 utf8(const char **p)
{
	const u8 *s = (const u8 *)*p;
	u32 c = *s++;
	if (c >= 0xF0) c = (c & 7) << 18 | (s[0] & 0x3F) << 12 | (s[1] & 0x3F) << 6 | (s[2] & 0x3F), s += 3;
	else if (c >= 0xE0) c = (c & 0xF) << 12 | (s[0] & 0x3F) << 6 | (s[1] & 0x3F), s += 2;
	else if (c >= 0xC0) c = (c & 0x1F) << 6 | (s[0] & 0x3F), s += 1;
	*p = (const char *)s;
	return c;
}

static float advance(u32 c)
{
	return c < 128 ? simAdv[c] : (c >= 0xE000 && c <= 0xE07F) ? SIM_BUTTON_ADV : SIM_FONT_SIZE;
}

Result fontEnsureMapped(void) { return 0; }
int fontGlyphIndexFromCodePoint(CFNT_s *font, u32 codePoint) { return codePoint; }

charWidthInfo_s *fontGetCharWidthInfo(CFNT_s *font, int glyphIndex)
{
	static charWidthInfo_s w;
	w.charWidth = advance(glyphIndex);
	w.glyphWidth = w.charWidth;
	return &w;
}

ssize_t decode_utf8(u32 *out, const u8 *in)
{
	const char *p = (const char *)in;
	*out = utf8(&p);
	return p - (const char *)in;
}

const char *C2D_TextParse(C2D_Text *t, C2D_TextBuf b, const char *str)
{
	size_t n = strlen(str) + 1;
	if (b->used + n > b->size) {
		fprintf(stderr, "sim: text buffer full\n");
		n = 1;
		str = "";
	}
	char *dst = b->buf + b->used;
	memcpy(dst, str, n);
	b->used += n;
	t->str = dst;
	t->width = 0;
	t->lines = 1;
	float w = 0;
	for (const char *p = str; *p;) {
		u32 c = utf8(&p);
		if (c == '\n') {
			t->lines++;
			w = 0;
			continue;
		}
		w += advance(c);
		if (w > t->width) t->width = w;
	}
	return str + strlen(str);
}

void C2D_DrawText(const C2D_Text *t, u32 flags, float x, float y, float depth, float sx, float sy, ...)
{
	u32 color = 0xFF000000;
	if (flags & C2D_WithColor) {
		va_list va;
		va_start(va, sy);
		color = va_arg(va, u32);
		va_end(va);
	}
	if (!shot) return;
	float w = t->width * sx;
	if (flags & C2D_AlignRight) x -= w;
	else if (flags & C2D_AlignCenter) x -= w / 2;
	char align = flags & C2D_AlignRight ? 'R' : flags & C2D_AlignCenter ? 'C' : 'L';
	fprintf(shot, "T %g %g %g %g %d %08lX %c ", x, y, w, sy, t->lines, color, align);
	for (const char *p = t->str; *p; p++) fputc(*p == '\n' ? '\x1f' : *p, shot);
	fputc('\n', shot);
}
