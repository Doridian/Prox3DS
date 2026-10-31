#pragma once
#include <citro2d.h>

// Top-screen drawing (citro2d, system font). Cards cover the whole bottom screen, so everything the
// user needs is up here; the bottom screen only mirrors the log.

#define UI_W 400
#define UI_H 240

#define S_TITLE 0.55f
#define S_BODY  0.5f
#define S_SMALL 0.42f
#define S_MONO  0.40f
#define MONO_W  7.0f   // fixed cell of uiMono (system font digits are 17 wide at scale 1)
#define LINE_H  15     // a S_BODY line
#define SMALL_H 13     // a S_SMALL line

// System font glyphs for the buttons (E079-E07C: D-pad up/down/left/right alone)
#define BTN_A     "\uE000"
#define BTN_B     "\uE001"
#define BTN_X     "\uE002"
#define BTN_Y     "\uE003"
#define BTN_L     "\uE004"
#define BTN_R     "\uE005"
#define BTN_DPAD  "\uE006"
#define BTN_UD    "\uE07D"
#define BTN_LR    "\uE07E"

enum {
	COL_BG, COL_PANEL, COL_BAR, COL_TEXT, COL_DIM, COL_ACCENT, COL_SEL, COL_CURSOR,
	COL_WARN, COL_ERR, COL_OK, COL_KEYA, COL_KEYB, COL_ACL, COL_CHANGED, COL_N
};
extern u32 uiCol[COL_N];

void uiInit(void);
void uiExit(void);
void uiFrameBegin(void);
void uiFrameEnd(void);

void uiRect(float x, float y, float w, float h, u32 color);
float uiText(float x, float y, float scale, u32 color, const char *fmt, ...); // returns the width
void uiTextRight(float right, float y, float scale, u32 color, const char *fmt, ...);
void uiTextCenter(float cx, float y, float scale, u32 color, const char *fmt, ...);
// Printable ASCII in fixed MONO_W cells (hex grids); anything else draws as '.'.
void uiMono(float x, float y, u32 color, const char *s);
void uiMonoS(float x, float y, float scale, float cell, u32 color, const char *s);
void uiHeader(const char *title, const char *right);
void uiFooter(const char *hints);
// A centered box with a title bar; returns the y where its content starts.
float uiBox(float w, float h, const char *title);

// Selectable list state: selection and first visible row.
typedef struct {
	int sel, top;
} UiList;
void uiListNav(UiList *l, int n, int visible, u32 kRepeat);

// Log ring, fed by logp (any thread). Line 0 is the oldest kept.
void uiLogAppend(const char *s);
int uiLogCount(void);
void uiLogLine(int i, char *out, u32 max);
