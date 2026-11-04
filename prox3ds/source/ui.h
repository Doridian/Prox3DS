#pragma once
#include <citro2d.h>

// Drawing (citro2d, system font). Everything the user needs is on the top screen and works with the
// buttons: a card on the reader covers the whole bottom screen. The bottom screen (touch) doubles the
// buttons: the footer's hints as touch buttons, a D-pad, or a screen's own keypad; and the log's tail.

#define UI_W 400
#define UI_H 240
#define UI_BW 320 // the bottom screen, as tall

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

void uiBottom(void); // draws from here to uiFrameEnd go to the bottom screen

// Touch, immediate mode: the app loop hands over each frame's new touch (uiTouch), and a button drawn
// on the bottom screen that frame holds it or not.
// A touch held past the repeat delay comes again every few frames as a repeat, which only uiButtonRep
// takes (D-pad, digits; not OK / Cancel).
void uiTouch(bool down, bool repeat, float x, float y);
bool uiButton(float x, float y, float w, float h, u32 color, const char *label); // true = tapped now
bool uiButtonRep(float x, float y, float w, float h, u32 color, const char *label);
// Two lines: a small dim caption over the label (form fields).
bool uiButton2(float x, float y, float w, float h, u32 color, const char *caption, const char *label);
// The footer's hints ("<button glyph> what it does" ...), for the bottom screen's touch buttons.
void uiHints(const char *hints);
const char *uiHintsNow(void);

void uiRect(float x, float y, float w, float h, u32 color);
void uiLine(float x0, float y0, float x1, float y1, float thick, u32 color);
void uiBar(float x, float y, float w, float h, float frac, u32 color); // progress bar, frac 0..1
void uiTri(float x0, float y0, float x1, float y1, float x2, float y2, u32 color);
float uiText(float x, float y, float scale, u32 color, const char *fmt, ...); // returns the width
void uiTextRight(float right, float y, float scale, u32 color, const char *fmt, ...);
// Word-wrapped at w (and at '\n'), lines SMALL_H apart at S_SMALL (in proportion otherwise); -> y below it
float uiTextWrap(float x, float y, float w, float scale, u32 color, const char *text);
int uiWrapLines(float w, float scale, const char *text); // how many lines uiTextWrap would draw
float uiTextWidth(float scale, const char *s);           // widest line, without drawing
char *uiFit(char *s, float w, float scale);              // cut to fit w with "...", in place; returns s
void uiTextCenter(float cx, float y, float scale, u32 color, const char *fmt, ...);
// Printable ASCII in fixed MONO_W cells (hex grids); anything else draws as '.'.
void uiMono(float x, float y, u32 color, const char *s);
void uiMonoS(float x, float y, float scale, float cell, u32 color, const char *s);
void uiHeader(const char *title, const char *right);
void uiFooter(const char *hints);
// A selected list row: highlight with a bar down its left edge.
void uiSel(float x, float y, float w, float h);
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
