#pragma once
// Host stand-in for citro2d: text is measured with sim/metrics.h and every draw is recorded for
// sim/render.py.
#include <3ds.h>

typedef struct C3D_RenderTarget C3D_RenderTarget;
typedef struct SimTextBuf *C2D_TextBuf;
typedef struct {
	const char *str; // in its text buffer
	float width;     // at scale 1, widest line
	int lines;
} C2D_Text;

enum { C2D_AtBaseline = 1, C2D_WithColor = 2, C2D_AlignLeft = 0, C2D_AlignRight = 4, C2D_AlignCenter = 8 };
#define C3D_DEFAULT_CMDBUF_SIZE 0x40000
#define C2D_DEFAULT_MAX_OBJECTS 4096
#define C3D_FRAME_SYNCDRAW 1

static inline u32 C2D_Color32(u8 r, u8 g, u8 b, u8 a) { return r | g << 8 | b << 16 | (u32)a << 24; }

bool C3D_Init(size_t cmdBufSize);
void C3D_Fini(void);
bool C3D_FrameBegin(u8 flags);
void C3D_FrameEnd(u8 flags);
bool C2D_Init(size_t maxObjects);
void C2D_Fini(void);
void C2D_Prepare(void);
C3D_RenderTarget *C2D_CreateScreenTarget(gfxScreen_t screen, gfx3dSide_t side);
void C2D_TargetClear(C3D_RenderTarget *t, u32 color);
void C2D_SceneBegin(C3D_RenderTarget *t);
C2D_TextBuf C2D_TextBufNew(size_t maxGlyphs);
void C2D_TextBufDelete(C2D_TextBuf buf);
void C2D_TextBufClear(C2D_TextBuf buf);
const char *C2D_TextParse(C2D_Text *text, C2D_TextBuf buf, const char *str);
void C2D_TextOptimize(const C2D_Text *text);
void C2D_DrawText(const C2D_Text *text, u32 flags, float x, float y, float depth, float sx, float sy, ...);
bool C2D_DrawRectSolid(float x, float y, float z, float w, float h, u32 clr);
bool C2D_DrawLine(float x0, float y0, u32 clr0, float x1, float y1, u32 clr1, float thickness, float depth);
bool C2D_DrawTriangle(float x0, float y0, u32 clr0, float x1, float y1, u32 clr1, float x2, float y2, u32 clr2, float depth);
