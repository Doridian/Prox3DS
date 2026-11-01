#pragma once
// Host stand-in for the bits of libctru the UI uses (sim/, see README). Built with -m32 so long is
// 32 bits, as on the ARM11: the app prints u32 with %lu.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef unsigned long u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef long s32;
typedef int64_t s64;
typedef u32 Handle;
typedef s32 Result;
#define U64_MAX UINT64_MAX
#define BIT(n) (1U << (n))

enum {
	KEY_A = BIT(0), KEY_B = BIT(1), KEY_SELECT = BIT(2), KEY_START = BIT(3), KEY_DRIGHT = BIT(4),
	KEY_DLEFT = BIT(5), KEY_DUP = BIT(6), KEY_DDOWN = BIT(7), KEY_R = BIT(8), KEY_L = BIT(9),
	KEY_X = BIT(10), KEY_Y = BIT(11), KEY_TOUCH = BIT(20),
	KEY_UP = KEY_DUP, KEY_DOWN = KEY_DDOWN, KEY_LEFT = KEY_DLEFT, KEY_RIGHT = KEY_DRIGHT,
};

typedef pthread_mutex_t LightLock;
static inline void LightLock_Init(LightLock *l) { pthread_mutex_init(l, NULL); }
static inline void LightLock_Lock(LightLock *l) { pthread_mutex_lock(l); }
static inline void LightLock_Unlock(LightLock *l) { pthread_mutex_unlock(l); }

typedef struct SimThread *Thread;
typedef void (*ThreadFunc)(void *);
Thread threadCreate(ThreadFunc entry, void *arg, size_t stack, int prio, int core, bool detached);
Result threadJoin(Thread t, u64 timeout);
void threadFree(Thread t);

void svcSleepThread(s64 ns);
u64 osGetTime(void);

bool aptMainLoop(void);
bool aptCheckHomePressRejected(void);
void hidScanInput(void);
u32 hidKeysDown(void);
u32 hidKeysDownRepeat(void);
u32 hidKeysHeld(void);
typedef struct { u16 px, py; } touchPosition;
void hidTouchRead(touchPosition *pos);
void hidSetRepeatParameters(u32 delay, u32 interval);

Result archive_getmtime(const char *path, u64 *mtime);

typedef enum { GFX_TOP, GFX_BOTTOM } gfxScreen_t;
typedef enum { GFX_LEFT, GFX_RIGHT } gfx3dSide_t;

// System font: the widths from metrics.h (fake.c)
typedef struct {
	s8 left;
	u8 glyphWidth;
	u8 charWidth;
} charWidthInfo_s;
typedef struct CFNT_s CFNT_s;
Result fontEnsureMapped(void);
int fontGlyphIndexFromCodePoint(CFNT_s *font, u32 codePoint);
charWidthInfo_s *fontGetCharWidthInfo(CFNT_s *font, int glyphIndex);
ssize_t decode_utf8(u32 *out, const u8 *in);
