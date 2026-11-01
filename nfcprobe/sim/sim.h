#pragma once
#include <3ds.h>

// A scene script: one step per frame (calls run before the frame, as many as are in a row).
enum { SIM_END, SIM_KEYS, SIM_SHOT, SIM_CALL };
typedef struct {
	int kind;
	u32 keys;
	const char *name;
	void (*fn)(void);
} SimStep;
#define KEYS(k) { SIM_KEYS, (k), NULL, NULL }
#define SHOT(n) { SIM_SHOT, 0, (n), NULL }
#define CALL(f) { SIM_CALL, 0, NULL, (f) }
#define END     { SIM_END, 0, NULL, NULL }

void simScript(const SimStep *s);
void simSetOutDir(const char *dir);
