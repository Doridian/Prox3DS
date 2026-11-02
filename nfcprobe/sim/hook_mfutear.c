#include "../source/mfutear.c"
#include "scenes.h"

// The EV1 test card, page 10 AAAAAAAA -> 55555555 (NOTES.md), from 300 us in 10s
void simTearScan(void)
{
	static const struct { u16 us; u32 v; } pts[] = {
		{ 300, 0xAAAAAAAA }, { 400, 0xAAAAAAAA }, { 410, 0xAAAAAAAA }, { 413, 0x2AAAAAAA }, { 423, 0x228AAAAA },
		{ 433, 0x00080000 }, { 453, 0x00080000 }, { 463, 0x00000000 }, { 1500, 0x00000000 }, { 2733, 0x00000000 },
		{ 2743, 0x00010000 }, { 2753, 0x00110000 }, { 2763, 0x00510011 }, { 2773, 0x00554011 },
		{ 2783, 0x50555015 }, { 2793, 0x55555555 }, { 2803, 0x55555555 },
	};
	wn = wTotal = sizeof(pts) / sizeof(pts[0]);
	for (int i = 0; i < wn; i++) {
		wr[i].us = pts[i].us, wr[i].ok = 1;
		for (int k = 0; k < 4; k++) wr[i].got[k] = pts[i].v >> (24 - 8 * k);
	}
	wPage = 10;
	snprintf(wType, sizeof(wType), "Ultralight EV1 (MF0UL11)");
	wl = (UiList){ 0 };
	appScreen(&wsResults);
}

void simTearCounter(void)
{
	ctr = 0;
	cp.phase = "Resetting", cp.bd = 2768, cp.steps = 37, cp.start = 1, cp.val = 0x00FFFF, cp.tear = 0xBD;
	cp.t0 = osGetTime() - 95000;
	simBusy("Counter reset", true, false);
	simBusyView(counterView);
}
