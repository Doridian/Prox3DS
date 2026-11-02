#include "../source/oathui.c"
#include "scenes.h"

void simOath(const OathInfo *o, int offset)
{
	oi = *o;
	clockOffset = offset * 60;
	cfgLoaded = true;
	u64 t = unixNow();
	for (int i = 0; i < oi.n; i++) oi.c[i].step = t / oi.c[i].period - (i == 3); // one stale code
	cl = (UiList){ 0 };
	appScreen(&oathScreen);
}

void simOathAdd(void)
{
	addAccount();
	snprintf(put.name, sizeof(put.name), "GitHub:someone@example.com");
	put.len = 20;
}
