#include "../source/editor.c"
#include "scenes.h"

void simEdWriteBlock(int result, const char *how, const char *why)
{
	wbResult = result;
	wbBlock = blk();
	snprintf(wbHow, sizeof(wbHow), "%s", how);
	snprintf(wbWhy, sizeof(wbWhy), "%s", why);
	doneWriteBlock();
}

void simEdValue(int result, int dest, const u8 out[16])
{
	vlResult = result;
	vlDest = dest;
	memcpy(vlOut, out, 16);
	snprintf(wbHow, sizeof(wbHow), "key A FFFFFFFFFFFF");
	doneValue();
}
