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
