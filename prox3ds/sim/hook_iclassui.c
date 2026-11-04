#include "../source/iclassui.c"
#include "scenes.h"

// iclassrw.c talks to the chip: the scenes fill the card screen directly.
IcCard icCard;
bool icWait(u8 csn[8], u32 timeoutMs) { return false; }
int icReadCard(IcCard *c, const u8 *key, int kind) { return 0; }
bool icSaveDump(const IcCard *c, char *path, u32 max) { return false; }
void icStop(void) {}
int httpGetFile(const char *url, const char *path, u32 max, char *why, u32 whyLen) { return 0; }

void simIclass(const IcCard *c)
{
	sc = *c;
	bl = (UiList){ 0 };
	appScreen(&cardScreen);
}

void simIclassMenu(void)
{
	iclassOpenMenu();
}
