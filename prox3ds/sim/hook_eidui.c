#include "../source/eidui.c"
#include "scenes.h"

void simEid(const EidCard *e, int can)
{
	ed = *e;
	il = (UiList){ 0 };
	canState = can;
	strcpy(canText, "123456");
	canSmSw = can == 1 ? 0x9000 : 0;
	if (can == 3) strcpy(canWhy, "mapping: 6A80 wrong data");
	appScreen(&eidScreen);
}

void simMrtd(const MrtdDoc *d)
{
	md = *d;
	appScreen(&mrtdScreen);
}
