#include "../source/emvui.c"
#include "scenes.h"

void simEmv(const EmvCard *e, bool full)
{
	ec = *e;
	cur = 0, showPan = full, ll = (UiList){ 0 };
	appScreen(&emvScreen);
}
