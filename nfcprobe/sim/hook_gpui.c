#include "../source/gpui.c"
#include "scenes.h"

void simGp(const GpCard *g, bool ok, const char *why)
{
	gc = *g;
	gcResult = 1;
	keysOk = ok;
	keys = gpDefaultKeys;
	snprintf(gcWhy, sizeof(gcWhy), "%s", why);
	el = (UiList){ 0 };
	appScreen(&gpScreen);
}

void simGpCaps(void)
{
	appScreen(&capsScreen);
}
