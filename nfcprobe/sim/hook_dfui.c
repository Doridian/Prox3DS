#include "../source/dfui.c"
#include "scenes.h"

void simDfCard(const Card *c, const DfInfo *d, int result, const char *why)
{
	sc = *c;
	di = *d;
	diResult = result;
	snprintf(diWhy, sizeof(diWhy), "%s", why);
	al = (UiList){ 0 };
	dfShow();
}

void simDfMenu(void)
{
	dfOpenMenu();
}

void simDfData(int app, int file)
{
	showData(&di.apps[app], &di.apps[app].files[file]);
}
