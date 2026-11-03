#include "../source/mfui.c"
#include "scenes.h"

void simMfcCard(const Card *c, const MfMagic *m)
{
	sc = *c;
	sm = *m;
	mfcShow();
}

void simMfcGen4(void)
{
	gen4Open();
}

void simMfcRead(const MfDump *d, int got, const char *path)
{
	rd = *d;
	rdGot = got;
	snprintf(rdPath, sizeof(rdPath), "%s", path);
	doneRead();
}

void simMfcClone(int result, const char *why)
{
	clResult = result;
	snprintf(clWhy, sizeof(clWhy), "%s", why);
	doneClone();
}

void simMfcMenu(void)
{
	mfcMenu.l = (UiList){ 0 }; // scenes start at the top (menus keep their cursor)
	mfcOpenMenu();
}
