#include "../source/mfuui.c"
#include "scenes.h"

void simMfuCard(const Card *c, const MfuDump *d, bool gtu)
{
	scJob = *c;
	smJob = *d;
	smGtuJob = gtu;
	mfuShow();
}

void simMfuRead(const MfuDump *d, int result, const char *path)
{
	rd = *d;
	rdResult = result;
	snprintf(rdPath, sizeof(rdPath), "%s", path);
	doneRead();
}

void simMfuRestore(int result, int pages, const char *why)
{
	wrResult = result;
	wrPages = pages;
	snprintf(wrWhy, sizeof(wrWhy), "%s", why);
	doneRestore();
}

void simMfuClone(const MfuDump *d, int result, const char *why)
{
	cl = *d;
	clResult = result;
	snprintf(clWhy, sizeof(clWhy), "%s", why);
	doneClone();
}

void simMfuMenu(void)
{
	mfuMenu.l = (UiList){ 0 };
	mfuOpenMenu();
}

void simMfuPick(const Card *c, const MfuDump *d)
{
	sc = *c;
	sm = *d;
	pickOpen();
}

void simMfuReadKey(const MfuDump *d, int result, const char *path, const MfuKey *cand)
{
	rdWithPwd = true;
	rdCand = *cand;
	simMfuRead(d, result, path);
}
