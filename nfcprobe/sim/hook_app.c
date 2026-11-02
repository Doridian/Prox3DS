#include "../source/app.c"
#include "scenes.h"

void simReset(void)
{
	depth = 1;
	dlg.kind = DLG_NONE;
	toastUntil = 0;
	jobBusy = false;
	logTop = -1;
	rootMenu.l = (UiList){ 0 };
}

void simTag(const Card *c)
{
	tag = *c;
	tagFamily = NULL;
	appScreen(&tagScreen);
}

void simBusy(const char *title, bool cancellable, bool stopping)
{
	jobTitle = title;
	jobCancellable = cancellable;
	mfCancel = stopping;
	jobBusy = true;
	jobFinished = false;
}

void simBusyView(float (*view)(float x, float y, float w))
{
	jobView = view;
}

void simBusyEnd(void)
{
	jobBusy = false;
	jobView = NULL;
	mfCancel = false;
}
