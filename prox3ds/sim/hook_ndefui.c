#include "../source/ndefui.c"
#include "scenes.h"

// Show the NDEF screen for a dump as if just read from card c
void simNdef(const MfuDump *d, const Card *c)
{
	ndJob = *d;
	ndJobCard = *c;
	ndWriting = false;
	ndResult = 1;
	doneNdef();
}

void simNdefActions(void) { actions(); }
void simNdefUrl(const char *url) { simKbdText = url; writeUrl(); simKbdText = NULL; }
