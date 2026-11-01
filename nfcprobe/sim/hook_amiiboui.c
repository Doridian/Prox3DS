#include "../source/amiiboui.c"
#include "scenes.h"

// amiibo.c needs the console (FS, ps:ps), so the screen gets its results from the scenes instead.
int amiiboKeysLoad(void) { return 1; }
const char *amiiboWhy(void) { return "no key table in the NFC module"; }
int amiiboUnpack(const u8 *tag, Amiibo *a) { return 1; }
int amiiboImage(const Amiibo *a, const u8 head[12], bool fresh, u8 *out) { return 0; }

// Show the Amiibo screen for a decrypted figure, as if just read from card c (name: from a dump)
void simAmiibo(const Amiibo *a, const u8 *tag, const Card *c, const char *name)
{
	amJob = *a;
	memcpy(amJobTag, tag, AMIIBO_TAG);
	amJobCard = *c;
	snprintf(amJobName, sizeof(amJobName), "%s", name ? name : "");
	amMode = name ? AM_FILE : AM_READ;
	amResult = 1;
	doneAmiibo();
}

void simAmiiboActions(void) { actions(); }
void simAmiiboCopy(bool fresh, bool lock) { copyAsk(fresh, lock); }
