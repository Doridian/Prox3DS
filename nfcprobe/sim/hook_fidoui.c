#include "../source/fidoui.c"
#include "scenes.h"

void simFido(const FidoInfo *f)
{
	fi = *f;
	appScreen(&fidoScreen);
}
