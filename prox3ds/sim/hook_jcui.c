#include "../source/jcui.c"
#include "scenes.h"

// The Java Card screen with the test CAPs from javacard/ (local builds; an empty card without them).
void simJc(bool empty)
{
	jcCardInit();
	restored = true;
	al = (UiList){ 0 };
	if (!empty) {
		jcCardInstallCap("../../../javacard/ykneo-oath.cap");
		jcCardInstallCap("../../../javacard/dspm-test.cap");
		jcCardInstallCap("../../../javacard/dspm-vmtest.cap");
		jcCardInstallCap("../../../javacard/dspm-lib.cap");
		jcCardInstallCap("../../../javacard/dspm-libuse.cap");
	}
	appScreen(&jcScreen);
}
