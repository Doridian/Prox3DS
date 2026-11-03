// Host build of the Java Card VM (jcvm.c, jcapi.c, jccard.c with the UI sim's fake libctru): installs the
// CAP files given, then hex APDUs on stdin, answers on stdout. R = new session, S = save, L = restore,
// I path = install a CAP. Compare with tools/jcvm/jcrelay.py - (the Python VM).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jccard.h"

int main(int argc, char **argv)
{
	jcCardInit();
	for (int i = 1; i < argc; i++)
		if (jcCardInstallCap(argv[i]) < 0) return printf("install %s: %s\n", argv[i], jcCard.vm.why), 1;
	char line[8192];
	while (fgets(line, sizeof(line), stdin)) {
		u8 c[4096], r[4096];
		u32 n = 0;
		unsigned x;
		line[strcspn(line, "\r\n")] = 0;
		if (line[0] == 'R') { jcCardApdu(NULL, 0, NULL, 0); puts("-- session"); continue; }
		if (line[0] == 'S') { printf("save %d\n", jcCardSave()); continue; }
		if (line[0] == 'L') { printf("restore %d, %d applets\n", jcCardRestore(), jcCard.napplets); continue; }
		if (line[0] == 'I') { int p = jcCardInstallCap(line + 2); printf("install %d %s\n", p, p < 0 ? jcCard.vm.why : ""); continue; }
		for (char *p = line; sscanf(p, "%2x", &x) == 1; p += 2) c[n++] = x;
		u32 s0 = jcCard.vm.steps;
		u32 m = jcCardApdu(c, n, r, sizeof(r));
		printf("< ");
		for (u32 i = 0; i < m; i++) printf("%02X", r[i]);
		printf("  (%u steps)%s%s\n", (unsigned)(jcCard.vm.steps - s0), jcCard.vm.why[0] ? "  why: " : "", jcCard.vm.why);
		jcCard.vm.why[0] = 0;
		fflush(stdout);
	}
}
