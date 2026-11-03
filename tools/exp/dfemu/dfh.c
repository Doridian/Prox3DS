// Host build of dfemu.c (with the sim's fake libctru): hex commands on stdin, answers on stdout, R = new session.
#include <stdio.h>
#include <string.h>
#include "desfire.h"
#include "dfemu.h"
static DfInfo d;
int main(int argc, char **argv)
{
	if (!dfLoadInfo(&d, argv[1])) return printf("load failed\n"), 1;
	dfEmuSet(&d);
	dfEmuApdu(NULL, 0, NULL, 0);
	char line[2048];
	while (fgets(line, sizeof(line), stdin)) {
		u8 c[1024], r[1024];
		u32 n = 0, x;
		if (line[0] == 'R') { dfEmuApdu(NULL, 0, NULL, 0); puts(""); fflush(stdout); continue; }
		for (char *p = line; sscanf(p, "%2x", &x) == 1; p += 2) c[n++] = x;
		u32 m = dfEmuApdu(c, n, r, 256);
		for (u32 i = 0; i < m; i++) printf("%02X", r[i]);
		puts("");
		fflush(stdout);
	}
}
