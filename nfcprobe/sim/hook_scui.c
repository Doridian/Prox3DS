#include "../source/scui.c"
#include "scenes.h"

void simScCard(const Card *c, const ScInfo *s, int result, const char *why)
{
	sc = *c;
	si = *s;
	siResult = result;
	snprintf(siWhy, sizeof(siWhy), "%s", why);
	al = (UiList){ 0 };
	scShow();
}

void simScMenu(void)
{
	scOpenMenu();
}

// A few exchanges: an activation, a SELECT, a long answer, an error, a lost card.
void simScConsole(bool empty)
{
	conN = 0, conTop = -1;
	if (!empty) {
		ConEntry *e = conAdd();
		snprintf(e->note, sizeof(e->note), "card 04B1B1B1B1B1B11122 activated, ATS 0578777102");
		static const u8 sel[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x00 };
		e = conAdd();
		memcpy(e->cmd, sel, sizeof(sel)), e->cmdLen = sizeof(sel);
		static const u8 a[] = { 0x79, 0x03, 0x05, 0x04, 0x03, 0x71, 0x08, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81 };
		memcpy(e->ans, a, sizeof(a)), e->ansLen = sizeof(a), e->sw = 0x9000;
		e = conAdd();
		static const u8 big[] = { 0x00, 0x02, 0x00, 0x00, 0x00 };
		memcpy(e->cmd, big, 5), e->cmdLen = 5;
		for (int i = 0; i < 100; i++) e->ans[i] = i;
		e->ansLen = 100, e->sw = 0x9000;
		e = conAdd();
		static const u8 bad[] = { 0x80, 0xCA, 0x00, 0xFE, 0x00 };
		memcpy(e->cmd, bad, 5), e->cmdLen = 5, e->sw = 0x6A88;
		e = conAdd();
		memcpy(e->cmd, bad, 5), e->cmdLen = 5;
		snprintf(e->note, sizeof(e->note), "lost the card: no answer");
		memcpy(conCmd, bad, 5), conLen = 5;
	}
	apduConsole();
}
