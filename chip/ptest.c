// Experiment (not in the app): look for a parity control in listen-mode TX. reader.c's READ8 / WRITE8 /
// READ32 (tools/chipmon.py drives it), plus
//   op 5 PT  -> 4F 2C | 00 | address (u32) of struct pt
//   op 6 RUN -> 4F 2C | 00 | pt.reps u32 TX times (ticks), sent from the command context while a reader
//               holds the field with the 3DS selected (listen state 4)
// The TX is the ROM's listen TX 0xF8E0 rebuilt, with pt.w[] applied after its setup, right before the FIFO
// fill (how: 0 write, 1 OR, 2 AND-NOT), and undone after. A frame starting E5 in states 4 / 9 is answered
// the same way (for a reader to see what goes out), E5 nn with test nn's write; other frames go to the ROM.
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define CMD_HOOK  (*(volatile u32 *)0x38718)
#define OID_DEBUG 0x2C
#define MAX_DATA  0xF0

#define ROM_FN(addr, type) ((type)((addr) | 1))
#define nci_alloc ROM_FN(0x188C2, u8 *(*)(u32 total_len, u32 mt))
#define nci_send  ROM_FN(0x188E4, void (*)(u8 *pkt))

#define REG(a)    (*(volatile u32 *)(a))
#define TIMER     (*(volatile u32 *)0x5E024) // free-running 1 MHz down-counter
#define LA_HOOK   (*(volatile u32 *)0x38518)
#define LA_FRAME  (*(u8 *volatile *)0x38534)
#define LA_LEN    (*(volatile u16 *)0x393AC)
#define LA_STATE  (*(volatile u8 *)0x39369)

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_PT, OP_RUN };

struct pt {
	u32 nw;
	u32 w[8][3];   // addr, value, how
	u32 n, crc;
	u8 data[32];
	u32 reps;
	u32 frames;    // E5 frames answered
	u32 r568;      // 0x5C568 during the TX (0: leave it)
	u32 old[8];    // the registers before the writes (last TX)
	u32 during[8]; // and right after them
	u32 t[64][3];  // E5 nn: test nn = one write (addr, value, how) for that TX
	u32 time[64];  // and its TX time
	u32 nfix;      // E5 frames: w[0..nfix) stay, the test's write goes after them
	u32 delay;     // ticks to wait before the TX (an answer computed late)
	u32 order;     // 1: the TX command (0x5C56C = 2) last, after the writes and the FIFO
} pt __attribute__((section(".data"))); // in the image: too big for the AON RAM

int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;

static u32 get32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24);
}

static void put32(u8 *p, u32 v)
{
	for (int i = 0; i < 4; i++) p[i] = v >> (8 * i);
}

static void reply(u32 status, const u8 *data, u32 len)
{
	u8 *pkt = nci_alloc(3 + 1 + len, 2);
	if (!pkt) return;
	pkt[0] |= 0xF;
	pkt[1] = OID_DEBUG;
	pkt[3] = status;
	for (u32 i = 0; i < len; i++) pkt[4 + i] = data[i];
	nci_send(pkt);
}

// 0xF8E0 without the patch hook: 0x5C56C = 2, CRC on / off (0x5C560 0x84 / 0x44, plus bit 4 of 0x5C01C or
// the 0x5C000 register 0x5C580 selects, and 0x5C040 bit 7), 0x5C55C = 0x88, FIFO, wait.
static u32 tx(void)
{
	u32 r580 = REG(0x5C580), sel = r580 & 0x80 ? 0x5C000 + ((r580 & 0x7F) >> 4) * 4 : 0x5C01C;
	u32 t0 = TIMER;
	while (t0 - TIMER < pt.delay)
		;
	u32 r568 = REG(0x5C568);
	if (pt.r568) REG(0x5C568) = pt.r568; // before the command, as tx4 in emu.c
	if (!pt.order) REG(0x5C56C) = 2;
	if (pt.crc) {
		REG(sel) &= ~0x10;
	} else {
		REG(sel) |= 0x10;
	}
	if (!(r580 & 0x80)) REG(0x5C040) |= 0x80;
	REG(0x5C560) = pt.crc ? 0x84 : 0x44;
	REG(0x5C55C) = 0x88;
	u32 nw = pt.nw > 8 ? 8 : pt.nw;
	for (u32 i = 0; i < nw; i++) {
		volatile u32 *r = (volatile u32 *)pt.w[i][0];
		u32 v = pt.w[i][1], o = *r;
		pt.old[i] = o;
		*r = pt.w[i][2] == 1 ? o | v : pt.w[i][2] == 2 ? o & ~v : v;
		pt.during[i] = *r;
	}
	u32 t = 0;
	for (u32 i = 0; i < pt.n && i < 32; i++) REG(0x5C600) = pt.data[i];
	if (pt.order) REG(0x5C56C) = 2;
	t0 = TIMER;
	while (REG(0x5C594) & 1)
		if ((t = t0 - TIMER) > 30000) break;
	t = t0 - TIMER;
	for (u32 i = nw; i--;) {
		volatile u32 *r = (volatile u32 *)pt.w[i][0];
		if (pt.w[i][2] == 0) *r = pt.old[i];
		else if (pt.w[i][2] == 1) *r = pt.old[i] & pt.w[i][1] ? *r | pt.w[i][1] : *r & ~pt.w[i][1];
		else *r = pt.old[i] & pt.w[i][1] ? *r | pt.w[i][1] : *r & ~pt.w[i][1];
	}
	REG(0x5C568) = r568;
	REG(0x5C56C) = 2;
	REG(sel) &= ~0x10;
	if (!(r580 & 0x80)) REG(0x5C040) &= ~0x80;
	REG(0x5C560) = 0x84;
	return t;
}

static u32 rx_hook(void)
{
	u32 st = LA_STATE;
	if ((st != 4 && st != 9) || !LA_LEN || LA_FRAME[0] != 0xE5) return 0;
	u32 k = LA_LEN > 1 ? LA_FRAME[1] & 63 : 0;
	pt.frames++;
	u32 n = pt.nfix > 7 ? 7 : pt.nfix;
	if (pt.t[k][0]) {
		pt.w[n][0] = pt.t[k][0];
		pt.w[n][1] = pt.t[k][1];
		pt.w[n][2] = pt.t[k][2];
		n++;
	}
	pt.nw = n;
	pt.time[k] = tx();
	return 1;
}

static int hook(u8 *msg)
{
	if ((msg[0] & 0xF) != 0xF || (msg[1] & 0x3F) != OID_DEBUG) return 0;
	u32 len = msg[2];
	const u8 *p = msg + 3;
	if (len < 5) {
		reply(1, 0, 0);
		return 1;
	}
	u32 addr = get32(p + 1), n = len - 5;
	const u8 *arg = p + 5;
	static u8 buf[MAX_DATA] __attribute__((aligned(4)));

	switch (p[0]) {
	case OP_READ8:
		if (n < 1 || arg[0] > MAX_DATA) break;
		for (u32 i = 0; i < arg[0]; i++) buf[i] = ((volatile u8 *)addr)[i];
		reply(0, buf, arg[0]);
		return 1;
	case OP_WRITE8:
		for (u32 i = 0; i < n; i++) ((volatile u8 *)addr)[i] = arg[i];
		reply(0, 0, 0);
		return 1;
	case OP_READ32:
		if (n < 1 || arg[0] > MAX_DATA / 4 || addr & 3) break;
		for (u32 i = 0; i < arg[0]; i++) put32(buf + 4 * i, ((volatile u32 *)addr)[i]);
		reply(0, buf, arg[0] * 4);
		return 1;
	case OP_PT:
		put32(buf, (u32)&pt);
		reply(0, buf, 4);
		return 1;
	case OP_RUN:
		for (u32 i = 0; i < pt.reps && i < MAX_DATA / 4; i++) put32(buf + 4 * i, tx());
		reply(0, buf, (pt.reps < MAX_DATA / 4 ? pt.reps : MAX_DATA / 4) * 4);
		return 1;
	}
	reply(1, 0, 0);
	return 1;
}

__attribute__((section(".text.init"))) int init(void)
{
	extern u32 __bss_start[], __bss_end[];
	for (u32 *p = __bss_start; p < __bss_end; p++) *p = 0;
	CMD_HOOK = (u32)hook;
	LA_HOOK = (u32)rx_hook;
	return 0;
}
