// Card emulation image (BCM20791B5): loaded instead of memrw while the 3DS listens as a card whose
// protocol the ROM can't hand to the host in time (no WTX outside ISO-DEP: an Ultralight answers a READ
// within ~100 us). memrw's basic ops (same 2F 2C protocol, opcodes 0-4, so tools/chipmon.py and the
// app's mon.c drive it) plus:
//   op 5 EMU     -> 4F 2C | 00 | address of struct emu u32
// The host fills struct emu (WRITE8) and sets mode; the rest happens in the RX hook.
//
// The ROM's listen-A frame handler 0xFF84 (from the RX-done path 0x10114, interrupt context) first
// calls the RAM hook *(0x38518) with no arguments; nonzero = frame consumed. The frame (CRC included) is
// at *(0x38534), its length at u16 0x393AC, the listen state at byte 0x39369 (0 idle, 1-3 anticollision,
// 4 active, 5 halted, 6-8 anticollision after WUPA, 9 active again, 10 frame passed to the host).
// Anticollision, HLTA and RATS stay with the ROM; frames in the active states are answered here with
// the ROM's listen TX 0xF8E0(data, len, crc) (it waits for TX done), as its own ATQA path does.
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define CMD_HOOK  (*(volatile u32 *)0x38718)
#define OID_DEBUG 0x2C
#define MAX_DATA  0xF0

#define ROM_FN(addr, type) ((type)((addr) | 1))
#define nci_alloc ROM_FN(0x188C2, u8 *(*)(u32 total_len, u32 mt))
#define nci_send  ROM_FN(0x188E4, void (*)(u8 *pkt))
#define la_tx     ROM_FN(0xF8E0, void (*)(const u8 *data, u32 len, u32 crc))

#define REG(a)    (*(volatile u32 *)(a))
#define LA_HOOK   (*(volatile u32 *)0x38518)
#define LA_FRAME  (*(u8 *volatile *)0x38534)
#define LA_LEN    (*(volatile u16 *)0x393AC)
#define LA_STATE  (*(volatile u8 *)0x39369)

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_EMU };
enum { MODE_OFF, MODE_MFU };

#define MFU_MAX_PAGES 256
#define N_LOG 16 // power of two

// Shared with the host (nfcprobe emu.c, tools/exp/listen/mfuemu.py): keep the layout.
struct emu {
	u8 mode;
	u8 npages;       // MFU: pages in mem (READ rolls over here)
	u8 flags;        // bit 0 GET_VERSION answers, bit 1 READ_SIG answers, bit 2 check PWD_AUTH
	u8 pad0;
	u8 version[8];
	u8 sig[32];
	u8 cnt[3][3];    // READ_CNT, LSB first
	u8 pack[2];
	u8 pad1;
	u8 pwd[4];       // PWD_AUTH compares with this (bit 2); the PWD / PACK pages in mem read as zeros
	u32 frames;      // frames seen in the active states
	u32 writes;      // pages written (WRITE / COMPATIBILITY WRITE)
	u32 nlog;        // log[nlog % N_LOG] is next: state, len, first 6 bytes
	u8 log[N_LOG][8];
	u8 mem[MFU_MAX_PAGES * 4];
} emu __attribute__((section(".data")));

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

static u32 crc_a(const u8 *d, u32 n)
{
	u32 c = 0x6363;
	while (n--) {
		u32 b = (*d++ ^ c) & 0xFF;
		b = (b ^ (b << 4)) & 0xFF;
		c = (c >> 8) ^ (b << 8) ^ (b << 3) ^ (b >> 4);
	}
	return c & 0xFFFF;
}

// 4-bit answer (ACK 0xA, NACK 0x0): 0x5C568 = bytes << 4 | bits, as in reader mode (the listen TX
// doesn't set it; 4 gives a start bit + 4 bits on air).
static void tx4(u32 nib)
{
	u8 b = nib;
	u32 old = REG(0x5C568);
	REG(0x5C568) = 4;
	la_tx(&b, 1, 0);
	REG(0x5C568) = old;
}

static u8 cwrite_page; // COMPATIBILITY WRITE: page + 1 between its two frames

// READ: 4 pages from p, rolling over at npages.
static void tx_read(u32 p)
{
	static u8 b[16];
	for (u32 n = 0; n < 16; n += 4, p++) {
		if (p >= emu.npages) p -= emu.npages;
		for (u32 i = 0; i < 4; i++) b[n + i] = emu.mem[p * 4 + i];
	}
	la_tx(b, 16, 1);
}

static void write_page(u32 p, const u8 *d)
{
	u8 *m = emu.mem + p * 4;
	if (p < 2) return; // UID
	for (u32 i = 0; i < 4; i++) {
		if (p == 2 && i < 2) continue; // serial byte, internal
		m[i] = p < 4 ? m[i] | d[i] : d[i]; // lock bytes and OTP only set bits
	}
	emu.writes++;
}

static u32 mfu(const u8 *f, u32 len)
{
	u32 n = len - 2, np = emu.npages;
	if (cwrite_page) {
		u32 p = cwrite_page - 1;
		cwrite_page = 0;
		if (n != 16) return 1;
		write_page(p, f);
		tx4(0xA);
		return 1;
	}
	switch (f[0]) {
	case 0x30: // READ
		if (n != 2 || f[1] >= np) break;
		tx_read(f[1]);
		return 1;
	case 0x3A: // FAST_READ
		if (n != 3 || f[1] > f[2] || f[2] >= np) break;
		la_tx(emu.mem + f[1] * 4, (f[2] - f[1] + 1) * 4, 1);
		return 1;
	case 0x60: // GET_VERSION
		if (n != 1 || !(emu.flags & 1)) break;
		la_tx(emu.version, 8, 1);
		return 1;
	case 0x3C: // READ_SIG
		if (n != 2 || !(emu.flags & 2)) break;
		la_tx(emu.sig, 32, 1);
		return 1;
	case 0x39: // READ_CNT
		if (n != 2 || f[1] > 2) break;
		la_tx(emu.cnt[f[1]], 3, 1);
		return 1;
	case 0x1B: // PWD_AUTH
		if (n != 5) break;
		if (emu.flags & 4)
			for (u32 i = 0; i < 4; i++)
				if (f[1 + i] != emu.pwd[i]) goto nack;
		la_tx(emu.pack, 2, 1);
		return 1;
	case 0xA2: // WRITE
		if (n != 6 || f[1] >= np) break;
		write_page(f[1], f + 2);
		tx4(0xA);
		return 1;
	case 0xA0: // COMPATIBILITY WRITE: ACK, then 16 bytes of which the first 4 are written
		if (n != 2 || f[1] >= np) break;
		cwrite_page = f[1] + 1;
		tx4(0xA);
		return 1;
	case 0xE0: // RATS: an Ultralight has no ISO-DEP, stays quiet
		return 1;
	}
nack:
	tx4(0x0);
	LA_STATE = 0; // a NACK sends the card back to IDLE: the reader reselects (in the active state the
	              // ROM would take that WUPA as a reason to halt)
	return 1;
}

static u32 rx_hook(void)
{
	u32 st = LA_STATE;
	if (emu.mode == MODE_OFF || (st != 4 && st != 9)) return 0;
	const u8 *f = LA_FRAME;
	u32 len = LA_LEN;
	u8 *l = emu.log[emu.nlog++ % N_LOG];
	l[0] = st;
	l[1] = len;
	for (u32 i = 0; i < 6; i++) l[2 + i] = i < len ? f[i] : 0;
	// Anticollision, HLTA and RATS go to the ROM (it moves the state); so does an empty frame.
	if (!len || f[0] == 0x26 || f[0] == 0x52 || f[0] == 0x50 || f[0] == 0x93 || f[0] == 0x95 || f[0] == 0x97)
		return 0;
	emu.frames++;
	if (len < 3 || crc_a(f, len - 2) != (f[len - 2] | f[len - 1] << 8)) return 1; // a bad frame: no answer
	return mfu(f, len);
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
	case OP_CALL: {
		if (n < 16) break;
		u32 r = ((u32 (*)(u32, u32, u32, u32))(addr | 1))(get32(arg), get32(arg + 4), get32(arg + 8), get32(arg + 12));
		put32(buf, r);
		reply(0, buf, 4);
		return 1;
	}
	case OP_READ32:
		if (n < 1 || arg[0] > MAX_DATA / 4 || addr & 3) break;
		for (u32 i = 0; i < arg[0]; i++) put32(buf + 4 * i, ((volatile u32 *)addr)[i]);
		reply(0, buf, arg[0] * 4);
		return 1;
	case OP_WRITE32:
		if (n & 3 || addr & 3) break;
		for (u32 i = 0; i < n / 4; i++) ((volatile u32 *)addr)[i] = get32(arg + 4 * i);
		reply(0, 0, 0);
		return 1;
	case OP_EMU:
		put32(buf, (u32)&emu);
		reply(0, buf, 4);
		return 1;
	}
	reply(1, 0, 0);
	return 1;
}

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	extern u32 __bss_start[], __bss_end[];
	for (u32 *p = __bss_start; p < __bss_end; p++) *p = 0;
	CMD_HOOK = (u32)hook;
	LA_HOOK = (u32)rx_hook;
	return 0;
}
