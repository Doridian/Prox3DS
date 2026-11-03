// Card emulation image (BCM20791B5): loaded instead of memrw while the 3DS listens as a card whose
// protocol the ROM can't hand to the host in time (no WTX outside ISO-DEP: an Ultralight answers a READ
// within ~100 us). memrw's protocol (2F 2C) with READ8 0, WRITE8 1 and READ32 3 only (no room for
// CALL / WRITE32), so tools/chipmon.py and the app's mon.c drive it, plus:
//   op 5 EMU     -> 4F 2C | 00 | addresses (u32) of struct emu, the frame log, the page / block memory
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
#define TIMER     (*(volatile u32 *)0x5E024) // free-running 1 MHz down-counter
#define LA_HOOK   (*(volatile u32 *)0x38518)
#define LA_FRAME  (*(u8 *volatile *)0x38534)
#define LA_LEN    (*(volatile u16 *)0x393AC)
#define LA_STATE  (*(volatile u8 *)0x39369)

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_EMU };
enum { MODE_OFF, MODE_MFU, MODE_MFC = 3 };

#define MFU_MAX_PAGES 256
#define N_LOG 16 // power of two

// Shared with the host (nfcprobe emu.c, tools/exp/listen/mfuemu.py): keep the layout.
struct emu {
	u8 mode;
	u8 npages;       // MFU: pages in mem (READ rolls over here); MFC: blocks (64 = 1K, 20 = Mini)
	u8 flags;        // bit 0 GET_VERSION answers, bit 1 READ_SIG answers, bit 2 check PWD_AUTH
	u8 pad0;
	u8 version[8];   // MFC: [0..3] = the UID bytes Crypto1 takes (the last 4 of a 7-byte UID)
	u8 sig[32];
	u8 cnt[3][3];    // READ_CNT, LSB first
	u8 pack[2];
	u8 pad1;
	u8 pwd[4];       // PWD_AUTH compares with this (bit 2); the PWD / PACK pages in mem read as zeros
	u32 frames;      // frames seen in the active states
	u32 writes;      // pages written (WRITE / COMPATIBILITY WRITE)
	u32 nlog;        // elog[nlog % N_LOG] is next
} emu; // zeroed AON RAM (init), like elog: only emem is in the downloaded image
static u8 emem[MFU_MAX_PAGES * 4] __attribute__((section(".data"))); // MFU pages / MFC blocks
static u8 elog[N_LOG][8]; // frames in the active states: state (| 0x80: decrypted), len, first 6 bytes
                          // (zeroed AON RAM, not downloaded)

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

#define AON __attribute__((section(".aon"), noinline)) // code in the AON RAM (link.ld): no room in the image

AON static void reply(u32 status, const u8 *data, u32 len)
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
		for (u32 i = 0; i < 4; i++) b[n + i] = emem[p * 4 + i];
	}
	la_tx(b, 16, 1);
}

static void write_page(u32 p, const u8 *d)
{
	u8 *m = emem + p * 4;
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
		la_tx(emem + f[1] * 4, (f[2] - f[1] + 1) * 4, 1);
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


// --- MIFARE Classic, card side ---
// Crypto1 as in chip/memrw.c (crapto1's odd/even halves). The reader's frames arrive with the parity
// bits stripped (encrypted parity or not); ours go out with their encrypted parity as a raw bit stream
// (tx_par).
static u32 c1_odd, c1_even;

static u32 parity(u32 x)
{
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;
	x ^= x >> 2;
	return (x ^ x >> 1) & 1;
}

static u32 c1_filter(void)
{
	u32 x = c1_odd, f;
	f = 0xf22c0 >> (x & 0xf) & 16;
	f |= 0x6c9c0 >> (x >> 4 & 0xf) & 8;
	f |= 0x3c8b0 >> (x >> 8 & 0xf) & 4;
	f |= 0x1e458 >> (x >> 12 & 0xf) & 2;
	f |= 0x0d938 >> (x >> 16 & 0xf) & 1;
	return 0xEC57E80A >> f & 1;
}

static u32 c1_bit(u32 in)
{
	u32 ret = c1_filter();
	u32 t = c1_odd;
	c1_odd = (c1_even << 1 | parity(in ^ (0x29CE5C & c1_odd) ^ (0x870804 & c1_even))) & 0xFFFFFF;
	c1_even = t;
	return ret;
}

static u32 c1_byte(u32 in)
{
	u32 ret = 0;
	for (int i = 0; i < 8; i++) ret |= c1_bit(in >> i & 1) << i;
	return ret;
}

static u32 swap32(u32 x)
{
	return x >> 24 | (x >> 8 & 0xFF00) | (x << 8 & 0xFF0000) | x << 24;
}

static u32 prng_successor(u32 x, int n)
{
	x = swap32(x);
	while (n--) x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
	return swap32(x);
}

static enum { C_IDLE, C_NT, C_AUTH } cst;
static u32 c_nt;
static u8 c_wblock; // WRITE: block + 1 between the command and its data

// A frame with our own parity bits (bit i of par: byte i's): the ROM's listen TX 0xF8E0 (no CRC; 0x5C580 bit 7
// clear, as in listen A) with slot 0's mode 1 -> 5 between its setup and the FIFO (0x5C000 bit 2: no hardware
// parity, the FIFO bytes go out as a bit stream, MSB first) + 0x20 (whole 9-bit groups only, the padding
// dropped): 9 bits per byte packed into the FIFO. With the mode set before the TX command, the frame came
// out a bit early or late.
static void tx_par(const u8 *d, u32 n, u32 par)
{
	volatile u32 *z = (volatile u32 *)0x5C000, *f = (volatile u32 *)0x5C55C, *fifo = (volatile u32 *)0x5C600;
	f[4] = 2;        // 0x5C56C
	z[7] |= 0x10;    // 0x5C01C
	z[16] |= 0x80;   // 0x5C040
	f[1] = 0x44;     // 0x5C560
	f[0] = 0x88;     // 0x5C55C
	u32 old = z[0];
	z[0] = old | 0x34;
	u32 acc = 0, nb = 0;
	for (u32 i = 0; i < n; i++) {
		u32 w = d[i] | (par >> i & 1) << 8;
		for (u32 k = 0; k < 9; k++) {
			acc = acc << 1 | (w >> k & 1);
			if (!(++nb & 7)) *fifo = acc;
		}
	}
	if (nb & 7) *fifo = acc << (8 - (nb & 7));
	u32 t0 = TIMER;
	while (f[14] & 1 && t0 - TIMER < 30000) // 0x5C594: TX busy
		;
	z[0] = old;
	z[7] &= ~0x10;
	z[16] &= ~0x80;
	f[1] = 0x84;
}

static void c1_key(const u8 *key)
{
	c1_odd = c1_even = 0;
	for (int i = 47; i > 0; i -= 2) { // key as a 48-bit big-endian number
		u32 o = (i - 1) ^ 7, e = i ^ 7;
		c1_odd = c1_odd << 1 | (key[5 - (o >> 3)] >> (o & 7) & 1);
		c1_even = c1_even << 1 | (key[5 - (e >> 3)] >> (e & 7) & 1);
	}
}

// Encrypts in place, feeding feed (NULL: zeros); parity: the plain byte's, encrypted with the next keystream bit.
static void c_tx(u8 *d, u32 n, const u8 *feed)
{
	u32 par = 0;
	for (u32 i = 0; i < n; i++) {
		u32 p = parity(d[i]) ^ 1;
		d[i] ^= c1_byte(feed ? feed[i] : 0);
		par |= (p ^ c1_filter()) << i;
	}
	tx_par(d, n, par);
}

// AUTH: load the sector's key, feed uid ^ nt; nt goes out plain (first auth) or encrypted (nested).
static void c_auth(u32 keyB, u32 blk, u32 nested)
{
	static u8 b[4], un[4];
	const u8 *tr = emem + (blk | 3) * 16;
	// a real PRNG state, some steps on from the last one (stepping to a random index takes too long)
	c_nt = prng_successor(c_nt ? c_nt : 0x01200145, 16 + (TIMER & 63));
	c1_key(tr + (keyB ? 10 : 0));
	for (u32 i = 0; i < 4; i++) {
		b[i] = c_nt >> (24 - 8 * i);
		un[i] = b[i] ^ emu.version[i];
	}
	if (nested) {
		c_tx(b, 4, un);
	} else {
		for (u32 i = 0; i < 4; i++) c1_byte(un[i]);
		la_tx(b, 4, 0);
	}
	cst = C_NT;
}

static void c_tx4(u32 nib)
{
	u32 k = 0;
	for (int i = 0; i < 4; i++) k |= c1_bit(0) << i;
	tx4(nib ^ k);
}

static void c_nack(void)
{
	if (cst == C_AUTH) c_tx4(0x4);
	else tx4(0x4);
	cst = C_IDLE;
	LA_STATE = 0;
}

static u32 mfc(const u8 *f, u32 len)
{
	static u8 d[18];
	u32 nb = emu.npages;
	if (cst == C_NT) { // {nr}{ar}: nr fed in encrypted, ar checked, {at} back
		cst = C_IDLE;
		if (len != 8) return 1;
		for (u32 i = 0; i < 4; i++)
			for (u32 k = 0; k < 8; k++) {
				u32 e = f[i] >> k & 1;
				c1_bit(e ^ c1_filter());
			}
		u32 ar = 0;
		for (u32 i = 0; i < 4; i++) ar = ar << 8 | (f[4 + i] ^ c1_byte(0));
		if (ar != prng_successor(c_nt, 64)) { // a wrong key: the card stays quiet
			LA_STATE = 0;
			return 1;
		}
		u32 at = prng_successor(c_nt, 96);
		for (u32 i = 0; i < 4; i++) d[i] = at >> (24 - 8 * i);
		c_tx(d, 4, 0);
		cst = C_AUTH;
		c_wblock = 0;
		return 1;
	}
	if (cst == C_IDLE) { // plaintext: only AUTH
		if (len != 4 || crc_a(f, 2) != (f[2] | f[3] << 8)) return 1;
		if ((f[0] == 0x60 || f[0] == 0x61) && f[1] < nb) {
			c_auth(f[0] & 1, f[1], 0);
			return 1;
		}
		c_nack();
		return 1;
	}
	// authenticated: everything encrypted
	if (len > sizeof(d)) return 1;
	for (u32 i = 0; i < len; i++) d[i] = f[i] ^ c1_byte(0);
	u8 *l = elog[(emu.nlog - 1) % N_LOG]; // the log shows the plaintext (state | 0x80)
	l[0] |= 0x80;
	for (u32 i = 0; i < 6; i++) l[2 + i] = d[i];
	if (len < 3 || crc_a(d, len - 2) != (d[len - 2] | d[len - 1] << 8)) {
		c_nack();
		return 1;
	}
	if (c_wblock) { // WRITE data
		u32 blk = c_wblock - 1;
		c_wblock = 0;
		if (len != 18 || !blk) { // block 0 stays (manufacturer block)
			c_nack();
			return 1;
		}
		for (u32 i = 0; i < 16; i++) emem[blk * 16 + i] = d[i];
		emu.writes++;
		c_tx4(0xA);
		return 1;
	}
	if (len != 4) {
		c_nack();
		return 1;
	}
	switch (d[0]) {
	case 0x30: { // READ: a trailer shows key A as zeros, key B only where its access bits allow
		u32 blk = d[1];
		if (blk >= nb) break;
		const u8 *m = emem + blk * 16;
		for (u32 i = 0; i < 16; i++) d[i] = m[i];
		if ((blk & 3) == 3) {
			u32 c = (m[7] >> 7 & 1) << 2 | (m[8] >> 3 & 1) << 1 | (m[8] >> 7 & 1);
			for (u32 i = 0; i < 6; i++) d[i] = 0;
			if (c != 0 && c != 1 && c != 2)
				for (u32 i = 10; i < 16; i++) d[i] = 0;
		}
		u32 c = crc_a(d, 16);
		d[16] = c, d[17] = c >> 8;
		c_tx(d, 18, 0);
		return 1;
	}
	case 0xA0: // WRITE
		if (d[1] >= nb) break;
		c_wblock = d[1] + 1;
		c_tx4(0xA);
		return 1;
	case 0x60: case 0x61: // nested AUTH
		if (d[1] >= nb) break;
		c_auth(d[0] & 1, d[1], 1);
		return 1;
	case 0x50: // HALT
		cst = C_IDLE;
		LA_STATE = 5;
		return 1;
	}
	c_nack();
	return 1;
}

static u32 rx_hook(void)
{
	u32 st = LA_STATE;
	if (st != 4 && st != 9) cst = C_IDLE; // a new selection
	if (emu.mode == MODE_OFF || (st != 4 && st != 9)) return 0;
	const u8 *f = LA_FRAME;
	u32 len = LA_LEN;
	u8 *l = elog[emu.nlog++ % N_LOG];
	l[0] = st;
	l[1] = len;
	for (u32 i = 0; i < 6; i++) l[2 + i] = f[i]; // past len: stale buffer bytes, not shown
	// Classic, authenticated: encrypted frames (4, 8 or 18 bytes) can start with any byte
	if (emu.mode == MODE_MFC && cst != C_IDLE && (len == 4 || len == 8 || len == 18)) {
		emu.frames++;
		return mfc(f, len);
	}
	// Anticollision, HLTA and RATS go to the ROM (it moves the state); so does an empty frame.
	if (!len || f[0] == 0x26 || f[0] == 0x52 || f[0] == 0x50 || f[0] == 0x93 || f[0] == 0x95 || f[0] == 0x97)
		return 0;
	emu.frames++;
	if (emu.mode == MODE_MFC) return mfc(f, len);
	if (len < 3 || crc_a(f, len - 2) != (f[len - 2] | f[len - 1] << 8)) return 1; // a bad frame: no answer
	return mfu(f, len);
}

AON static int hook(u8 *msg)
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
		reply(0, (const u8 *)addr, arg[0]);
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
	case OP_EMU:
		put32(buf, (u32)&emu);
		put32(buf + 4, (u32)elog);
		put32(buf + 8, (u32)emem);
		reply(0, buf, 12);
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
