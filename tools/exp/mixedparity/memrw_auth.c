// Chip-side debug monitor (BCM20791B5): memory read/write and function calls as a vendor
// NCI command, answered with a proper response.
//
// The ROM's NCI command dispatcher (0x189A2) calls the function pointer at RAM 0x38718 (if
// set, never written by the ROM) with every command that passed the OID range check; a
// nonzero return means the command was consumed. We take 2F 2C (unimplemented in ROM):
//   2F 2C | op u8 | addr u32 | ...
//   op 0 READ8    len u8                -> 4F 2C | 00 | len bytes
//   op 1 WRITE8   data...               -> 4F 2C | 00
//   op 2 CALL     r0 r1 r2 r3 (u32 each) -> 4F 2C | 00 | r0 u32   (addr = function, Thumb bit added)
//   op 3 READ32   len u8 (words)        -> 4F 2C | 00 | len*4 bytes, 32-bit loads (for MMIO)
//   op 4 WRITE32  words...              -> 4F 2C | 00, 32-bit stores
//   op 5 CAPTURE  on u8                 -> 4F 2C | 00 | ring address u32 | irq log address u32
//   op 6 TXRAW    r570 r574 r568 r55c (u8 each), data... -> 4F 2C | 00   (addr = pace, see txraw)
//                 the ROM's bit-mode TX (0x11DE + 0x1280) with every register value given:
//                 cmd 0x5C56C = 1, 0x5C570/574/568 framing (568 = bytes << 4 | bits),
//                 TX mode 0x5C55C, then the data into the TX byte port 0x5C600
//   op 7 AUTH     key[6] uid u32 nr u32 (big-endian, as on the wire) code u8, AUTH frame...
//                 (addr = ticks per byte << 16 | r574 << 8 | length code for the 72-bit {nr}{ar}
//                 frame; 0 = 0x178, not paced; paced = 6 bytes prefilled)
//                 -> 4F 2C | 00 | nt u32 | cipher odd u32 | even u32   (02 = no nt)
//                 Mifare Classic reader auth with the card's timing: TX the given (parity-packed)
//                 AUTH frame, wait for nt in the capture ring, answer {nr}{ar} right away. The
//                 host must have parity off (0x5C560 = 8) and capture on; it reads {at} from the
//                 ring and continues the session with the returned cipher state.
// Errors answer 4F 2C | 01.
//
// CAPTURE takes the framer's TX/RX interrupt group away from the ROM: the framer ISR (0x197E)
// reads that group's status from 0x5C5D0 (write-1-clear) and passes it through the RAM filter
// *(0x380D8) before acting on it (bit 4 = RX done -> 0x1372, bit 5 = TX done -> RF state
// machine). Our filter records RX-done frames (status registers + the RX FIFO, byte port
// 0x5C620) into a ring the host reads with READ8, and returns 0, so the ROM's state machine
// never sees our raw exchanges and doesn't time out and re-poll. Interrupt context: RAM only.
typedef unsigned int u32;
typedef unsigned char u8;

#define CMD_HOOK  (*(volatile u32 *)0x38718)
#define OID_DEBUG 0x2C
#define MAX_DATA  0xF0

#define ROM_FN(addr, type) ((type)((addr) | 1))
#define nci_alloc ROM_FN(0x188C2, u8 *(*)(u32 total_len, u32 mt)) // [hdr 3][payload], len set
#define nci_send  ROM_FN(0x188E4, void (*)(u8 *pkt))

#define RF_FILTER   (*(volatile u32 *)0x380D4) // group 0x5C5C4 (ISR bit 2, handler 0x15F2)
#define TXRX_FILTER (*(volatile u32 *)0x380D8) // group 0x5C5D0 (ISR bit 1, handler 0x1736)
#define TMR_FILTER  (*(volatile u32 *)0x380DC) // group 0x5C5DC (ISR bit 0, handler 0x18FE)
#define TIMER       (*(volatile u32 *)0x5E024) // free-running counter (ROM 0x1C56)
#define TXRX_RX_DONE 0x10
#define REG(a)    (*(volatile u32 *)(a))
#define RX_PORT   (*(volatile u8 *)0x5C620)
#define TX_PORT   (*(volatile u8 *)0x5C600)

#define irq_save    ROM_FN(0xC5C, u32 (*)(void))
#define irq_restore ROM_FN(0xC64, void (*)(u32))

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_CAPTURE, OP_TXRAW, OP_AUTH, OP_TXTIME };

// Captured frames: regs = TX/RX status (0x5C5D0), 0x5C588, 0x5C58C, 0x5C598, 0x5C5A0 (RX bytes).
#define N_FRAMES   16
#define FRAME_DATA 28
struct frame {
	u32 seq; // 0 = empty
	u32 regs[5];
	u8 len;  // bytes popped
	u8 data[FRAME_DATA];
	u8 pad[3];
};
static struct {
	u32 count; // frames captured so far; frame i is in ring[(i - 1) % N_FRAMES], seq = i
	struct frame ring[N_FRAMES];
} capture;
static u32 capturing;

// Interrupt log while capturing: (timer << 8 | group, status) pairs, for debugging hangs.
// Group 3 = TX started by us (status = length code).
#define N_LOG 8
static struct {
	u32 count;
	u32 ent[N_LOG][2];
} irqlog;

static void log_irq(u32 group, u32 status)
{
	u32 *e = irqlog.ent[irqlog.count++ % N_LOG];
	e[0] = TIMER << 8 | group;
	e[1] = status;
}

static u32 rf_filter(u32 status)
{
	if (capturing) log_irq(0, status);
	return status;
}

static u32 tmr_filter(u32 status)
{
	if (capturing) log_irq(2, status);
	return status;
}

int init(void);

__attribute__((section(".entry"), used)) int (*const entry)(void) = init;

static u32 get32(const u8 *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((u32)p[3] << 24);
}

static u32 get32be(const u8 *p)
{
	return (u32)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
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

static u32 txrx_filter(u32 status)
{
	if (!capturing) return status;
	log_irq(1, status);
	if (!(status & TXRX_RX_DONE)) return 0;
	struct frame *f = &capture.ring[capture.count % N_FRAMES];
	static const u32 regs[5] = { 0, 0x5C588, 0x5C58C, 0x5C598, 0x5C5A0 };
	f->regs[0] = status;
	for (int i = 1; i < 5; i++) f->regs[i] = REG(regs[i]);
	u32 n = f->regs[4];
	if (n > FRAME_DATA) n = FRAME_DATA;
	for (u32 i = 0; i < n; i++) f->data[i] = RX_PORT;
	f->len = n;
	f->seq = ++capture.count;
	return 0;
}

// The ROM's bit-mode TX with every register value given (see OP_TXRAW).
// pace = prefill << 16 | ticks per byte: write only `prefill` bytes up front and feed the rest one
// per `ticks` while the frame goes out (0 = all at once).
static void txraw(u32 r570, u32 r574, u32 code, u32 r55c, const u8 *data, u32 len, u32 pace)
{
	// After an RX the framer must get cmd 1 some time before the next TX setup, or the TX
	// hangs the chip (writing it from the RX interrupt is too early).
	REG(0x5C56C) = 1;
	for (u32 t0 = TIMER; t0 - TIMER < 50;) // ~1 MHz down-counter
		;
	u32 irq = irq_save();
	REG(0x5C56C) = 1;
	REG(0x5C570) = r570;
	REG(0x5C574) = r574;
	REG(0x5C568) = code;
	REG(0x5C55C) = r55c;
	(void)pace;
	if (capturing) log_irq(3, code);
	for (u32 i = 0; i < len; i++) TX_PORT = data[i];
	irq_restore(irq);
}

// Crypto1, crapto1's reference form (odd/even LFSR halves); tools/crypto1.py is the same.
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

static u32 getbit(const u8 *p, u32 i)
{
	return p[i >> 3] >> (i & 7) & 1;
}

static void putbit(u8 *p, u32 i, u32 v)
{
	p[i >> 3] |= v << (i & 7);
}

// Reader side of the 3-pass auth (first auth, plaintext nt). Returns 0 if no nt came back.
static int auth(const u8 *key, u32 uid, u32 nr, u32 code, const u8 *frame, u32 len, u32 nrar_tx, u32 pace, u32 *nt_out)
{
	u32 seen = capture.count;
	txraw(0, 1, code, 0x88, frame, len, 0);
	for (u32 t0 = TIMER; *(volatile u32 *)&capture.count == seen;) // set by the RX interrupt
		if (t0 - TIMER > 20000) return 0;
	// nt, 4 bytes + parity; the RX bit stream continues where the 36-bit AUTH frame left off
	struct frame *f = &capture.ring[(capture.count - 1) % N_FRAMES];
	if (f->len < 5) return 0;
	u32 nt = 0;
	for (u32 j = 0; j < 4; j++)
		for (u32 k = 0; k < 8; k++) nt |= getbit(f->data, 4 + 9 * j + k) << (24 - 8 * j + k);
	*nt_out = nt;
	c1_odd = c1_even = 0;
	for (int i = 47; i > 0; i -= 2) { // key as a 48-bit big-endian number
		u32 o = (i - 1) ^ 7, e = i ^ 7;
		c1_odd = c1_odd << 1 | (key[5 - (o >> 3)] >> (o & 7) & 1);
		c1_even = c1_even << 1 | (key[5 - (e >> 3)] >> (e & 7) & 1);
	}
	u32 un = uid ^ nt;
	for (u32 i = 0; i < 32; i++) c1_bit(un >> (i ^ 24) & 1);
	// {nr}{ar}: 8 bytes, each followed by its encrypted parity bit
	static u8 out[9];
	for (int i = 0; i < 9; i++) out[i] = 0;
	u32 ar = prng_successor(nt, 64);
	for (u32 i = 0; i < 8; i++) {
		u32 b = i < 4 ? nr >> (24 - 8 * i) & 0xFF : ar >> (56 - 8 * i) & 0xFF;
		u32 c = c1_byte(i < 4 ? b : 0) ^ b;
		for (u32 k = 0; k < 8; k++) putbit(out, 9 * i + k, c >> k & 1);
		putbit(out, 9 * i + 8, c1_filter() ^ 1 ^ parity(b));
	}
	txraw(0, nrar_tx >> 8 & 0xFF, nrar_tx & 0xFF, 0x88, out, 9, pace);
	return 1;
}

// Experiment: txraw, then time TX busy (0x5C594 bit 0) and do up to 8 scheduled stores
// (delay ticks after the last FIFO write, reg, val), in delay order. a: r570 r574 code r55c
// nsched u32, nsched * (delay, reg, val) u32. Returns ticks (start -> busy clear), ticks at each store.
static u32 txtime(const u8 *a, u32 n, u8 *out)
{
	u32 ns = get32(a + 4);
	if (ns > 8 || n < 8 + 12 * ns) return 0;
	const u8 *sc = a + 8, *data = sc + 12 * ns;
	u32 len = n - 8 - 12 * ns, k = 0, done = 0;
	REG(0x5C56C) = 1;
	for (u32 t0 = TIMER; t0 - TIMER < 50;)
		;
	u32 irq = irq_save();
	REG(0x5C56C) = 1;
	REG(0x5C570) = a[0];
	REG(0x5C574) = a[1];
	REG(0x5C568) = a[2];
	REG(0x5C55C) = a[3];
	u32 t = TIMER;
	if (capturing) log_irq(3, a[2]);
	for (u32 i = 0; i < len; i++) TX_PORT = data[i];
	u32 tl = TIMER;
	while (t - TIMER < 30000) {
		if (k < ns && tl - TIMER >= get32(sc + 12 * k)) {
			REG(get32(sc + 12 * k + 4)) = get32(sc + 12 * k + 8);
			put32(out + 4 + 4 * k++, t - TIMER);
		}
		if (!(REG(0x5C594) & 1)) {
			done = t - TIMER;
			break;
		}
	}
	irq_restore(irq);
	put32(out, done);
	return 4 + 4 * ns;
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
	static u8 buf[MAX_DATA]; // not on the stack: the NCI task stack size is unknown

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
	case OP_CAPTURE:
		if (n < 1) break;
		capturing = arg[0];
		TXRX_FILTER = (u32)txrx_filter;
		RF_FILTER = (u32)rf_filter;
		TMR_FILTER = (u32)tmr_filter;
		put32(buf, (u32)&capture);
		put32(buf + 4, (u32)&irqlog);
		reply(0, buf, 8);
		return 1;
	case OP_TXRAW:
		if (n < 4) break;
		txraw(arg[0], arg[1], arg[2], arg[3], arg + 4, n - 4, addr);
		reply(0, 0, 0);
		return 1;
	case OP_AUTH: {
		if (n < 15) break;
		u32 nt;
		if (!auth(arg, get32be(arg + 6), get32be(arg + 10), arg[14], arg + 15, n - 15, addr & 0xFFFF ? addr & 0xFFFF : 0x178, (addr >> 16) ? (6 << 16 | addr >> 16) : 0, &nt)) {
			reply(2, 0, 0);
			return 1;
		}
		put32(buf, nt);
		put32(buf + 4, c1_odd);
		put32(buf + 8, c1_even);
		reply(0, buf, 12);
		return 1;
	}
	case OP_TXTIME: {
		if (n < 8) break;
		u32 r = txtime(arg, n, buf);
		if (!r) break;
		reply(0, buf, r);
		return 1;
	}
	}
	reply(1, 0, 0);
	return 1;
}

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	CMD_HOOK = (u32)hook;
	return 0;
}
