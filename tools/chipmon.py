#!/usr/bin/env python3
"""Talk to the chip-side debug monitor (chip/memrw.c, vendor command 2F 2C).

    chipmon.py HOST load                       power cycle, download memrw, check it answers
    chipmon.py HOST read ADDR LEN [OUT]        byte reads (hex dump, or raw to OUT)
    chipmon.py HOST read32 ADDR WORDS          32-bit loads (MMIO)
    chipmon.py HOST write ADDR HEX             byte writes
    chipmon.py HOST write32 ADDR WORD...       32-bit stores
    chipmon.py HOST call ADDR [R0 [R1 [R2 [R3]]]]   call a Thumb function, print r0
All numbers hex. Commands other than load expect the monitor to be loaded already.
"""
import struct
import sys

import dumpchip
import mkpatch
import nfcnet

CHIP = __file__.rsplit("/", 2)[0] + "/chip/"
(OP_READ8, OP_WRITE8, OP_CALL, OP_READ32, OP_WRITE32, OP_CAPTURE, OP_TXRAW, OP_AUTH, OP_TXSCHED,
 OP_NESTED, OP_SNAP, OP_CHKKEYS, OP_DARKSIDE) = range(13)
CHUNK = 0xF0


class MonError(Exception):
    pass


class Mon:
    def __init__(self, nfc, on_other=None):
        self.nfc = nfc
        # Packets that arrive in place of a monitor answer (RF notifications while polling).
        self.on_other = on_other or (lambda pkt: print("  (other) " + nfcnet.describe(pkt)))

    def load(self):
        nfc = self.nfc
        nfc.takeover()
        if dumpchip.load(nfc, mkpatch.build(open(CHIP + "memrw.bin", "rb").read())) is None:
            raise MonError("chip dead after download")
        nfc.cmd(nfcnet.CORE_INIT)

    @staticmethod
    def _pkt(op, addr, data=b""):
        p = struct.pack("<BI", op, addr) + data
        return bytes([0x10, 0x2F, 0x2C, len(p)]) + p

    @staticmethod
    def _payload(pkt):
        if not pkt or pkt[:3] != b"\x10\x4f\x2c":
            raise MonError("unexpected answer: " + nfcnet.describe(pkt))
        if pkt[4] != 0:
            raise MonError(f"monitor status {pkt[4]:02X}")
        return pkt[5:]

    def _do(self, op, addr, data=b"", timeout_ms=1000, grace_ms=4000):
        """One monitor request. While the chip is busy with RF (error recovery, re-polling) the
        answer can come late, so after the first timeout wait up to grace_ms more."""
        pkt = self.nfc.xfer(self._pkt(op, addr, data), timeout_ms)
        if not pkt:
            pkt = self.nfc.read(grace_ms)
        for _ in range(16):
            if pkt[:3] == b"\x10\x4f\x2c" or not pkt:
                break
            self.on_other(pkt)
            pkt = self.nfc.read(timeout_ms)
        return self._payload(pkt)

    def _pipelined(self, reqs, window=32):
        """Send all request packets with up to `window` in flight; returns the payloads in order."""
        out, sent = [], 0
        for i in range(len(reqs)):
            while sent < len(reqs) and sent - i < window:
                self.nfc.send_call(nfcnet.OP_XFER, struct.pack("<H", 1000) + reqs[sent])
                sent += 1
            out.append(self._payload(self.nfc.recv_reply(nfcnet.OP_XFER)))
        return out

    def read(self, addr, length):
        reqs = [self._pkt(OP_READ8, a, bytes([min(CHUNK, addr + length - a)]))
                for a in range(addr, addr + length, CHUNK)]
        return b"".join(self._pipelined(reqs))

    def read32(self, addr, words):
        return list(struct.unpack(f"<{words}I", self._do(OP_READ32, addr, bytes([words]))))

    def write(self, addr, data):
        for o in range(0, len(data), CHUNK):
            self._do(OP_WRITE8, addr + o, data[o:o + CHUNK])

    def write32(self, addr, words):
        self._do(OP_WRITE32, addr, struct.pack(f"<{len(words)}I", *words))

    def capture(self, on=True):
        """Start/stop RX capture (memrw OP_CAPTURE); remembers the ring address."""
        self.ring = struct.unpack("<I", self._do(OP_CAPTURE, 0, bytes([1 if on else 0])))[0]
        self.seen = struct.unpack("<I", self.read(self.ring, 4))[0]

    def frames(self):
        """New captured frames since the last call: [(regs[5], data)]."""
        n_frames, size = 8, 4 + 20 + 1 + 36 + 3
        raw = self.read(self.ring, 4 + n_frames * size)
        count, out = struct.unpack_from("<I", raw)[0], []
        for seq in range(max(self.seen + 1, count - n_frames + 1), count + 1):
            o = 4 + ((seq - 1) % n_frames) * size
            fseq, *regs = struct.unpack_from("<6I", raw, o)
            if fseq == seq:
                out.append((regs, raw[o + 25:o + 25 + raw[o + 24]]))
        self.seen = count
        return out

    def txraw(self, data, code=None, r570=0, r574=1, r55c=0x88, pace=0):
        """Raw framer TX (memrw OP_TXRAW); code = bytes << 4 | extra bits, default whole bytes.
        pace is ignored (the FIFO takes a whole frame; kept for old scripts)."""
        code = len(data) << 4 if code is None else code
        self._do(OP_TXRAW, 0, bytes([r570, r574, code, r55c]) + data)

    def txsched(self, data, code, sched, r570=0, r574=1, r55c=0x88):
        """TX with timed register stores (memrw OP_TXSCHED): sched = [(ticks after the last FIFO
        write, reg, val)] ascending. Returns the TX busy time in ticks (1 MHz)."""
        p = bytes([r570, r574, code, r55c, len(sched)])
        p += b"".join(struct.pack("<HII", *e) for e in sched)
        return struct.unpack("<I", self._do(OP_TXSCHED, 0, p + data))[0]

    def auth(self, key, uid, nr, frame, code, nrar_tx=0):
        """On-chip Mifare Classic auth (memrw OP_AUTH): sends the parity-packed AUTH frame,
        answers nt with {nr}{ar} (sent with nrar_tx = r574 << 8 | length code, 0 = chip default).
        Returns (nt, cipher odd, cipher even) or None if no nt."""
        try:
            p = self._do(OP_AUTH, nrar_tx, bytes(key) + struct.pack(">IIB", uid, nr, code) + frame)
        except MonError as e:
            if "status 02" in str(e):
                return None
            raise
        return struct.unpack("<III", p)

    def nested(self, key, uid, nr, frame, code, nested_cmd, nrar_tx=0):
        """On-chip nested auth (memrw OP_NESTED): auth1 with the known key, then the nested AUTH
        command (nested_cmd = 4 plaintext bytes, 60/61 target + CRC) encrypted with the session
        cipher and sent at fixed cycles so the PRNG distance is stable. Returns nt0 (the known
        auth's plaintext nonce) or None; read the encrypted nested nonce from frames()."""
        arg = bytes(key) + struct.pack(">IIB", uid, nr, code) + bytes(nested_cmd) + frame
        try:
            p = self._do(OP_NESTED, nrar_tx, arg)
        except MonError:
            return None
        return struct.unpack("<I", p)[0]

    def darkside(self, steps, acode, aframe, nrar_frames, sync, tq=0, maxiter=40, atw=5000, nrar_tx=0,
                 nslot=1, need=None, sfr=0):
        """Darkside runs (memrw OP_DARKSIDE): fire AUTHs on a grid sync ticks apart, slot i taking every
        nslot-th grid point (sync * nslot = one PRNG period), each slot steering onto its own nonce
        (tq = ticks per PRNG step * 256; 0 = no steering, for calibration); stops when `need` slots
        (default all) are complete. steps: list of (r574, code, rx, bytes) re-select frames (parity
        on); acode/aframe: the AUTH frame (parity off, packed); nrar_frames: 8 packed 9-byte {nr}{ar}
        frames (parity off, nt_diff 0..7). Returns per slot (nt, ks[8], mask, hits): nt the slot's
        locked (first) nonce, mask a bit per filled nt_diff (0xFF = complete). Unsteered with 2 slots,
        the two nonces are a grid point apart (period calibration)."""
        arg = struct.pack("<IhHHHBBB", sync, sfr, maxiter, atw, tq, nslot,
                          nslot if need is None else need, len(steps))
        for r574, code, rx, data in steps:
            arg += bytes([r574, code, rx, len(data)]) + bytes(data)
        arg += bytes([acode, len(aframe)]) + bytes(aframe)
        for f in nrar_frames:
            assert len(f) == 9
            arg += bytes(f)
        self.nfc.sock.settimeout(60)
        try:
            p = self._do(OP_DARKSIDE, nrar_tx, arg, timeout_ms=45000, grace_ms=45000)
        finally:
            self.nfc.sock.settimeout(10)
        slots = []
        for i in range(nslot):  # memrw struct dslot: target, ph, ks[8], mask, hits, lost, pad
            o = 20 * i
            slots.append((struct.unpack_from("<I", p, o)[0], list(p[o + 8:o + 16]), p[o + 16], p[o + 17]))
        return slots

    def call(self, addr, *args):
        args = (list(args) + [0] * 4)[:4]
        return struct.unpack("<I", self._do(OP_CALL, addr, struct.pack("<4I", *args)))[0]


def hexdump(addr, data):
    for o in range(0, len(data), 16):
        row = data[o:o + 16]
        print(f"{addr + o:08X}: {row.hex(' '):48s} {''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}")


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    mon = Mon(nfcnet.Nfc(sys.argv[1]))
    what, args = sys.argv[2], sys.argv[3:]
    num = [int(a, 16) for a in args] if what not in ("write",) else None
    if what == "load":
        mon.load()
        print("monitor up, ROM reset vector:", hex(mon.read32(4, 1)[0]))
    elif what == "read":
        data = mon.read(num[0], num[1])
        if len(args) > 2:
            open(args[2], "wb").write(data)
        else:
            hexdump(num[0], data)
    elif what == "read32":
        for i, w in enumerate(mon.read32(num[0], num[1])):
            print(f"{num[0] + 4 * i:08X}: {w:08X}")
    elif what == "write":
        mon.write(int(args[0], 16), bytes.fromhex(args[1]))
    elif what == "write32":
        mon.write32(num[0], num[1:])
    elif what == "call":
        print(f"r0 = {mon.call(*num):08X}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
