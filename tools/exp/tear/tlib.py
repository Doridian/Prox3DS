# Shared bits for the tear-off experiments (#18): an activated Ultralight EV1 through the monitor,
# reselect after a power cut, data-mode commands, and the timed field cut (0x5C360: 6 on, 0 off; it
# acts at once, even mid-transaction, unlike 0x5C054 which the framer latches per TX).
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc, crc_a

FIELD, OFF, ON = 0x5C360, 0, 6
HOLD = 2000


class Ev1:
    def __init__(self, host):
        self.s = Session(host)
        self.s.recover()
        self.u = self.s.uid

    def resel(self):
        s, u = self.s, self.u
        for _ in range(4):
            if s.answer(b'\x52', 0x07) is None:
                continue
            s.answer(b'\x93\x20'); s.answer(b'\x93\x70\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
            s.answer(b'\x95\x20')
            if s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]])) is not None:
                return True
        return False

    def cmd(self, c):
        """Data mode (HW CRC); the answer without CRC, b'ACK'/'NAK' for 4 bits, None."""
        a = self.s.data_tx(bytes(c))
        if a is None:
            return None
        if len(a) == 1:
            return b'ACK' if a[0] & 0xF == 0xA else b'NAK'
        return a[:-2] if len(a) >= 3 and crc_a(a[:-2]) == a[-2:] else None

    def ok(self, c):
        r = self.cmd(c)
        if r is None or r == b'NAK':
            self.resel()
        return r

    def cnt(self, i):
        r = self.ok([0x39, i])
        return int.from_bytes(r, 'little') if r and len(r) == 3 else None

    def tear_flag(self, i):
        r = self.ok([0x3E, i])
        return r[0] if r and len(r) == 1 else None

    def incr(self, i, v):
        return self.ok([0xA5, i] + list(v.to_bytes(3, 'little')) + [0]) == b'ACK'

    def torn(self, c, d, hold=HOLD):
        """Send c with the field cut d ticks after the last FIFO write, back on hold later; reselect."""
        self.s.mon.txsched(bytes(c), 0, [(d, FIELD, OFF), (d + hold, FIELD, ON)], r574=0)
        time.sleep(0.01)
        self.s.nfc.drain(50); self.s.mon.frames()
        return self.resel()
