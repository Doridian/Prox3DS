# Tear-off (#18): UL / NTAG page WRITE with the field dropped D timer ticks (1 us) after the last
# FIFO write (reader.c TXSCHED storing 0x5C360 = 0, field off), then field on (= 6), reselect,
# read the page back. USER PAGE ONLY (default 10 of the UL EV1 test card's free 4..15).
#   tear.py HOST D0 D1 STEP [PAGE]
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc, crc_a

FIELD, OFF, ON = 0x5C360, 0, 6  # acts at once, even mid-transaction (0x5C054 is latched per TX)
HOLD = 2000  # field off this long (ticks), then back on
host, d0, d1, step = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
page = int(sys.argv[5]) if len(sys.argv) > 5 else 10
assert 4 <= page <= 15
A, B = bytes.fromhex('AAAAAAAA'), bytes.fromhex('55555555')

s = Session(host)
s.recover()
u = s.uid


def field_on():
    s.mon.write32(FIELD, [ON]); time.sleep(0.005)


def reselect():
    if s.answer(b'\x52', 0x07) is None:
        return False
    s.answer(b'\x93\x20'); s.answer(b'\x93\x70\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
    s.answer(b'\x95\x20')
    return s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]])) is not None


def read():
    a = s.answer(with_crc(bytes([0x30, page])))
    return a[:4] if a and len(a) == 18 and crc_a(a[:16]) == a[16:] else None


def write(d):
    return s.data_tx(bytes([0xA2, page]) + d)


def cycle():
    s.mon.write32(FIELD, [OFF]); time.sleep(0.01); field_on()
    for _ in range(3):
        if reselect():
            return True
    return False


assert cycle(), 'no reselect'
print('page', page, 'now', read().hex())
for d in range(d0, d1 + 1, step):
    def run():
        assert cycle()
        if write(A) != b'\x0a' or read() != A:
            raise chipmon.MonError('setup write failed')
        busy = s.mon.txsched(bytes([0xA2, page]) + B, 0, [(d, FIELD, OFF), (d + HOLD, FIELD, ON)], r574=0)
        time.sleep(0.01)
        s.nfc.drain(50); s.mon.frames()
        field_on()
        ok = any(reselect() for _ in range(3))
        return busy, ok, read() if ok else None
    busy, ok, got = s.retry(run)
    tag = 'old' if got == A else 'NEW' if got == B else ('??' if got else 'no read')
    print(f'D={d:5d} busy={busy:4d}  {got.hex() if got else "-":8s} {tag}', flush=True)
