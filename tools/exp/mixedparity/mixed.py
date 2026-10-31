# Mixed-parity frames: most FIFO bytes raw (parity off, 8 stream bits each), a few sent with HW
# parity (8 data bits + HW odd parity = 9 stream bits), toggling 0x5C560 between bytes.
import sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from txtime import *

D0 = 69.5      # ticks from TX start to the parity decision of FIFO byte 0 (end of its 8 bits)
BIT = 9.44     # ticks per bit at 106 kbps
WRITE_T = 14   # ticks the FIFO writes take before the schedule clock starts


def build(data, par, hw):
    """data bytes + required parity bits; hw = set of data-byte indices sent with HW parity
    (their required parity must be the odd parity of the byte). Returns (fifo, sched)."""
    bits = []
    for b, p in zip(data, par):
        bits += [(b >> k) & 1 for k in range(8)] + [p]
    fifo, flags, pos = bytearray(), [], 0
    while pos < len(bits):
        j, r = divmod(pos, 9)
        if r == 0 and j in hw:
            fifo.append(data[j]); flags.append(1); pos += 9
        else:
            chunk = bits[pos:pos + 8]
            assert len(chunk) == 8, 'frame does not end on a FIFO byte boundary'
            fifo.append(sum(v << i for i, v in enumerate(chunk))); flags.append(0); pos += 8
    sched, cur, before = [], 0, 0
    for k, f in enumerate(flags):
        if f != cur:
            t = D0 + BIT * before - 38
            sched.append((max(0, round(t - WRITE_T)), 0x5C560, 0 if f else 8))
            cur = f
        before += 9 if f else 8
    return bytes(fifo), sched


def odd(b):
    return 1 ^ (bin(b).count('1') & 1)
