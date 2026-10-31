# On-air length per length code: TX start (logged by txraw) -> RX timeout (no answer), parity off,
# junk frames the card ignores, FIFO fed paced so nothing overflows.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
codes = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x77, 0x80, 0x88, 0x90, 0xA0, 0xC0, 0xF0]
for r574 in (1, 0):
    for code in codes:
        nb = min(15, (code >> 4) + (1 if code & 0xF else 0)) + 1
        def run():
            s.parity(False)
            s.mon.txraw(bytes([0x55] * nb), code, r574=r574, pace=6 << 16 | 83)
            s.nfc.drain(150)
            ev = s.mon.irqs()
            s.parity(True)
            st = [e for e in ev if e[1] == 3][-1]
            after = [e for e in ev if e[1] == 1 and e[0] < st[0]]
            return st[0] - after[0][0] if after else None, after[0][2] if after else None
        d, status = s.retry(run)
        bits = (code >> 4) * 8 + (code & 0xF)
        print(f'r574={r574} code {code:02x} ({bits:3d} bits nominal): start -> irq {status} after {d} ticks', flush=True)
