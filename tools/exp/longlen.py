# On-air length of long parity-off frames vs FIFO bytes written: TX start (logged by txraw) -> first
# TX/RX interrupt (RX timeout, junk frames the card ignores). ~83 ticks per byte at 106 kbps.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
modes = [int(m) for m in sys.argv[2].split(',')] if len(sys.argv) > 2 else [1, 0]
paces = [int(p, 0) for p in sys.argv[3].split(',')] if len(sys.argv) > 3 else [0, 6 << 16 | 83]
codes = [int(c, 0) for c in sys.argv[4].split(',')] if len(sys.argv) > 4 else [0x70]
for r574 in modes:
    for pace in paces:
        for code in codes:
            for nb in ([int(n) for n in sys.argv[5].split(",")] if len(sys.argv) > 5 else (4, 6, 7, 8, 9, 10, 12, 16, 21)):
                stalls = []
                def run():
                    stalls.append(1)
                    s.parity(False)
                    s.mon.txraw(bytes([0x55] * nb), code, r574=r574, pace=pace)
                    s.nfc.drain(150)
                    ev = s.mon.irqs()
                    s.parity(True)
                    st = [e for e in ev if e[1] == 3][-1]
                    after = [e for e in ev if e[1] == 1 and e[0] < st[0]]
                    return (st[0] - after[0][0], after[0][2]) if after else (None, None)
                try:
                    d, status = s.retry(run, tries=2)
                except chipmon.MonError:
                    d, status = 'HANG', None
                print(f'r574={r574} pace {pace:06x} code {code:02x} n {nb:2d}: {d} ticks '
                      f'({d / 83:.1f} B)' if isinstance(d, int) else
                      f'r574={r574} pace {pace:06x} code {code:02x} n {nb:2d}: {d}',
                      f'irq {status}', 'stalled' if len(stalls) > 1 else '', flush=True)
