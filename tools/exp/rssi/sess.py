# Several sessions (power cycle + reload each): field-on I/Q vs field-off (0x5C360 = 0) I/Q, 10-bit readout.
import sys, time, math
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
def iq(s, n=8):
    si = sq = 0
    for k in range(n):
        a = s.mon.read32(0x5C420, 4); si += ((a[0] << 8) | a[1]) - 1024; sq += ((a[2] << 8) | a[3]) - 1024
    return si / n, sq / n
for k in range(int(sys.argv[2])):
    s = Session(sys.argv[1]); s.recover()
    on = iq(s)
    s.mon.write32(0x5C360, [0]); time.sleep(0.01); off = iq(s)
    s.mon.write32(0x5C360, [6]); time.sleep(0.01); on2 = iq(s)
    d = (on[0] - off[0], on[1] - off[1])
    print(f'on {on[0]:7.1f} {on[1]:7.1f} |{math.hypot(*on):6.1f}|  off {off[0]:6.1f} {off[1]:6.1f}  on-off |{math.hypot(*d):6.1f}| ang {math.degrees(math.atan2(on[1], on[0])):6.1f}  on2 {on2[0]:7.1f} {on2[1]:7.1f}', flush=True)
    s.close() if hasattr(s, 'close') else None
