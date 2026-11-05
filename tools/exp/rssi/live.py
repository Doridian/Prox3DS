# Field on (card activated first), then sample the carrier I/Q for SECS seconds, card present or not.
import sys, time, math
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
secs = float(sys.argv[2])
t0 = time.time()
print('t      I10  Q10  mag10 | I8 Q8 mag8 | Is Qs mags', flush=True)
while time.time() - t0 < secs:
    a = s.mon.read32(0x5C420, 4); b = s.mon.read32(0x5C454, 2); c = s.mon.read32(0x5C510, 2)
    i10 = ((a[0] << 8) | a[1]) - 1024; q10 = ((a[2] << 8) | a[3]) - 1024
    i8 = b[0] - 128; q8 = b[1] - 128
    sx = lambda v: v - 256 if v & 0x80 else v
    is_, qs = sx(c[0] & 0xFF), sx(c[1] & 0xFF)
    print(f'{time.time()-t0:6.2f} {i10:5d} {q10:5d} {math.hypot(i10,q10):6.1f} | {i8:4d} {q8:4d} {math.hypot(i8,q8):5.1f} | {is_:4d} {qs:4d} {math.hypot(is_,qs):5.1f}', flush=True)
    time.sleep(0.1)
