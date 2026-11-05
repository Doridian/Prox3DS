# One session, field toggled N times: (I, Q) after each field-on (10-bit and 8-bit readouts). Card stays put.
import sys, time, math, json
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
N = int(sys.argv[2]); pts = []
for k in range(N):
    s.mon.write32(0x5C360, [0]); time.sleep(0.02); s.mon.write32(0x5C360, [6]); time.sleep(0.03)
    a = s.mon.read32(0x5C420, 4); b = s.mon.read32(0x5C454, 2); a2 = s.mon.read32(0x5C420, 4)
    i = ((a[0] << 8) | a[1]) - 1024; q = ((a[2] << 8) | a[3]) - 1024
    i2 = ((a2[0] << 8) | a2[1]) - 1024; q2 = ((a2[2] << 8) | a2[3]) - 1024
    pts.append((i, q, b[0] - 128, b[1] - 128, i2, q2))
    print(f'{i:5d} {q:5d} {math.hypot(i,q):6.1f} {math.degrees(math.atan2(q,i)):7.1f} | {b[0]-128:4d} {b[1]-128:4d} | {i2:5d} {q2:5d}', flush=True)
json.dump(pts, open(sys.argv[3], 'w'))
