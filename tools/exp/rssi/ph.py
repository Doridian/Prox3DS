import sys, time, math
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
for k in range(int(sys.argv[2])):
    s.mon.write32(0x5C360, [0]); time.sleep(0.02); s.mon.write32(0x5C360, [6]); time.sleep(0.04)
    a = s.mon.read32(0x5C420, 4); i = ((a[0] << 8) | a[1]) - 1025.3; q = ((a[2] << 8) | a[3]) - 1031.6
    r = s.mon.read32(0x5C040, 4) + s.mon.read32(0x5C3C0, 5) + s.mon.read32(0x5C400, 4)
    print(f'{math.degrees(math.atan2(q, i)):7.1f} {math.hypot(i, q):6.1f} |', ' '.join(f'{x:2x}' for x in r), flush=True)
