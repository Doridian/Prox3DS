# Card on -> activate; then wait until it's removed (READ fails), wait 3 s, toggle the field N times (empty field).
import sys, time, json, math
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover(); print('ACTIVE', s.uid.hex(), flush=True)
while True:
    a = s.answer(with_crc(b'\x30\x00'))
    if not (a and len(a) == 18): break
    time.sleep(0.2)
print('REMOVED', flush=True); time.sleep(3)
pts = []
for k in range(int(sys.argv[2])):
    s.mon.write32(0x5C360, [0]); time.sleep(0.02); s.mon.write32(0x5C360, [6]); time.sleep(0.03)
    a = s.mon.read32(0x5C420, 4); b = s.mon.read32(0x5C454, 2)
    i = ((a[0] << 8) | a[1]) - 1024; q = ((a[2] << 8) | a[3]) - 1024
    pts.append((i, q, b[0] - 128, b[1] - 128))
    print(f'tog {i:5d} {q:5d} r={math.hypot(i-1.6, q-7.7):6.1f}', flush=True)
json.dump(pts, open(sys.argv[3], 'w'))
