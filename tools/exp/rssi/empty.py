# No card: load the monitor, start NFC-A discovery, sample 0x5C360 + I/Q while the ROM polls.
import sys, time, math, json
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1])
s.mon.load(); s.nfc.cmd(rawa.RF_DISCOVER_MAP); s.nfc.cmd(rawa.RF_DISCOVER_A, 300)
pts = []
t0 = time.time()
while time.time() - t0 < float(sys.argv[2]):
    f = s.mon.read32(0x5C360, 1)[0]; a = s.mon.read32(0x5C420, 4); b = s.mon.read32(0x5C454, 2)
    i = ((a[0] << 8) | a[1]) - 1024; q = ((a[2] << 8) | a[3]) - 1024
    pts.append((f, i, q, b[0] - 128, b[1] - 128))
    print(f'{time.time()-t0:5.2f} f={f:x} {i:5d} {q:5d} {math.hypot(i-1.6, q-7.7):6.1f} | {b[0]-128:4d} {b[1]-128:4d}', flush=True)
json.dump(pts, open(sys.argv[3], 'w'))
