import sys, time, json
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1])
s.mon.load(); s.nfc.cmd(rawa.RF_DISCOVER_MAP); s.nfc.cmd(rawa.RF_DISCOVER_A, 300)
time.sleep(0.5)
out = {}
for base in range(0x5C000, 0x5C800, 0x80):
    if base == 0x5C600: continue
    for i, v in enumerate(s.mon.read32(base, 32)): out[base + 4 * i] = v
act = {int(a, 16): v for a, v in json.load(open(sys.argv[2])).items()}
for a in sorted(set(out) | set(act)):
    o, c = out.get(a, 0), act.get(a, 0)
    if o != c: print(f'{a:x} disc {o:x} active {c:x}')
