# No card: stop discovery, write the active-card register set, field-on command, sample I/Q.
import sys, time, json, math
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1])
s.mon.load(); s.nfc.cmd(rawa.RF_DISCOVER_MAP); s.nfc.cmd(rawa.RF_DISCOVER_A, 300)
time.sleep(0.3)
s.nfc.cmd(bytes.fromhex('10210601 00'.replace(' ', '')) if False else bytes.fromhex('1021060100'), 300)  # RF_DEACTIVATE idle
time.sleep(0.1)
act = {int(a, 16): v for a, v in json.load(open(sys.argv[2])).items()}
SKIP = {0x5C420, 0x5C424, 0x5C428, 0x5C42C, 0x5C454, 0x5C458, 0x5C510, 0x5C514, 0x5C518, 0x5C04C, 0x5C55C, 0x5C588, 0x5C590, 0x5C5D4, 0x5C5D8, 0x5C5E4, 0x5C568}
for a in sorted(act):
    if a not in SKIP: s.mon.write32(a, [act[a]])
s.mon.write32(0x5C55C, [0x41]); time.sleep(0.002); s.mon.write32(0x5C55C, [0x81]); time.sleep(0.05)
def iq():
    a = s.mon.read32(0x5C420, 4); b = s.mon.read32(0x5C454, 2)
    return ((a[0] << 8) | a[1]) - 1024, ((a[2] << 8) | a[3]) - 1024, b[0] - 128, b[1] - 128
for k in range(5):
    i, q, i8, q8 = iq(); print(f'{i:5d} {q:5d} r={math.hypot(i-1.6, q-7.7):6.1f} | {i8} {q8} r8={math.hypot(i8,q8):.1f}', flush=True)
pts = []
for k in range(int(sys.argv[3])):
    s.mon.write32(0x5C360, [0]); time.sleep(0.02); s.mon.write32(0x5C360, [6]); time.sleep(0.03)
    i, q, i8, q8 = iq(); pts.append((i, q, i8, q8))
    print(f'tog {i:5d} {q:5d} r={math.hypot(i-1.6, q-7.7):6.1f} | {i8} {q8}', flush=True)
json.dump(pts, open(sys.argv[4], 'w'))
