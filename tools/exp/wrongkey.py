# Framer registers after a normal exchange vs after a wrong-key auth (which hangs the next TX).
#   wrongkey.py HOST
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()
uid = int.from_bytes(s.uid, 'big')
RANGES = [(0x5C540, 32), (0x5C640, 36)]


def regs():
    out = {}
    for a, n in RANGES:
        for i, w in enumerate(s.mon.read32(a, n)):
            out[a + 4 * i] = w
    return out


s.parity(True)
s.select()
base = regs()
s.parity(False)
a = bytes([0x60, 4]); fifo, code = pack(a + crc_a(a))
s.mon.frames()
r = s.mon.auth(bytes(6), uid, 0x12345678, fifo, code)
print('auth ->', r and f'{r[0]:08x}')
s.nfc.drain(100)
print('frames', len(s.mon.frames()))
after = regs()
for k in sorted(base):
    if base[k] != after[k]:
        print(f'{k:05X}: {base[k]:08X} -> {after[k]:08X}')
print('irqs:', [(t, g, f'{st:x}') for t, g, st in s.mon.irqs()[-8:]])
