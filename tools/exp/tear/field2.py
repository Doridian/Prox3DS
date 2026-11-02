# Which store power-cycles the card: 0x40 alone, 0x41 alone (each followed only by 0x81)?
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover(); u = s.uid
def rd():
    a = s.answer(with_crc(b'\x30\x00')); return a.hex()[:8] if a else None
def resel():
    if s.answer(b'\x52', 0x07) is None: return False
    s.answer(b'\x93\x20'); s.answer(b'\x93\x70\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
    s.answer(b'\x95\x20'); return s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]])) is not None
print('read', rd())
for seq in sys.argv[2:]:
    for v in seq.split(','):
        v, _, ms = v.partition('/')
        s.mon.write32(0x5C55C, [int(v, 16)]); time.sleep(float(ms or 5) / 1000)
    r = rd()
    print(f'{seq:16s} read {r}', end='')
    if r is None: print('  reselect', resel(), 'read', rd())
    else: print()
