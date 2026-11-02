# Off store at D with no on store: what does 0x5C054 read afterwards, and is the card reset?
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover(); u = s.uid
def rd():
    a = s.answer(with_crc(b'\x30\x00')); return bool(a and len(a) == 18)
def resel():
    for _ in range(3):
        if s.answer(b'\x52', 0x07) is None: continue
        s.answer(b'\x93\x20'); s.answer(b'\x93\x70\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
        s.answer(b'\x95\x20')
        if s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]])) is not None: return True
    return False
REG, ON = int(sys.argv[2], 16), int(sys.argv[3], 16)
for d in [int(x) for x in sys.argv[4:]]:
    rd() or resel()
    s.mon.txsched(with_crc(b'\x30\x00'), 0x40, [(d, REG, 0)])
    v = s.mon.read32(REG, 1)[0]
    time.sleep(0.01); s.nfc.drain(50); fr = s.mon.frames()
    v2 = s.mon.read32(REG, 1)[0]
    s.mon.write32(REG, [ON]); time.sleep(0.005)
    print(f'off at {d}: 054 after {v:x} / {v2:x}, answered {any(len(f[1]) == 18 for f in fr)}, card {"kept" if rd() else "RESET"}', flush=True)
