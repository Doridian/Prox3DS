# How long must the field be off (0x5C054 = 0) before the card resets? READ page 0 via TXSCHED
# with off at 3000 ticks and on at 3000 + H, then READ again (ok = card kept its state).
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
REG, OFFV, ONV = int(sys.argv[2], 16), int(sys.argv[3], 16), int(sys.argv[4], 16)
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
for h in [int(x) for x in sys.argv[5:]]:
    res = []
    for _ in range(4):
        if not rd(): resel()
        s.mon.txsched(with_crc(b'\x30\x00'), 0x40, [(3000, REG, OFFV), (3000 + h, REG, ONV)])
        time.sleep(0.01); s.nfc.drain(50); s.mon.frames()
        r = rd(); res.append('ok' if r else 'RESET')
        if not r: resel()
    print(f'H={h:6d}: {" ".join(res)}', flush=True)
