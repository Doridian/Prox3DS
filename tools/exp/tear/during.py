# Field off at D (ticks after the last FIFO write), on at E, around a READ page 0 frame:
# did the READ get answered, and did the card keep its state? Also the plain TX busy time.
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
rd() or resel()
print('busy READ bit mode', s.mon.txsched(with_crc(b'\x30\x00'), 0x40, []))
time.sleep(0.01); s.nfc.drain(50); s.mon.frames()
print('busy WRITE data mode (page 10 = its current value)')
CMD = int(sys.argv[2], 16)
for arg in sys.argv[3:]:
    d, e = map(int, arg.split(','))
    res = []
    for _ in range(4):
        rd() or resel()
        s.mon.txsched(with_crc(b'\x30\x00'), 0x40, [(d, 0x5C56C, CMD), (d, 0x5C054, 0), (e, 0x5C054, 4)] if CMD else [(d, 0x5C054, 0), (e, 0x5C054, 4)])
        time.sleep(0.01); s.nfc.drain(50); fr = s.mon.frames()
        ans = any(len(f[1]) == 18 for f in fr)
        r = rd()
        res.append(f'{"ans" if ans else "---"}/{"kept" if r else "RESET"}')
    print(f'off {d:5d} on {e:5d}: {" ".join(res)}', flush=True)
