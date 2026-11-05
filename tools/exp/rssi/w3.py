import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover()
N = int(sys.argv[2]); rd = len(sys.argv) > 3
t0 = time.time()
print('t     04c  420 424 428 42c  454 458  510 514 518  read')
for n in range(N):
    ok = ''
    if rd:
        a = s.answer(with_crc(b'\x30\x00')); ok = 'ok' if a and len(a) == 18 else 'FAIL'
    a = s.mon.read32(0x5C04C, 1); b = s.mon.read32(0x5C420, 4); c = s.mon.read32(0x5C454, 2); d = s.mon.read32(0x5C510, 3)
    print(f'{time.time()-t0:5.2f}', ' '.join(f'{x:3x}' for x in a + b + c + d), ok, flush=True)
