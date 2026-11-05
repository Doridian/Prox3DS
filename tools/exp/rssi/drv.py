import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
s = Session(sys.argv[1]); s.recover()
REG = int(sys.argv[2], 16); orig = s.mon.read32(REG, 1)[0]
print(f'{REG:x} orig {orig:x}')
print('val   04c  420 424 428 42c  454 458  510 514 518  read')
try:
  for v in [int(x, 16) for x in sys.argv[3:]]:
    s.mon.write32(REG, [v])
    for k in range(3):
        a = s.answer(with_crc(b'\x30\x00')); ok = 'ok' if a and len(a) == 18 else 'FAIL'
        r = s.mon.read32(0x5C04C, 1) + s.mon.read32(0x5C420, 4) + s.mon.read32(0x5C454, 2) + s.mon.read32(0x5C510, 3)
        print(f'{v:4x} ', ' '.join(f'{x:3x}' for x in r), ok, flush=True)
finally:
    s.mon.write32(REG, [orig])
