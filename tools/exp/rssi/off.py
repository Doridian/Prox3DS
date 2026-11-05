import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
s.mon.write32(0x5C360, [0]); t0 = time.time()
for k in range(15):
    a = s.mon.read32(0x5C420, 4)
    print(f'{time.time()-t0:5.2f}', ((a[0] << 8) | a[1]) - 1024, ((a[2] << 8) | a[3]) - 1024, flush=True)
s.mon.write32(0x5C360, [6])
