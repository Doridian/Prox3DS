# Watch candidate registers with a card active. args: HOST N [field-off-at]
import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
N = int(sys.argv[2]); off = int(sys.argv[3]) if len(sys.argv) > 3 else -1
R = [0x5C04C, 0x5C424, 0x5C42C, 0x5C454, 0x5C458, 0x5C510, 0x5C518]
print(' '.join(f'{a:x}' for a in R))
t0 = time.time()
for n in range(N):
    if n == off: s.mon.write32(0x5C360, [0]); print('-- field off')
    v = [s.mon.read32(a, 1)[0] for a in R]
    print(f'{time.time()-t0:5.2f}', ' '.join(f'{x:5x}' for x in v), flush=True)
s.mon.write32(0x5C360, [6])
