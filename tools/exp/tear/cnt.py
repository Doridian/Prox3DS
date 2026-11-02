# INCR_CNT(+0) torn at D: counter + tearing flag afterwards.   cnt.py HOST CNT D0 D1 STEP
import sys
from tlib import *
e = Ev1(sys.argv[1]); c = int(sys.argv[2])
print('cnt', e.cnt(c), 'tear', hex(e.tear_flag(c) or 0))
for d in range(int(sys.argv[3]), int(sys.argv[4]) + 1, int(sys.argv[5])):
    e.torn([0xA5, c, 0, 0, 0, 0], d)
    v, t = e.cnt(c), e.tear_flag(c)
    print(f'D={d:5d} cnt {v} tear {t if t is None else hex(t)}', flush=True)
    if t != 0xBD:
        e.incr(c, 0); print('   after +0:', e.cnt(c), hex(e.tear_flag(c) or 0))
