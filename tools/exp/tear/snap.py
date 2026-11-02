# Snapshot 0x5C000-0x5C7FF with a card active (ROM-activated, monitor capture on).
import sys, json
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
out = {}
for base in range(0x5C000, 0x5C800, 0x80):
    if base in (0x5C600,):  # FIFO ports: reads pop data
        continue
    for i, v in enumerate(s.mon.read32(base, 32)):
        if v: out[base + 4 * i] = v
for a, v in sorted(out.items()): print(f'{a:x} {v:x}')
json.dump({hex(a): v for a, v in out.items()}, open(sys.argv[2], 'w'))
