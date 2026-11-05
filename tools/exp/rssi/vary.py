# Sample the RF block N times with a card active; print registers that change.
import sys, collections
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10
seen = collections.defaultdict(list)
for n in range(N):
    for base in range(0x5C000, 0x5C800, 0x80):
        if base == 0x5C600: continue
        for i, v in enumerate(s.mon.read32(base, 32)):
            seen[base + 4 * i].append(v)
for a, vs in sorted(seen.items()):
    if len(set(vs)) > 1: print(f'{a:x}', ' '.join(f'{v:x}' for v in vs))
