# Lost monitor exchanges: is the request lost (not executed) or only the reply?
# Each request writes a counter to a scratch byte; after a timeout we read it back.
#   lost.py HOST [N]
import sys, time
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()
scratch = s.mon.ring + 4 + 15 * 56 + 25  # data of ring slot 15, unused while idle
t0, n, stats = time.time(), 0, {'request lost': 0, 'reply lost': 0}
while n < int(sys.argv[2]) if len(sys.argv) > 2 else 4:
    v = (int((time.time() - t0) * 10) & 0x7F) | 0x80
    try:
        s.mon.write(scratch, bytes([v]))
        time.sleep(0.1)
    except (chipmon.MonError, nfcnet.NfcError) as e:
        dt = time.time() - t0
        s.reconnect()
        got = s.mon.read(scratch, 1)[0]
        kind = 'reply lost' if got == v else 'request lost'
        stats[kind] += 1
        n += 1
        print(f'{dt:6.1f}s: {kind} (wrote {v:02x}, reads {got:02x})', flush=True)
print(stats)
