# Does the chip hang on its own after activation (no TX from us)? Poll a register, report when.
#   idle.py HOST [SECONDS] [select]
import sys, time
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
for rnd in range(3):
    s.recover()
    if len(sys.argv) > 3:
        s.select()
    t0 = time.time()
    log = []
    try:
        while time.time() - t0 < float(sys.argv[2] if len(sys.argv) > 2 else 20):
            log = s.mon.irqs()
            time.sleep(0.25)
        print(f'round {rnd}: alive {time.time() - t0:.1f}s', flush=True)
    except (chipmon.MonError, nfcnet.NfcError) as e:
        print(f'round {rnd}: HANG after {time.time() - t0:.1f}s ({e})', flush=True)
        for t, g, st in log[-12:]:
            print(f'    t={t:08x} group {g} status {st:08x}')
        s.reconnect()
