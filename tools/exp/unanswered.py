# How many unanswered frames in a row before the chip hangs? select, then HLTA x N.
#   unanswered.py HOST [ROUNDS]
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()
hlta = b'\x50\x00' + crc_a(b'\x50\x00')
for rnd in range(int(sys.argv[2]) if len(sys.argv) > 2 else 4):
    s.parity(True)
    try:
        sak = s.select()
        print(f'round {rnd}: select {sak}', end='', flush=True)
        for i in range(6):
            s.tx(hlta)
            print(f' hlta{i + 1}', end='', flush=True)
        s.mon.read32(0x5C540, 1)
        print(' ok', flush=True)
    except (chipmon.MonError, nfcnet.NfcError) as e:
        print(f' HANG ({e})', flush=True)
        s.reconnect(); s.recover()
