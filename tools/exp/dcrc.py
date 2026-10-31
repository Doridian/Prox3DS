# Does data mode (r574 = 0) with length code 0 append a CRC? READ 0 without CRC on the unlocked card.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
r0 = b'\x30\x00'
for name, r570, r574, frame, code in [('data mode, no CRC, code 0', 0, 0, r0, 0),
                                       ('data mode, CRC, code 0', 0, 0, r0 + crc_a(r0), 0),
                                       ('r570=1 r574=0, no CRC, code 0', 1, 0, r0, 0),
                                       ('r570=1 r574=0, CRC, code 0', 1, 0, r0 + crc_a(r0), 0)]:
    def run():
        s.parity(True)
        if not s.gen1a_unlock():
            raise chipmon.MonError('unlock failed')
        s.mon.txraw(frame, code, r570=r570, r574=r574)
        s.nfc.drain(150)
        return s.mon.frames()
    fr = s.retry(run)
    print(f'{name}: ' + (' '.join(f'{d.hex()}[{r[1]:x}]' for r, d in fr) or 'nothing'), flush=True)
