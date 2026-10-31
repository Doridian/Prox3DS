# Parity-ON long TX control: SELECT with our own CRC (9 bytes) in data mode, and without CRC.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
sel = b'\x93\x70' + s.uid + bytes([s.uid[0] ^ s.uid[1] ^ s.uid[2] ^ s.uid[3]])
cases = [('data mode, our CRC, code 90', 0, sel + crc_a(sel), 0x90),
         ('data mode, our CRC, code 88', 0, sel + crc_a(sel), 0x88),
         ('data mode, our CRC, code 00', 0, sel + crc_a(sel), 0x00),
         ('data mode, no CRC, code 00', 0, sel, 0x00),
         ('data mode, no CRC, code 70', 0, sel, 0x70)]
for name, r574, frame, code in cases:
    def run():
        a = s.wupa()
        s.mon.txraw(frame, code, r574=r574)
        s.nfc.drain(150)
        return a, s.mon.frames()
    a, fr = s.retry(run)
    print(f'{name}: ATQA {a.hex() if a else None} -> ' + (' '.join(d.hex() for _, d in fr) or 'nothing'), flush=True)
