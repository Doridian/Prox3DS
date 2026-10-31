# Long parity-off TX control: hand-packed SELECT (9 bytes + parity = 81 bits) from READY.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
PACE = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
sel = b'\x93\x70' + s.uid + bytes([s.uid[0] ^ s.uid[1] ^ s.uid[2] ^ s.uid[3]])
fifo_crc, code_crc = pack(sel + crc_a(sel))
fifo_nocrc, code_nocrc = pack(sel)
cases = [('data mode, CRC, A1', 0, fifo_crc, code_crc), ('data mode, no CRC, 77', 0, fifo_nocrc, code_nocrc),
         ('bit mode, CRC, A1', 1, fifo_crc, code_crc), ('bit mode, no CRC, 77', 1, fifo_nocrc, code_nocrc),
         ('parity ON reference: bit mode SELECT (HW CRC)', None, sel, 0x70)]
for name, r574, fifo, code in cases:
    def run():
        a = s.wupa()
        if r574 is None:
            fr = s.tx(fifo, code)
        else:
            s.parity(False)
            s.mon.txraw(fifo, code, r574=r574, pace=PACE)
            s.nfc.drain(150)
            fr = s.mon.frames()
            s.parity(True)
        return a, fr
    a, fr = s.retry(run)
    print(f'{name}: ATQA {a.hex() if a else None} -> ' + (' '.join(d.hex() for _, d in fr) or 'nothing'), flush=True)
