# Parity-off TX in data mode (r574 = 0) vs bit mode (r574 = 1): READ 0 on the Gen1a-unlocked card.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
r0 = b'\x30\x00'
cases = [
    ('bit mode, CRC in frame, code 44', 1, r0 + crc_a(r0), 0x44),
    ('data mode, CRC in frame, code 44', 0, r0 + crc_a(r0), 0x44),
    ('data mode, CRC in frame, code 00', 0, r0 + crc_a(r0), 0x00),
    ('data mode, no CRC, code 22', 0, r0, 0x22),
    ('data mode, no CRC, code 00', 0, r0, 0x00),
]
for name, r574, frame, code in cases:
    fifo, _ = pack(frame)
    def run():
        s.parity(True)
        if not s.gen1a_unlock():
            raise chipmon.MonError('unlock failed')
        s.parity(False)
        s.mon.txraw(fifo, code, r574=r574)
        s.nfc.drain(150)
        fr = s.mon.frames()
        s.parity(True)
        return fr
    fr = s.retry(run)
    out = []
    for regs, d in fr:
        for off in range(8):
            b, p = unpack(d, off)
            if len(b) >= 18 and crc_a(b[:16]) == b[16:18]:
                out.append(f'off {off}: {b[:18].hex()}')
                break
        else:
            out.append(f'raw {d.hex()}')
    print(f'{name}: {"; ".join(out) or "nothing"}', flush=True)
