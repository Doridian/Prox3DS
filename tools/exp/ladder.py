# Parity-off TX length ladder: anticollision with NVB 0x20..0x67 (2 bytes .. 6 bytes + 7 bits);
# the card answers each with the rest of its UID + BCC.
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()
uidb = s.uid + bytes([s.uid[0] ^ s.uid[1] ^ s.uid[2] ^ s.uid[3]])
PACE = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
for nbytes, nbits in [(6, 0), (6, 1), (6, 3), (6, 5), (6, 7)]:
    nvb = nbytes << 4 | nbits
    frame = bytes([0x93, nvb]) + uidb[:nbytes - 2]
    bits = []
    fifo, _ = pack(frame)
    bits = [(fifo[i // 8] >> (i % 8)) & 1 for i in range(len(frame) * 9)]
    bits += [(uidb[nbytes - 2] >> j) & 1 for j in range(nbits)] if nbits else []
    fifo = bytes(sum(bits[8 * k + j] << j for j in range(8) if 8 * k + j < len(bits)) for k in range((len(bits) + 7) // 8))
    code = (len(bits) // 8) << 4 | len(bits) % 8

    def run():
        a = s.wupa()
        s.parity(False)
        s.mon.txraw(fifo, code, pace=PACE)
        s.nfc.drain(150)
        fr = s.mon.frames()
        s.parity(True)
        return a, fr
    a, fr = s.retry(run)
    print(f'NVB {nvb:02x}: {len(bits)} bits, {len(fifo)} FIFO bytes, code {code:02x}: ATQA {a.hex() if a else None} -> '
          + (' '.join(d.hex() for _, d in fr) or 'nothing'), flush=True)
