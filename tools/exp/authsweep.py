# Sweep the {nr}{ar} length code (bit mode, paced FIFO) until the card answers {at}.
#   authsweep.py HOST FIRST LAST [PACE]
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *
from crypto1 import Crypto1, prng_successor

host, first, last = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
pace = int(sys.argv[4], 0) if len(sys.argv) > 4 else 83
key, blk = bytes.fromhex('ffffffffffff'), 0
s = Session(host)
s.recover()
uid = int.from_bytes(s.uid, 'big')
for code in range(first, last + 1):
    def run():
        s.parity(True)
        if s.select() is None:
            raise chipmon.MonError('select failed')
        s.parity(False)
        a = bytes([0x60, blk]); fifo, c = pack(a + crc_a(a))
        s.mon.frames()
        r = s.mon.auth(key, uid, 0x12345678, fifo, c, pace << 16 | 0x100 | code)
        s.nfc.drain(100)
        fr = s.mon.frames()
        s.parity(True)
        return r, fr
    r, fr = s.retry(run, tries=6)
    line = f'code {code:02x}: '
    if not r:
        line += 'no nt'
    else:
        nt, odd, even = r
        line += f'nt {nt:08x} frames {len(fr)}'
        for regs, d in fr[1:]:
            c = Crypto1.from_state(odd, even)
            for off in range(8):
                atb, _ = unpack(d, off, 4)
                if len(atb) == 4 and int.from_bytes(Crypto1.from_state(odd, even).decrypt(atb), 'big') == prng_successor(nt, 96):
                    line += f'  <<<<<< AUTH OK (at offset {off})'
                    break
            else:
                line += f'  rx {d.hex()}'
    print(line, flush=True)
