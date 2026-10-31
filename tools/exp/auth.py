# On-chip Crypto1 auth (memrw OP_AUTH) with several {nr}{ar} TX settings; then an encrypted READ.
#   auth.py HOST KEY BLOCK [r574<<8|code ...]
import struct, sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *
from crypto1 import Crypto1, prng_successor

host, key, blk = sys.argv[1], bytes.fromhex(sys.argv[2]), int(sys.argv[3])
variants = [int(v, 16) for v in sys.argv[4:]] or [0x188]
s = Session(host)
s.recover()
uid = int.from_bytes(s.uid, 'big')
for v in variants:
    def run():
        s.parity(True)
        if s.select() is None:
            raise chipmon.MonError('select failed')
        s.parity(False)
        a = bytes([0x60, blk]); fifo, code = pack(a + crc_a(a))
        s.mon.frames()
        r = s.mon.auth(key, uid, 0x12345678, fifo, code, v)
        if not r:
            return 'no nt'
        nt, odd, even = r
        s.nfc.drain(100)
        fr = s.mon.frames()
        res = f'nt {nt:08x}, {len(fr)} frames'
        if len(fr) < 2:
            s.parity(True)
            return res + ': no {at}'
        c = Crypto1.from_state(odd, even)
        atb, _ = unpack(fr[-1][1], 0, 4)
        at = int.from_bytes(c.decrypt(atb), 'big')
        ok = at == prng_successor(nt, 96)
        res += f', at {at:08x} ' + ('AUTH OK' if ok else f'!= {prng_successor(nt, 96):08x}')
        if ok:
            cmd = bytes([0x30, blk]); cmd += crc_a(cmd)
            enc, par = c.encrypt(cmd)
            raw, off = s.ptx(enc, par)
            if raw:
                d = c.decrypt(unpack(raw, off, 18)[0])
                res += f'\n    READ {blk}: {d[:16].hex(" ")} crc ' + ('ok' if crc_a(d[:16]) == d[16:18] else 'BAD')
        s.parity(True)
        return res
    print(f'nrar tx {v:03x}: {s.retry(run)}', flush=True)
