# Can an 18-byte (162-bit) frame go out in parity-off bit mode? Long bit-mode frames are whole
# FIFO bytes only (code 0x70: n*8 bits; nonzero extra bits with n >= 9: (n-1)*8), so try the
# 162-bit frame + 6 trailing bits (168) and see if the card still takes it. Test bed: Gen1a
# backdoor WRITE (plaintext) of a block's CURRENT contents back to itself (no change on success).
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

BLK = 2
s = Session(sys.argv[1] if len(sys.argv) > 1 else '192.0.2.132')
s.recover()


def bits_of(data, par=None):
    bits = []
    for i, b in enumerate(data):
        bits += [(b >> k) & 1 for k in range(8)]
        bits.append(par[i] if par is not None else 1 ^ (bin(b).count('1') & 1))
    return bits


def to_fifo(bits):
    out = bytearray((len(bits) + 7) // 8)
    for i, v in enumerate(bits):
        out[i // 8] |= v << (i % 8)
    return bytes(out)


def attempt(data_bits, code, label):
    def run():
        s.parity(True)
        cur = rawa.RawA.read_block(s, BLK) if s.gen1a_unlock() else None
        if cur is None:
            raise chipmon.MonError('read failed')
        if not s.gen1a_unlock() or s.data_tx(bytes([0xA0, BLK])) != b'\x0a':
            raise chipmon.MonError('A0 not ACKed')
        frame = cur + crc_a(cur)
        bits = bits_of(frame) + data_bits
        s.parity(False)
        s.mon.txraw(to_fifo(bits), code)
        s.nfc.drain(150)
        fr = s.mon.frames()
        s.parity(True)
        ok = s.gen1a_unlock() and rawa.RawA.read_block(s, BLK) == cur
        return fr, len(bits), ok
    fr, nbits, ok = s.retry(run)
    ans = ' '.join(f'{d.hex()}(rx {r[4]}B/{r[2]}b st {r[1]:x})' for r, d in fr) or 'nothing'
    print(f'{label:28s} {nbits} bits code {code:02x}: {ans}  readback {"same" if ok else "DIFFERENT"}', flush=True)


# control: plaintext data-mode write (HW parity + CRC)
s.parity(True)
s.gen1a_unlock()
cur = rawa.RawA.read_block(s, BLK)
print('block', BLK, cur.hex() if cur else cur)
s.gen1a_unlock()
print('control data-mode A0:', s.data_tx(bytes([0xA0, BLK])), 'data:', s.data_tx(cur))
for label, extra, code in [
    ('160 bits (2 short)', None, 0x02),
    ('+6 zeros', [0] * 6, 0x70),
    ('+6 ones', [1] * 6, 0x70),
    ('+ 101010', [1, 0, 1, 0, 1, 0], 0x70),
    ('+ 000001', [0, 0, 0, 0, 0, 1], 0x70),
]:
    if extra is None:
        attempt([], code, label)  # 162 bits in 21 bytes, the framer drops the last byte
    else:
        attempt(extra, code, label)
