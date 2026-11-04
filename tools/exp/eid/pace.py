#!/usr/bin/env python3
"""German eID (nPA) / eMRTD PACE prototype over a Proxmark3 (pm3 client driven with pexpect).

PACE-ECDH-GM-AES-CBC-CMAC-128 on brainpoolP256r1 (what the nPA's EF.CardAccess offers), then AES secure
messaging: EF.CardSecurity, the ePass application's files. Card data goes to OUTDIR, not the repo.

usage: pace.py PORT CAN OUTDIR
"""
import os, re, sys, hashlib
import pexpect
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

# --- brainpoolP256r1, affine points (None = infinity) ---
P = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
A = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
B = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
G = (0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
     0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997)
N = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7


def ec_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if p1 == p2: l = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else: l = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (l * l - x1 - x2) % P
    return x3, (l * (x1 - x3) - y1) % P


def ec_mul(k, pt):
    r = None
    while k:
        if k & 1: r = ec_add(r, pt)
        pt = ec_add(pt, pt)
        k >>= 1
    return r


def enc_pt(pt): return b'\x04' + pt[0].to_bytes(32, 'big') + pt[1].to_bytes(32, 'big')


def dec_pt(b):
    assert b[0] == 4 and len(b) == 65, b.hex()
    pt = (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:], 'big'))
    assert (pt[1] ** 2 - pt[0] ** 3 - A * pt[0] - B) % P == 0, 'not on the curve'
    return pt


def rnd_scalar(): return int.from_bytes(os.urandom(40), 'big') % (N - 1) + 1


# --- crypto ---
def aes_ecb(k, d): e = Cipher(algorithms.AES(k), modes.ECB()).encryptor(); return e.update(d) + e.finalize()
def aes_cbc_enc(k, iv, d): e = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor(); return e.update(d) + e.finalize()
def aes_cbc_dec(k, iv, d): e = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor(); return e.update(d) + e.finalize()
def cmac(k, d): c = CMAC(algorithms.AES(k)); c.update(d); return c.finalize()
def kdf(secret, ctr): return hashlib.sha1(secret + ctr.to_bytes(4, 'big')).digest()[:16]
def pad(d): d = d + b'\x80'; return d + b'\x00' * (-len(d) % 16)
def unpad(d): return d[:d.rindex(b'\x80')]


def tlv(tag, v):
    t = tag.to_bytes((tag.bit_length() + 7) // 8, 'big')
    l = bytes([len(v)]) if len(v) < 0x80 else (bytes([0x81, len(v)]) if len(v) < 256 else bytes([0x82]) + len(v).to_bytes(2, 'big'))
    return t + l + v


def tlv_parse(d):
    """Flat list of (tag, value)."""
    out, i = [], 0
    while i < len(d):
        tag = d[i]; i += 1
        if tag & 0x1F == 0x1F:
            while True:
                tag = tag << 8 | d[i]; i += 1
                if not d[i - 1] & 0x80: break
        l = d[i]; i += 1
        if l & 0x80:
            n = l & 0x7F; l = int.from_bytes(d[i:i + n], 'big'); i += n
        out.append((tag, d[i:i + l])); i += l
    return out


# --- pm3 transport ---
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


class Pm3:
    def __init__(self, port):
        self.p = pexpect.spawn('pm3', ['-p', port], encoding='utf-8', timeout=30)
        self.p.expect(r'pm3 --> ')
        self.first = True

    def apdu(self, a):
        flags = '-s -k' if self.first else '-k'
        self.first = False
        self.p.sendline(f'hf 14a apdu {flags} -d {a.hex()}')
        self.p.expect(r'pm3 --> ')
        out = ANSI.sub('', self.p.before)
        m = re.findall(r'<<< ([0-9A-Fa-f]+) \|', out)
        if not m:
            raise RuntimeError('no answer: ' + out.strip()[-300:])
        r = bytes.fromhex(m[0])
        return r[:-2], int.from_bytes(r[-2:], 'big')

    def close(self):
        self.p.sendline('hf 14a reader -x')  # field off
        self.p.expect(r'pm3 --> ')
        self.p.sendline('quit')


PACE_OID = bytes.fromhex('04007F00070202040202')  # id-PACE-ECDH-GM-AES-CBC-CMAC-128


class Sm:
    def __init__(self, card, kenc, kmac):
        self.c, self.ke, self.km, self.ssc = card, kenc, kmac, 0

    def _ssc(self): return self.ssc.to_bytes(16, 'big')

    def apdu(self, cla, ins, p1, p2, data=b'', le=None):
        self.ssc += 1
        hdr = bytes([cla | 0x0C, ins, p1, p2])
        do = b''
        if data:
            iv = aes_ecb(self.ke, self._ssc())
            do += tlv(0x87, b'\x01' + aes_cbc_enc(self.ke, iv, pad(data)))
        if le is not None:
            do += tlv(0x97, bytes([le]))
        mac = cmac(self.km, self._ssc() + pad(hdr) + (pad(do) if do else b''))[:8]
        body = do + tlv(0x8E, mac)
        r, sw = self.c.apdu(hdr + bytes([len(body)]) + body + b'\x00')
        self.ssc += 1
        if sw not in (0x9000, 0x6282) or not r:
            return b'', sw  # plain error (SM dropped)
        objs = tlv_parse(r)
        d = dict(objs)
        macd = b''.join(tlv(t, v) for t, v in objs if t in (0x87, 0x99))
        if cmac(self.km, self._ssc() + pad(macd))[:8] != d.get(0x8E):
            raise RuntimeError('response MAC wrong')
        out = b''
        if 0x87 in d:
            iv = aes_ecb(self.ke, self._ssc())
            out = unpad(aes_cbc_dec(self.ke, iv, d[0x87][1:]))
        return out, int.from_bytes(d[0x99], 'big')

    def read_sfi(self, sfi):
        data, sw = self.apdu(0x00, 0xB0, 0x80 | sfi, 0, le=0)
        if sw != 0x9000: return None, sw
        # length from the first TLV
        t = data
        l = t[1]
        if l & 0x80:
            n = l & 0x7F; total = 2 + n + int.from_bytes(t[2:2 + n], 'big')
        else:
            total = 2 + l
        while len(data) < total:
            off = len(data)
            chunk, sw = self.apdu(0x00, 0xB0, off >> 8, off & 0xFF, le=min(0xDF, total - off))
            if sw != 0x9000 or not chunk: return data, sw
            data += chunk
        return data, 0x9000


def pace(card, can):
    # MSE:Set AT, CAN = password 02
    _, sw = card.apdu(bytes.fromhex('0022C1A4') + bytes([15]) + tlv(0x80, PACE_OID) + tlv(0x83, b'\x02'))
    print(f'MSE:Set AT (CAN): {sw:04X}')
    if sw != 0x9000: raise RuntimeError('MSE failed')

    def ga(inner, last=False):
        data = tlv(0x7C, inner)
        r, sw = card.apdu(bytes([0x00 if last else 0x10, 0x86, 0, 0, len(data)]) + data + b'\x00')
        if sw != 0x9000: raise RuntimeError(f'General Authenticate: {sw:04X}')
        return dict(tlv_parse(dict(tlv_parse(r))[0x7C]))

    z = ga(b'')[0x80]
    s = int.from_bytes(aes_cbc_dec(kdf(can.encode(), 3), b'\x00' * 16, z), 'big')
    print('nonce decrypted')

    sk1 = rnd_scalar()
    pkc1 = dec_pt(ga(tlv(0x81, enc_pt(ec_mul(sk1, G))))[0x82])
    g2 = ec_add(ec_mul(s, G), ec_mul(sk1, pkc1))
    print('mapped')

    sk2 = rnd_scalar()
    pk2 = ec_mul(sk2, g2)
    pkc2b = ga(tlv(0x83, enc_pt(pk2)))[0x84]
    k = ec_mul(sk2, dec_pt(pkc2b))[0].to_bytes(32, 'big')
    kenc, kmac = kdf(k, 1), kdf(k, 2)

    tok = lambda pk: cmac(kmac, tlv(0x7F49, tlv(0x06, PACE_OID) + tlv(0x86, pk)))[:8]
    r = ga(tlv(0x85, tok(pkc2b)), last=True)
    if r[0x86] != tok(enc_pt(pk2)): raise RuntimeError('card token wrong')
    print('PACE done, card token ok' + (f'; CAR {r[0x87]!r}' if 0x87 in r else ''))
    return Sm(card, kenc, kmac)


def main():
    port, can, outdir = sys.argv[1:4]
    os.makedirs(outdir, exist_ok=True)
    card = Pm3(port)
    try:
        # PIN status: MSE:Set AT with the PIN (03) answers 9000 / 63Cx, no attempt is used
        _, sw = card.apdu(bytes.fromhex('0022C1A4') + bytes([15]) + tlv(0x80, PACE_OID) + tlv(0x83, b'\x03'))
        print(f'PIN status (MSE with PIN): {sw:04X}')
        sm = pace(card, can)

        def save(name, data, sw):
            print(f'{name}: {sw:04X}' + (f', {len(data)} bytes' if data else ''))
            if data: open(os.path.join(outdir, name + '.bin'), 'wb').write(data)

        save('CardSecurity', *sm.read_sfi(0x1D))
        _, sw = sm.apdu(0x00, 0xA4, 0x04, 0x0C, bytes.fromhex('A0000002471001'))
        print(f'SELECT ePass: {sw:04X}')
        if sw == 0x9000:
            for name, sfi in (('COM', 0x1E), ('SOD', 0x1D), ('DG1', 1), ('DG2', 2), ('DG14', 14)):
                save(name, *sm.read_sfi(sfi))
    finally:
        card.close()


if __name__ == '__main__':
    main()
