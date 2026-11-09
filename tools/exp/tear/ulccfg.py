# ulccfg.py HOST CMD ... : raw UL-C config helper over the monitor (tlib), for testing AUTH0/AUTH1.
#   HOST dump [KEY]            READ pages 0..2F (3DES auth first if KEY given; 32 hex, pm3 order)
#   HOST cfg AUTH0 AUTH1 [KEY] write page 2A = AUTH0 000000, 2B = AUTH1 000000 (auth first if KEY)
#   HOST setkey NEW CUR        write the 3DES key pages 2C-2F (auth with CUR), then auth with NEW
# KEY default = factory 49454D4B41455242214E4143554F5946 (BREAKMEIFYOUCAN!). Never touches lock bits.
import os, sys
sys.path.insert(0, '.')
from tlib import Ev1
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

FACTORY = '49454D4B41455242214E4143554F5946'


def des(key, iv, data, enc):
    c = Cipher(TripleDES(key), modes.CBC(iv))
    o = c.encryptor() if enc else c.decryptor()
    return o.update(data) + o.finalize()


def auth(e, keyhex):
    k = bytes.fromhex(keyhex)
    r = e.cmd([0x1A, 0x00])
    if not r or len(r) != 9 or r[0] != 0xAF:
        print('auth step 1:', r); e.resel(); return False
    ekb = r[1:]
    rndb = des(k, bytes(8), ekb, False)
    rnda = os.urandom(8)
    c = des(k, ekb, rnda + rndb[1:] + rndb[:1], True)
    r = e.cmd([0xAF] + list(c))
    if not r or len(r) != 9 or r[0] != 0x00:
        print('auth step 2:', r); e.resel(); return False
    a = des(k, c[8:], r[1:], False)
    ok = a == rnda[1:] + rnda[:1]
    print('auth', 'ok' if ok else "RndA' mismatch")
    return ok


e = Ev1(sys.argv[1]); cmd = sys.argv[2]
if cmd == 'dump':
    import time
    e.s.mon.write32(0x5C360, [0]); time.sleep(0.2); e.s.mon.write32(0x5C360, [6]); time.sleep(0.02)
    print('field cycled, reselect', e.resel())
    if len(sys.argv) > 3: auth(e, sys.argv[3])
    for p in range(0x30):
        r = e.cmd([0x30, p])
        print(f'{p:2} {p:02X}:', r[:4].hex() if r and len(r) >= 4 else r)
        if r in (None, b'NAK'): e.resel()
elif cmd == 'cfg':
    a0, a1 = int(sys.argv[3], 16), int(sys.argv[4], 16)
    if not auth(e, sys.argv[5] if len(sys.argv) > 5 else FACTORY): sys.exit(1)
    # AUTH1 first while still authenticated, then AUTH0
    for page, v in ((0x2B, a1), (0x2A, a0)):
        r = e.cmd([0xA2, page, v, 0, 0, 0])
        print(f'write {page:02X} {v:02X}000000: {r}')
        if r != b'ACK': sys.exit(1)
elif cmd == 'setkey':  # HOST setkey NEWKEY CURKEY: write 2C-2F, then check the new key
    new, cur = sys.argv[3], sys.argv[4]
    if not auth(e, cur): sys.exit(1)
    k = bytes.fromhex(new)
    pg = [k[(i // 8) * 8 + 7 - i % 8] for i in range(16)]
    for i in range(4):
        r = e.cmd([0xA2, 0x2C + i] + pg[4 * i:4 * i + 4])
        print(f'write {0x2C + i:02X} {bytes(pg[4*i:4*i+4]).hex()}: {r}')
        if r != b'ACK': sys.exit(1)
    e.resel()
    print('new key:', auth(e, new))
