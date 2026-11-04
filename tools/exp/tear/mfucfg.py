# mfucfg.py HOST CMD ... : raw EV1 config helper over the monitor (tlib).
#   HOST dump                 read pages 0..19 (plain)
#   HOST auth PWD             PWD_AUTH, show PACK
#   HOST write PAGE HEX8 [PWD]   WRITE page (PWD_AUTH first if PWD given)
#   HOST setpwd PWD PACK AUTH0 ACCESS [CURPWD]  set PWD/PACK/cfg1.access/cfg0.auth0 in a safe order
#   HOST clear CURPWD         restore factory (AUTH0 FF, cfg1 00050000, PWD FFFFFFFF, PACK 0000)
import sys
sys.path.insert(0, '.')
from tlib import Ev1

e = Ev1(sys.argv[1]); cmd = sys.argv[2]


def auth(pwd):
    r = e.cmd([0x1B] + list(bytes.fromhex(pwd)))
    if r in (b'NAK', None):
        print('PWD_AUTH refused', r); return None
    return r  # PACK (2 bytes)


def wr(page, data, pwd=None):
    if pwd:
        if auth(pwd) is None: return False
    r = e.cmd([0xA2, page] + list(bytes.fromhex(data)))
    print(f'write {page} {data}: {r}')
    return r == b'ACK'


def dump():
    for p in range(20):
        r = e.cmd([0x30, p])
        print(f'{p:2} {p:02X}:', r[:4].hex() if r and len(r) >= 4 else r)


if cmd == 'dump':
    dump()
elif cmd == 'auth':
    pk = auth(sys.argv[3])
    print('PACK', pk.hex() if pk else None)
elif cmd == 'write':
    wr(int(sys.argv[3], 0), sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else None)
elif cmd == 'setpwd':
    pwd, pack, auth0, access = sys.argv[3:7]
    cur = sys.argv[7] if len(sys.argv) > 7 else None
    # order: PWD, PACK (while still open or with cur), then cfg1 access, then cfg0 auth0 last
    wr(18, pwd, cur)
    wr(19, pack + '0000', pwd)
    wr(17, access, pwd)       # cfg1: byte0 access (PROT bit7, AUTHLIM bits2-0), byte1 VCTID 05
    wr(16, '000000' + auth0, pwd)  # cfg0: byte3 AUTH0
    print('--- after ---');
    e.resel(); print('PACK', (auth(pwd) or b'').hex()); dump()
elif cmd == 'clear':
    cur = sys.argv[3]
    wr(16, '000000ff', cur)
    wr(17, '00050000', cur)
    wr(18, 'ffffffff', cur)
    wr(19, '00000000', cur)
    print('--- after ---'); e.resel(); dump()
