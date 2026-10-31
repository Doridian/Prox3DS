# Does a frame without answer hang the next TX? parity on vs off.
#   noanswer.py HOST
import sys
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()


def probe(name, fn):
    def run():
        s.parity(True)
        if s.select() is None:
            raise chipmon.MonError('select failed')
        fn()
        s.parity(True)
        return 'next select: ' + ('ok' if s.select() is not None else 'no answer')
    try:
        print(name, run(), flush=True)
    except (chipmon.MonError, nfcnet.NfcError) as e:
        print(name, 'HANG', e, flush=True)
        s.reconnect(); s.recover()


hlta = with_crc(b'\x50\x00') if False else b'\x50\x00' + crc_a(b'\x50\x00')
for _ in range(2):
    probe('HLTA parity on ', lambda: s.tx(hlta))
    probe('HLTA parity off', lambda: (s.parity(False), s.ptx(hlta)))
    probe('junk 9B parity off', lambda: (s.parity(False), s.ptx(bytes(8))))
