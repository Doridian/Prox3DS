# For each register of a snapshot: write 0 (or VAL), hold 5 ms, restore, then READ page 0.
# A READ that fails while the card answers WUPA afterwards = the card lost power (field went off).
import sys, json, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
from rawa import with_crc
snap = {int(a, 16): v for a, v in json.load(open(sys.argv[2])).items()}
only = [int(a, 16) for a in sys.argv[3:]] or sorted(snap)
s = Session(sys.argv[1]); s.recover(); u = s.uid
def rd():
    a = s.answer(with_crc(b'\x30\x00')); return bool(a and len(a) == 18)
def resel():
    if s.answer(b'\x52', 0x07) is None: return False
    s.answer(b'\x93\x20'); s.answer(b'\x93\x70\x88' + u[:3] + bytes([0x88 ^ u[0] ^ u[1] ^ u[2]]))
    s.answer(b'\x95\x20'); return s.answer(b'\x95\x70' + u[3:7] + bytes([u[3] ^ u[4] ^ u[5] ^ u[6]])) is not None
for a in only:
    v = snap.get(a, 0)
    try:
        if not rd():
            print(f'{a:x}: card not active before, reselect', resel(), rd()); continue
        s.mon.write32(a, [0]); time.sleep(0.005); s.mon.write32(a, [v]); time.sleep(0.005)
        r = rd()
        w = None if r else s.answer(b'\x52', 0x07)
        print(f'{a:x} ({v:x}): read {"ok" if r else "FAIL"}' + ('' if r else f'  wupa {w.hex() if w else None}'), flush=True)
        if not r: resel() or resel() or resel()
    except (chipmon.MonError, nfcnet.NfcError, OSError) as e:
        print(f'{a:x}: stall {e}', flush=True); s.reconnect(); s.recover(); u = s.uid
