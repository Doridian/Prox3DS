# authtear.py HOST FROM TO STEP [PWD]: torn wrong-PWD_AUTH sweep. AUTHLIM must be 0 (no lockout).
# For each delay, cut the field that many us after the 0x1B frame, then (after reselect) do a correct
# auth to confirm the card is alive and NOT locked. Prints what the torn auth returned.
import sys
sys.path.insert(0, '.')
from tlib import Ev1
TX_END = 697
e = Ev1(sys.argv[1]); frm, to, step = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
good = sys.argv[5] if len(sys.argv) > 5 else '11223344'
wrong = [0xDE, 0xAD, 0xBE, 0xEF]
def correct():
    r = e.cmd([0x1B] + list(bytes.fromhex(good)))
    return r.hex() if r and r not in (b'ACK', b'NAK') else r
for us in range(frm, to + 1, step):
    e.resel()
    # torn wrong auth: schedule the field cut us after the 0x1B frame
    e.s.mon.txsched(bytes([0x1B] + wrong), 0, [(TX_END + us, 0x5C360, 0), (TX_END + us + 2000, 0x5C360, 6)], r574=0)
    import time; time.sleep(0.01); e.s.nfc.drain(50)
    fr = e.s.mon.frames()
    resp = fr[-1][1].hex() if fr else 'none'
    e.resel()
    alive = correct()
    print(f'{us:5} us: torn resp {resp:8}  correct-auth {alive}', flush=True)
