# After an idle hang: GPIO state, raw reads, and whether the monitor comes back on its own.
#   hang.py HOST
import sys, time, struct
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()
t0 = time.time()
while True:
    try:
        s.mon.read32(0x5C540, 1)
        time.sleep(0.25)
    except (chipmon.MonError, nfcnet.NfcError) as e:
        print(f'hang after {time.time() - t0:.1f}s: {e}', flush=True)
        break
s.reconnect()
gp = struct.unpack('<I', s.nfc.call(nfcnet.OP_GPIO, struct.pack('<II', 0, 0)))[0]
print(f'gpio {gp:08x} (REG_PU {gp >> 13 & 1}, WAKE {gp >> 12 & 1}, IRQ {gp >> 16 & 1})')
for i in range(8):
    p = s.nfc.read(500)
    print(f'  read: {p.hex(" ") if p else "(nothing)"}', flush=True)
t1 = time.time()
while time.time() - t1 < 30:
    try:
        s.mon.read32(0x5C540, 1)
        print(f'monitor back after {time.time() - t1:.1f}s', flush=True)
        break
    except (chipmon.MonError, nfcnet.NfcError) as e:
        s.reconnect()
else:
    print('still hung after 30s')
