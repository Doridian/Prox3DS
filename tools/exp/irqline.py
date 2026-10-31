# Does the IRQ pin go high while a reply is pending, and low once it has been read?
#   irqline.py HOST
import sys, time, struct
sys.path.insert(0, __file__.rsplit('/', 2)[0])
from mfc import *

s = Session(sys.argv[1])
s.recover()
gpio = lambda: struct.unpack('<I', s.nfc.call(nfcnet.OP_GPIO, struct.pack('<II', 0, 0)))[0] >> 16 & 1
pkt = s.mon._pkt(chipmon.OP_READ32, 0x5C540, bytes([1]))
for i in range(5):
    before = gpio()
    s.nfc.write(pkt)
    time.sleep(0.02)
    pending = gpio()
    r = s.nfc.read(200)
    after = gpio()
    print(f'irq idle {before}, reply pending {pending}, after read {after}; reply {r.hex(" ")}', flush=True)
