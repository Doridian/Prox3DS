# TX busy duration per mode/code/FIFO bytes, with the experimental monitor (op 8 TXTIME).
import struct, sys
sys.path.insert(0, __file__.rsplit('/', 3)[0])
import chipmon, dumpchip, mkpatch, nfcnet
from mfc import *

EXP = __file__.rsplit('/', 1)[0] + '/reader_auth.bin'
def load(self):
    self.nfc.takeover()
    if dumpchip.load(self.nfc, mkpatch.build(open(EXP, 'rb').read())) is None:
        raise chipmon.MonError('chip dead after download')
    self.nfc.cmd(nfcnet.CORE_INIT)
chipmon.Mon.load = load

def txtime(s, data, code, r574=1, r570=0, r55c=0x88, sched=()):
    """sched: [(delay ticks after the FIFO writes, reg, val)] in delay order.
    Returns (TX busy ticks, [tick of each store])."""
    p = s.mon._do(8, 0, bytes([r570, r574, code, r55c]) + struct.pack('<I', len(sched))
                  + b''.join(struct.pack('<III', *e) for e in sched) + data)
    v = struct.unpack(f'<{len(p) // 4}I', p)
    return v[0], list(v[1:])

