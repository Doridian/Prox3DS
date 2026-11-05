import sys, time
sys.path.insert(0, __file__.rsplit('/', 3)[0])
from mfc import *
s = Session(sys.argv[1]); s.recover()
for n in range(4):
    print('blk 400', ' '.join(f'{x:x}' for x in s.mon.read32(0x5C400, 24)))
    print('blk 420', ' '.join(f'{x:x}' for x in s.mon.read32(0x5C420, 4)))
    print('blk 424', ' '.join(f'{x:x}' for x in s.mon.read32(0x5C424, 3)))
    print('blk 500', ' '.join(f'{x:x}' for x in s.mon.read32(0x5C500, 8)))
    print('blk 040', ' '.join(f'{x:x}' for x in s.mon.read32(0x5C040, 8)))
