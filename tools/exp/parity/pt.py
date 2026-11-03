"""Listen-mode parity hunt with chip/ptest.c: load it, listen as UID 01020304 / SAK 08, and give helpers to
time listen TXs (the pm3 holds the field: hf 14a raw -k -s -c e5)."""
import struct
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet

OP_PT, OP_RUN = 5, 6
O_NW, O_W, O_N, O_CRC, O_DATA, O_REPS, O_FRAMES, O_R568, O_OLD, O_DURING = 0, 4, 100, 104, 108, 140, 144, 148, 152, 184
PM3 = ["pm3", "-p", "/dev/ttyACM1", "-c"]


class PT:
    def __init__(self, host="192.0.2.6"):
        self.nfc = nfcnet.Nfc(host)
        self.mon = chipmon.Mon(self.nfc, on_other=lambda p: None)
        self.reload()

    def reload(self):
        self.mon.load("ptest.bin")
        self.base = struct.unpack("<I", self.mon._do(OP_PT, 0))[0]
        tl = bytes.fromhex("300104" "310100" "320108" "330401020304")
        for c in (bytes([0x20, 0x02, len(tl) + 1, 4]) + tl, bytes.fromhex("2100040104" "0202"),
                  bytes.fromhex("200204018001" "01"), bytes.fromhex("2103030180" "01")):
            self.nfc.cmd(b"\x10" + c)

    def setup(self, data, crc=0, writes=(), reps=4, r568=0):
        w = b"".join(struct.pack("<III", *x) for x in writes).ljust(96, b"\0")
        blob = struct.pack("<I", len(writes)) + w + struct.pack("<II", len(data), crc) + bytes(data).ljust(32, b"\0")
        blob += struct.pack("<III", reps, 0, r568)
        self.mon.write(self.base, blob)

    def run(self, reps=4):
        r = self.mon._do(OP_RUN, 0)
        return list(struct.unpack(f"<{len(r) // 4}I", r))

    def regs(self):
        r = self.mon._do(chipmon.OP_READ8, self.base + O_OLD, bytes([64]))
        return struct.unpack("<8I", r[:32]), struct.unpack("<8I", r[32:])

    def frames(self):
        return struct.unpack("<I", self.mon._do(chipmon.OP_READ8, self.base + O_FRAMES, bytes([4])))[0]

    def rearm(self):
        self.nfc.drain(50)
        self.nfc.cmd(bytes.fromhex("1021060100"))
        self.nfc.cmd(bytes.fromhex("10" "2103030180" "01"))
        time.sleep(0.2)

    def select(self, tries=5):
        for _ in range(tries):
            self.rearm()
            f = self.frames()
            o = pm3(["hf 14a raw -k -s -c e5 00"])
            if self.frames() > f:
                return o
        raise RuntimeError("no select")

    def stop(self):
        self.nfc.cmd(bytes.fromhex("1021060100"))


def pm3(cmd, t=20):
    return subprocess.run(PM3 + cmd, capture_output=True, text=True, timeout=t).stdout


O_T, O_TIME, O_NFIX = 216, 984, 1240


def session(p, tests, data=bytes(range(16)), crc=0, tries=6, r568=0, fixed=()):
    """Run tests [(addr, value, how) or None] (up to 64) on one selection; returns (times, pm3 answers)."""
    p.setup(data, crc, writes=fixed, r568=r568)
    p.mon.write(p.base + O_NFIX, struct.pack("<I", len(fixed)))
    tab = b"".join(struct.pack("<III", *(t or (0, 0, 0))) for t in tests)
    p.mon.write(p.base + O_T, tab)
    p.mon.write(p.base + O_TIME, bytes(4 * len(tests)))
    cmd = "; ".join([f"hf 14a raw -k {'-s ' if i == 0 else ''}-c e5 {i:02x}" for i in range(len(tests))] + ["hw fpgaoff"])
    for _ in range(tries):
        p.nfc.drain(50)
        o = pm3([cmd], t=60)
        if "Can't select" not in o:
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("no select")
    ans, cur = [], None
    for l in o.splitlines():
        if "pm3 --> hf 14a raw" in l:
            if cur is not None:
                ans.append(cur)
            cur = ""
        elif cur is not None and l.startswith("[+] ") and "pm3" not in l:
            cur += l[4:].strip() + " "
        elif cur is not None and ("[!]" in l or "[-]" in l):
            cur += l.strip() + " "
    if cur is not None:
        ans.append(cur)
    r = b"".join(p.mon._do(chipmon.OP_READ8, p.base + O_TIME + o, bytes([min(128, 4 * len(tests) - o)]))
                 for o in range(0, 4 * len(tests), 128))
    return list(struct.unpack(f"<{len(tests)}I", r)), ans
