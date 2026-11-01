#!/usr/bin/env python3
"""PC side of nfcprobe's network server (nfcprobe/source/netsrv.c, TCP port 8020).

usage: nfcnet.py HOST probe              take over, power cycle, CORE_RESET/INIT, GET_PATCH_VERSION
       nfcnet.py HOST spd FILE.ncd       power cycle, download an SPD patch, show the version
       nfcnet.py HOST send HEX [HEX...]  send raw I2C packets (HCIT included), print the replies
       nfcnet.py HOST release            power off and give the pins back
       nfcnet.py HOST update [FILE]      send a new nfcprobe.3dsx (default: the build), app restarts into it
  Card ops implemented in the app (nfcprobe mfc.c):
       nfcnet.py HOST scan                         activate a card, show ATQA/SAK/UID
       nfcnet.py HOST mfread BLOCK KEY [b] [N]     Mifare Classic auth + read N blocks
       nfcnet.py HOST mfdump [KEY...] [-o OUT]     dump with keys (+ keys.txt + defaults), also saved to SD
       nfcnet.py HOST gen1awrite BLOCK HEX32       Gen1a backdoor write of 16 bytes (WRITES THE CARD)
       nfcnet.py HOST mfwrite BLOCK KEY HEX32 [b]  Mifare Classic encrypted write + read-back (WRITES THE CARD)
       nfcnet.py HOST nested KBLK KKEY TBLK [kb][tb]  recover TBLK's key from a known key (nested attack)
       nfcnet.py HOST magic [nogen2] [PWD]         detect Gen1a / Gen2 / Gen4 GTU / USCUID (+ config); Gen2 the
                                                   pm3 way (ATS, block 0 WRITE ACK, aborted: nothing written)
       nfcnet.py HOST g4read BLOCK [N] [PWD]       Gen4 GTU read without keys (PWD default 00000000)
       nfcnet.py HOST g4write BLOCK HEX32 [PWD]    Gen4 GTU write + read-back (WRITES THE CARD)
       nfcnet.py HOST clone FILE [force]           write a dump (.bin) onto a magic card (GTU, Gen1a/USCUID,
                                                   Gen2), each block read back (WRITES THE CARD)
       nfcnet.py HOST uscconfig [HEX32]            USCUID (Gen4 GDM) config via the Gen1a wakeup: read and
                                                   decode; with HEX32 write it (guarded; WRITES CONFIG)
       nfcnet.py HOST g4config [HEX60] [PWD]       Gen4 GTU config: read and decode; with HEX60 write it
                                                   (only UID length/shadow/ATS/ATQA/SAK may change; WRITES CONFIG)
  UI debugging:
       nfcnet.py HOST mfudump [PWD] [-o OUT]       Ultralight / NTAG: info + every readable page (PWD: 8 hex,
                                                   tried once), also saved to SD; OUT = pm3 .bin
       nfcnet.py HOST mfuwrite PAGE HEX8           Ultralight / NTAG user page write + read-back (WRITES THE CARD)
       nfcnet.py HOST mfuclone FILE                clone a pm3 mfu dump onto a Gen4 GTU (switches it to
                                                   Ultralight mode; WRITES THE CARD AND ITS CONFIG)
       nfcnet.py HOST apdu [-a] HEX [HEX...]       ISO-DEP (nfcprobe isodep.c): -a = DESELECT + reselect + RATS
                                                   first (shows the ATS); each HEX one command, its answer
       nfcnet.py HOST df [-a] STEP [STEP...]      DESFire through nfcprobe desfire.c (EV1 secure messaging),
                                                   -a = ISO-DEP activate first. STEPs (MAY WRITE THE CARD):
                                                     auth:K:TYPE:KEY       TYPE des/2k3des/3k3des/aes
                                                     cmd:COMM:HDR:HEX      COMM plain/mac/full/enc, HDR = plain
                                                                           bytes after the command byte
                                                     ck:K:TYPE:KEY[:OTYPE:OKEY][:picc][:vN]  ChangeKey
                                                     info / infokeys       read all (+ key dictionary), print
       nfcnet.py HOST shot [OUT.png]               grab the top screen (default shot.png; needs Pillow)
       nfcnet.py HOST log [N]                      the app log's last N lines (default 50), net client lines cut
       nfcnet.py HOST keys KEY [KEY...]            press buttons in the UI, one frame each, ~0.1 s apart
                                                   (a b x y l r up down left right start select)
"""
import os
import socket
import struct
import sys

PORT = 8020
(OP_PING, OP_TAKEOVER, OP_POWER, OP_WRITE, OP_READ, OP_XFER, OP_GPIO, OP_RELEASE, OP_UPDATE,
 OP_UPDATE_DONE) = range(10)
UPDATE_CHUNK = 0x7000
(OP_14A_START, OP_14A_PARITY, OP_14A_TX, OP_MF_READ, OP_MF_DUMP,
 OP_GEN1A_WRITE, OP_MF_WRITE, OP_MF_NESTED, OP_MF_MAGIC, OP_GEN4_READ,
 OP_GEN4_WRITE, OP_GEN4_CONFIG, OP_USC_CONFIG, OP_MF_CLONE, OP_MFU_DUMP, OP_MFU_WRITE) = range(0x10, 0x20)
GEN4_PWD = bytes(4)
OP_SHOT, OP_KEYS, OP_MFU_CLONE, OP_ISODEP, OP_LOG, OP_DF = 0x20, 0x21, 0x22, 0x23, 0x24, 0x25
DF_TYPES = {"des": 1, "2k3des": 1, "3k3des": 2, "aes": 3}  # dfcrypto.h (DES goes as 2K3DES, halves equal)
DF_COMM = {"plain": 0, "mac": 1, "full": 3, "enc": 4}


def df_key(t, k):
    k = bytes.fromhex(k)
    return bytes([DF_TYPES[t]]) + (k * 2 if t == "des" else k)
KEYS = {"a": 1 << 0, "b": 1 << 1, "select": 1 << 2, "start": 1 << 3, "right": 1 << 4, "left": 1 << 5,
        "up": 1 << 6, "down": 1 << 7, "r": 1 << 8, "l": 1 << 9, "x": 1 << 10, "y": 1 << 11}
NO_CARD = 1  # card op result: no card / auth refused

CORE_RESET = bytes.fromhex("1020000101")
CORE_INIT = bytes.fromhex("10200100")
GET_PATCH_VERSION = bytes.fromhex("102f2d00")


class NfcError(Exception):
    pass


class Nfc:
    def __init__(self, host, port=PORT):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise NfcError("connection closed")
            buf += chunk
        return buf

    def call(self, op, payload=b""):
        self.send_call(op, payload)
        return self.recv_reply(op)

    # Split halves of call(), for pipelining requests without waiting for each reply.
    def send_call(self, op, payload=b""):
        self.sock.sendall(struct.pack("<BH", op, len(payload)) + payload)

    def recv_reply(self, op):
        rop, res, ln = struct.unpack("<BIH", self._recv(7))
        data = self._recv(ln)
        if rop != op:
            raise NfcError(f"reply for op {rop}, sent {op}")
        if res:
            raise NfcError(f"op {op} failed: {res:08X}")
        return data

    def card_call(self, op, payload=b"", timeout=10):
        """Card ops: returns the payload, None for result NO_CARD."""
        self.sock.settimeout(timeout)
        try:
            self.send_call(op, payload)
            rop, res, ln = struct.unpack("<BIH", self._recv(7))
            data = self._recv(ln)
        finally:
            self.sock.settimeout(10)
        if res == NO_CARD:
            self.why = data.decode(errors="replace")
            return None
        if res:
            raise NfcError(f"op {op:#x} failed: {res:08X} {data.decode(errors='replace')}")
        return data

    def scan(self):
        """-> (atqa, sak, uid) or None."""
        p = self.card_call(OP_14A_START, timeout=30)
        return p and (p[0:2], p[2], p[4:4 + p[3]])

    def mf_read(self, block, key, key_b=False, count=1):
        """-> [16 bytes or None per block], None if auth was refused."""
        p = self.card_call(OP_MF_READ, bytes([block, key_b]) + key + bytes([count]), 30)
        return p and [p[i + 1:i + 17] if p[i] else None for i in range(0, len(p), 17)]

    def mf_dump(self, keys=(), sectors=0):
        """-> (keys {(sector, 'A'/'B'): key}, blocks [16 bytes or None]) or None (no card)."""
        p = self.card_call(OP_MF_DUMP, bytes([sectors]) + b"".join(keys), None)
        if p is None:
            return None
        n, o, found = p[0], 1, {}
        for sec in range(n):
            for k, name in ((0, "A"), (1, "B")):
                if p[o] >> k & 1:
                    found[sec, name] = p[o + 1 + 6 * k:o + 7 + 6 * k]
            o += 13
        blocks = [p[i + 1:i + 17] if p[i] else None for i in range(o, len(p), 17)]
        return found, blocks

    def gen1a_write(self, block, data):
        """Gen1a backdoor write of 16 bytes to a block (writes the card). Returns True if the
        device verified the write, False if refused (reason in self.why). WRITES THE CARD."""
        if len(data) != 16:
            raise ValueError("data must be 16 bytes")
        p = self.card_call(OP_GEN1A_WRITE, bytes([block]) + bytes(data), 30)
        return p is not None

    def mf_write(self, block, key, data, key_b=False):
        """Encrypted Mifare Classic write of 16 bytes (auth with key, write, read back). True if
        verified, False if refused / failed (reason in self.why). WRITES THE CARD."""
        if len(data) != 16:
            raise ValueError("data must be 16 bytes")
        p = self.card_call(OP_MF_WRITE, bytes([block, key_b]) + bytes(key) + bytes(data), 30)
        return p is not None

    def mf_nested(self, known_block, known_key, target_block, known_b=False, target_b=False):
        """Nested attack: recover target_block's key from a known key in another sector. Returns the
        6-byte key, or None (reason in self.why)."""
        arg = (bytes([known_block, 1 if known_b else 0]) + bytes(known_key)
               + bytes([target_block, 1 if target_b else 0]))
        return self.card_call(OP_MF_NESTED, arg, 60)

    def mf_magic(self, gen2=False, pwd=GEN4_PWD):
        """-> ({'gen1a', 'gen2', 'gen4', 'uscuid'}, gen4 config, uscuid config) or None (no card). gen2=True also tests
        Gen2 (known ATS, or block 0 WRITE ACKed and aborted before the data: nothing written)."""
        p = self.card_call(OP_MF_MAGIC, bytes([gen2]) + bytes(pwd), 60)
        if p is None:
            return None
        flags = {n for i, n in enumerate(("gen1a", "gen2", "gen4", "uscuid")) if p[0] >> i & 1}
        return flags, p[2:2 + p[1]], p[2 + p[1]:] if "uscuid" in flags else b""

    def usc_config(self, cfg=None):
        """Read the USCUID config (16 bytes, None if refused: reason in self.why), or write cfg and
        read it back: True if verified. WRITES THE CARD CONFIG."""
        p = self.card_call(OP_USC_CONFIG, bytes(cfg or b""), 30)
        return p if cfg is None or p is None else True

    def gen4_read(self, block, count=1, pwd=GEN4_PWD):
        """Gen4 GTU read without keys -> [16 bytes or None per block], None if no card."""
        p = self.card_call(OP_GEN4_READ, bytes(pwd) + bytes([block, count]), 30)
        return p and [p[i + 1:i + 17] if p[i] else None for i in range(0, len(p), 17)]

    def gen4_write(self, block, data, pwd=GEN4_PWD):
        """Gen4 GTU write of 16 bytes + read-back. True if verified, False if refused (reason in
        self.why). WRITES THE CARD."""
        if len(data) != 16:
            raise ValueError("data must be 16 bytes")
        return self.card_call(OP_GEN4_WRITE, bytes(pwd) + bytes([block]) + bytes(data), 30) is not None

    def gen4_config(self, cfg=None, pwd=GEN4_PWD):
        """Read the Gen4 GTU config (bytes, None if no answer: reason in self.why), or with cfg
        (30 bytes) write it and read it back: True if verified. WRITES THE CARD CONFIG."""
        p = self.card_call(OP_GEN4_CONFIG, bytes(pwd) + bytes(cfg or b""), 30)
        return p if cfg is None or p is None else True

    def mfu_dump(self, pwd=None):
        """-> (header[56], pwd_ok, pages [bytes or None], type name), or None (self.why)."""
        r = self.card_call(OP_MFU_DUMP, pwd or b"", timeout=30)
        if r is None:
            return None
        hdr, pwd_ok, n = r[:56], r[56], r[11] + 1
        pages = [r[57 + 5 * i + 1:57 + 5 * i + 5] if r[57 + 5 * i] else None for i in range(n)]
        p = 57 + 5 * n
        return hdr, bool(pwd_ok), pages, r[p + 1:p + 1 + r[p]].decode()

    def mfu_clone(self, dump):
        return self.card_call(OP_MFU_CLONE, dump, timeout=60) is not None

    def mfu_write(self, page, data):
        if self.card_call(OP_MFU_WRITE, bytes([page]) + data) is None:
            return False
        return True

    def isodep(self, inf=b"", activate=False):
        """One ISO-DEP exchange -> answer (with activate: ATS + answer), None on failure (self.why)."""
        return self.card_call(OP_ISODEP, bytes([activate]) + inf, timeout=30)

    def df(self, action, args=b"", timeout=60):
        """DESFire op (netsrv OP_DF): status byte + data, None on a lost card (self.why)."""
        return self.card_call(OP_DF, bytes([action]) + args, timeout)

    def update(self, data, log=print):
        """Upload a new .3dsx; the app swaps it in, exits and relaunches itself."""
        for o in range(0, len(data), UPDATE_CHUNK):
            self.call(OP_UPDATE, struct.pack("<I", o) + data[o:o + UPDATE_CHUNK])
            log(f"  {min(o + UPDATE_CHUNK, len(data))}/{len(data)}")
        self.call(OP_UPDATE_DONE, struct.pack("<I", len(data)))

    def mf_clone(self, blocks, force=False):
        """Write blocks (16 bytes each, None = skip) onto a magic card. True if done, False if
        refused (reason in self.why). WRITES THE CARD."""
        p = bytes([force]) + b"".join(bytes([1]) + b if b else bytes(17) for b in blocks)
        return self.card_call(OP_MF_CLONE, p, None) is not None

    def shot(self):
        """Top screen as a PIL image (the framebuffer is 240x400 BGR8, column-major from the bottom)."""
        from PIL import Image
        raw = b""
        while True:
            chunk = self.call(OP_SHOT, struct.pack("<I", len(raw)))
            if not chunk:
                break
            raw += chunk
        img = Image.frombytes("RGB", (240, len(raw) // 720), raw, "raw", "BGR")
        return img.transpose(Image.Transpose.ROTATE_90)

    def log(self, lines=50):
        """The last `lines` lines of the app log."""
        return self.call(OP_LOG, struct.pack("<I", lines)).decode(errors="replace")

    def keys(self, mask):
        self.call(OP_KEYS, struct.pack("<I", mask))

    def takeover(self):
        self.call(OP_TAKEOVER)

    def power(self, on=True):
        self.call(OP_POWER, bytes([1 if on else 0]))

    def write(self, pkt):
        self.call(OP_WRITE, pkt)

    def read(self, timeout_ms=100):
        return self.call(OP_READ, struct.pack("<H", timeout_ms))

    def xfer(self, pkt, timeout_ms=500):
        return self.call(OP_XFER, struct.pack("<H", timeout_ms) + pkt)

    def gpio(self, value=0, mask=0):
        return struct.unpack("<I", self.call(OP_GPIO, struct.pack("<II", value, mask)))[0]

    def release(self):
        self.call(OP_RELEASE)

    def drain(self, timeout_ms=50):
        pkts = []
        while pkt := self.read(timeout_ms):
            pkts.append(pkt)
        return pkts

    def cmd(self, pkt, timeout_ms=500):
        """Send a command, return [response, notifications...]."""
        first = self.xfer(pkt, timeout_ms)
        return ([first] if first else []) + self.drain()

    def spd_download(self, ncd, log=print):
        """Send an SPD patch record by record (see nfcprobe spdDownload)."""
        o, rec = 0, 0
        while o + 5 <= len(ncd):
            ln = 4 + ncd[o + 3]
            status = None
            for pkt in self.cmd(ncd[o:o + ln], 1000):
                if pkt[1] == 0x4F and pkt[2] & 0x3F == 0x2E and len(pkt) >= 5:
                    status = pkt[4]
                else:
                    log("  other: " + describe(pkt))
            log(f"  rec {rec:2d} type {ncd[o + 4]:02X} len {ln - 5:3d} -> status {status}")
            if status != 0:
                return False
            o += ln
            rec += 1
        # Authentication result, then the reset notification (60 00) ends the download.
        while pkt := self.read(2000):
            log("  " + describe(pkt))
            if pkt[1:3] == b"\x60\x00":
                break
        return True


def describe(pkt):
    s = pkt.hex(" ")
    if not pkt:
        return "(nothing)"
    if pkt[0] == 0x04 and len(pkt) >= 7 and pkt[1] == 0x0E:
        return f"{s}  [HCI cmd complete {pkt[4] | pkt[5] << 8:04X} status {pkt[6]:02X}]"
    if pkt[0] != 0x10 or len(pkt) < 4:
        return s
    mt, gid, oid, p = pkt[1] >> 5, pkt[1] & 0xF, pkt[2] & 0x3F, pkt[4:]
    what = f"{['DATA', 'CMD', 'RSP', 'NTF'][mt]} {gid:X}/{oid:02X}"
    if mt == 2 and gid == 0xF and oid == 0x2D and len(p) >= 24:
        chip = p[4:20].split(b"\0")[0].decode(errors="replace").strip()
        what += f" PATCH_VERSION proj={p[0] | p[1] << 8:04X} chip={chip} ver={p[20] | p[21] << 8}.{p[22] | p[23] << 8}"
    elif mt == 2 and p:
        what += f" status {p[0]:02X}"
    return f"{s}  [{what}]"


def chip_info(nfc):
    for c in (CORE_RESET, CORE_INIT, GET_PATCH_VERSION):
        for pkt in nfc.cmd(c):
            print("  " + describe(pkt))


def start(nfc):
    nfc.takeover()
    nfc.power(True)
    for pkt in nfc.drain():
        print("  power-up: " + describe(pkt))


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    nfc = Nfc(sys.argv[1])
    print(nfc.call(OP_PING).decode())
    what, args = sys.argv[2], sys.argv[3:]
    if what == "probe":
        start(nfc)
        chip_info(nfc)
    elif what == "spd":
        start(nfc)
        ok = nfc.spd_download(open(args[0], "rb").read())
        print("download", "completed" if ok else "FAILED")
        chip_info(nfc)
    elif what == "send":
        nfc.takeover()
        for h in args:
            for pkt in nfc.cmd(bytes.fromhex(h)):
                print("  " + describe(pkt))
    elif what == "release":
        nfc.release()
    elif what == "update":
        path = args[0] if args else os.path.join(os.path.dirname(__file__), "../nfcprobe/nfcprobe.3dsx")
        nfc.update(open(path, "rb").read())
        print("updated, app restarting")
    elif what == "shot":
        out = args[0] if args else "shot.png"
        nfc.shot().save(out)
        print("saved", out)
    elif what == "log":
        # the net client lines every call adds are noise here
        lines = nfc.log(int(args[0]) if args else 50).splitlines()
        print("\n".join(l for l in lines if not l.startswith("net: client")))
    elif what == "keys":
        import time
        for k in args:
            nfc.keys(KEYS[k.lower()])
            time.sleep(0.1)
    elif what == "scan":
        r = nfc.scan()
        print("no card" if r is None else f"ATQA {r[0][::-1].hex()} SAK {r[1]:02X} UID {r[2].hex()}")
    elif what == "mfread":
        blk, key = int(args[0]), bytes.fromhex(args[1])
        r = nfc.mf_read(blk, key, len(args) > 2 and args[2] == "b", int(args[3]) if len(args) > 3 else 1)
        if r is None:
            print("auth refused / no card:", nfc.why)
        for i, d in enumerate(r or []):
            print(f"{blk + i:3}: {d.hex(' ') if d else 'read failed'}")
    elif what == "mfdump":
        out = args[args.index("-o") + 1] if "-o" in args else None
        keys = [bytes.fromhex(k) for k in args if len(k) == 12 and k != out]
        r = nfc.mf_dump(keys)
        if r is None:
            sys.exit("no card")
        found, blocks = r
        for sec in range(len(blocks) // 4 if len(blocks) <= 128 else 32 + (len(blocks) - 128) // 16):
            ka, kb = found.get((sec, "A")), found.get((sec, "B"))
            print(f"sector {sec:2}: A {ka.hex() if ka else '-' * 12}  B {kb.hex() if kb else '-' * 12}")
        for i, d in enumerate(blocks):
            print(f"{i:3}: {d.hex(' ') if d else '??'}")
        if out:
            open(out, "wb").write(b"".join(d or bytes(16) for d in blocks))
    elif what == "nested":
        # nested KNOWN_BLOCK KNOWN_KEY TARGET_BLOCK [kb] [tb]
        kblk, kkey, tblk = int(args[0]), bytes.fromhex(args[1]), int(args[2])
        flags = args[3:]
        key = nfc.mf_nested(kblk, kkey, tblk, "kb" in flags, "tb" in flags)
        print(f"recovered key for block {tblk}: {key.hex()}" if key else f"failed: {nfc.why}")
    elif what == "gen1awrite":
        blk, data = int(args[0]), bytes.fromhex(args[1])
        ok = nfc.gen1a_write(blk, data)
        print("VERIFIED" if ok else f"write failed: {nfc.why}")
    elif what == "mfwrite":
        blk, key, data = int(args[0]), bytes.fromhex(args[1]), bytes.fromhex(args[2])
        ok = nfc.mf_write(blk, key, data, len(args) > 3 and args[3] == "b")
        print("VERIFIED" if ok else f"write failed: {nfc.why}")
    elif what == "magic":
        gen2 = "nogen2" not in args
        pwd = next((bytes.fromhex(a) for a in args if len(a) == 8), GEN4_PWD)
        r = nfc.mf_magic(gen2, pwd)
        if r is None:
            sys.exit("no card")
        print("magic:", ", ".join(sorted(r[0])) or "none", "" if gen2 else "(gen2 not tested)")
        if r[1]:
            print(f"gen4 config ({len(r[1])} bytes): {r[1].hex()}")
        if r[2]:
            print(f"uscuid config: {r[2].hex()}")
    elif what == "g4read":
        blk = int(args[0])
        n = int(args[1]) if len(args) > 1 and len(args[1]) != 8 else 1
        pwd = bytes.fromhex(args[-1]) if len(args) > 1 and len(args[-1]) == 8 else GEN4_PWD
        r = nfc.gen4_read(blk, n, pwd)
        if r is None:
            sys.exit("no card")
        for i, d in enumerate(r):
            print(f"{blk + i:3}: {d.hex(' ') if d else 'read failed'}")
    elif what == "g4write":
        blk, data = int(args[0]), bytes.fromhex(args[1])
        ok = nfc.gen4_write(blk, data, bytes.fromhex(args[2]) if len(args) > 2 else GEN4_PWD)
        print("VERIFIED" if ok else f"write failed: {nfc.why}")
    elif what == "clone":
        raw = open(args[0], "rb").read()
        if len(raw) % 16:
            sys.exit("dump size is not whole blocks")
        ok = nfc.mf_clone([raw[i:i + 16] for i in range(0, len(raw), 16)], "force" in args[1:])
        print("CLONED (every block read back)" if ok else f"clone failed: {nfc.why}")
    elif what == "mfudump":
        out = args[args.index("-o") + 1] if "-o" in args else None
        pwd = next((bytes.fromhex(a) for a in args if len(a) == 8 and a != out), None)
        r = nfc.mfu_dump(pwd)
        if r is None:
            sys.exit(f"no Ultralight / NTAG: {nfc.why}")
        hdr, pwd_ok, pages, name = r
        print(name, f"(password {'ok' if pwd_ok else 'refused'})" if pwd else "")
        print("version  ", hdr[:8].hex(), "\nsignature", hdr[12:44].hex())
        ev1 = "EV1" in name
        for i in range(3) if ev1 else [2] if name in ("NTAG213", "NTAG215", "NTAG216") else []:
            c = hdr[44 + 4 * i:48 + 4 * i]
            print(f"counter {i}: {int.from_bytes(c[:3], 'little')}" + (f"  tearing {c[3]:02X}" if ev1 else ""))
        for i, d in enumerate(pages):
            print(f"{i:3} {i:02X}: {d.hex(' ') if d else '-- -- -- --'}")
        if out:
            open(out, "wb").write(hdr + b"".join(d or bytes(4) for d in pages))
    elif what == "mfuclone":
        ok = nfc.mfu_clone(open(args[0], "rb").read())
        print("CLONED (read back as a reader would)" if ok else f"clone failed: {nfc.why}")
    elif what == "apdu":
        act = "-a" in args
        cmds = [bytes.fromhex(a) for a in args if a != "-a"]
        if act:
            r = nfc.isodep(activate=True)
            if r is None:
                sys.exit(f"activate failed: {nfc.why}")
            print(f"ATS {r.hex().upper()}")
        for c in cmds:
            r = nfc.isodep(c)
            print(f">>> {c.hex().upper()}")
            print(f"<<< {r.hex().upper()} ({len(r)} bytes)" if r is not None else f"<<< failed: {nfc.why}")
    elif what == "df":
        if "-a" in args:
            r = nfc.isodep(activate=True)
            if r is None:
                sys.exit(f"activate failed: {nfc.why}")
            print(f"ATS {r.hex().upper()}")
        for step in (a for a in args if a != "-a"):
            f = step.split(":")
            if f[0] == "auth":
                r = nfc.df(0, bytes([int(f[1], 0)]) + df_key(f[2], f[3]))
            elif f[0] == "cmd":
                c = bytes.fromhex(f[3])
                r = nfc.df(1, bytes([DF_COMM[f[1]], int(f[2], 0)]) + c)
            elif f[0] == "ck":
                picc = "picc" in f
                ver = next((int(x[1:], 0) for x in f if x.startswith("v")), 0)
                rest = [x for x in f[4:] if x != "picc" and not x.startswith("v")]
                a = bytes([int(f[1], 0), picc, ver]) + df_key(f[2], f[3])
                if rest:
                    a += df_key(rest[0], rest[1])
                r = nfc.df(2, a)
            elif f[0] in ("info", "infokeys"):
                r = nfc.df(3, bytes([f[0] == "infokeys"]), timeout=300)
                print(r.decode(errors="replace") if r is not None else f"info failed: {nfc.why}")
                continue
            else:
                sys.exit(f"unknown step {step}")
            if r is None:
                print(f"{step}: failed: {nfc.why}")
            else:
                print(f"{step}: status {r[0]:02X}" + (f" {r[1:].hex().upper()}" if len(r) > 1 else ""))
    elif what == "mfuwrite":
        ok = nfc.mfu_write(int(args[0], 0), bytes.fromhex(args[1]))
        print("VERIFIED" if ok else f"write failed: {nfc.why}")
    elif what == "uscconfig":
        if args:
            ok = nfc.usc_config(bytes.fromhex(args[0]))
            print("VERIFIED" if ok else f"config write failed: {nfc.why}")
        c = nfc.usc_config()
        if c is None:
            sys.exit(f"no config: {nfc.why}")
        on = lambda b: "on" if b == 0x5A else "off" if b == 0 else f"{b:02X}"
        print(f"uscuid config: {c.hex()}")
        print(f"  wakeup {c[0:2].hex()} style {'20/23' if c[2] == 0x85 else '40/43'}  block key B {on(c[6])}"
              f"  CUID {on(c[7])}  perso {c[9]:02X}  shadow {on(c[10])}  magic auth {on(c[11])}")
        print(f"  static enc nonce {on(c[12])}  signature {on(c[13])}  SAK {c[15]:02X}")
    elif what == "g4config":
        cfg = next((bytes.fromhex(a) for a in args if len(a) == 60), None)
        pwd = next((bytes.fromhex(a) for a in args if len(a) == 8), GEN4_PWD)
        if cfg is not None:
            print("VERIFIED" if nfc.gen4_config(cfg, pwd) else f"config write failed: {nfc.why}")
        c = nfc.gen4_config(None, pwd)
        if c is None:
            sys.exit(f"no config: {nfc.why}")
        print(f"config ({len(c)} bytes): {c.hex()}")
        if len(c) >= 27:
            print(f"  protocol {c[0]:02X}  UID length {c[1]:02X}  password {c[2:6].hex()}  shadow {c[6]:02X}")
            print(f"  ATS {c[8:8 + c[7]].hex() if c[7] else '(off)'}  ATQA {c[25]:02X}{c[24]:02X}  SAK {c[26]:02X}")
            print(f"  rest {c[27:].hex()}")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
