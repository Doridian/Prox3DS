#!/usr/bin/env python3
"""Stock NCI listen mode (card emulation through the ROM): set LA_* params, map ISO-DEP listen ->
ISO-DEP interface, RF_DISCOVER listen-A, then print every packet for SECONDS while a reader
(pm3 hf 14a reader / apdu) talks to the 3DS. DATA packets get an echo + 9000 answer.

    stock.py HOST [SECONDS] [MAP]
"""
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 3)[0])
import chipmon
import nfcnet


def cfg_cmds():
    """Env CFG: extra CORE_SET_CONFIG TLVs (hex, comma-separated, one SET_CONFIG each)."""
    for tlv in filter(None, __import__("os").environ.get("CFG", "").split(",")):
        yield f"2002{len(tlv) // 2 + 1:02X}01{tlv}"


def main():
    host = sys.argv[1]
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 30
    mapping = sys.argv[3] if len(sys.argv) > 3 else "040202"  # ISO-DEP, listen, ISO-DEP intf
    nfc = nfcnet.Nfc(host)
    mon = chipmon.Mon(nfc)
    patch = sys.argv[4] if len(sys.argv) > 4 else "reader"
    if patch == "reader":
        mon.load()
    else:
        nfc.takeover()
        nfc.power(True)
        nfc.drain()
        if patch != "none":  # path to an .ncd (e.g. extracted/patch_20791B5.ncd)
            nfc.spd_download(open(patch, "rb").read())
        for c in (nfcnet.CORE_RESET, nfcnet.CORE_INIT):
            for p in nfc.cmd(c):
                print("  " + nfcnet.describe(p))
    nmap = len(mapping) // 6
    cmds = [
        # CORE_SET_CONFIG: LA_BIT_FRAME_SDD 04, LA_PLATFORM_CONFIG 00, LA_SEL_INFO 20,
        # LA_NFCID1 = 4 bytes
        "20021004" "300104" "310100" "320120" "330401020304",
        f"2100{len(mapping)//2 + 1:02X}{nmap:02X}{mapping}",
        "200204018001" "01",  # RF_FIELD_INFO on
        *([f"20020501" "0002" + EXTRA] if (EXTRA := __import__("os").environ.get("TOTAL", "")) else []),
        # LISTEN_MODE_ROUTING: tech A -> DH (power on), proto ISO-DEP -> DH
        *cfg_cmds(),
        "21010C" "0002" "000300" "0100" "010300" "0104",
        "2103030180" "01",
    ]
    if patch == "reader" and __import__("os").environ.get("FLOG", "1") == "1":
        mon.write(0x380A0, b"\1\1")  # FRAME_LOG TX + RX (env FLOG=0: off)
    for c in cmds:
        for p in nfc.cmd(bytes.fromhex("10" + c)):
            print("  " + nfcnet.describe(p))
    pokes = [(int(a, 16), int(v, 16)) for a, v in
             (x.split("=") for x in __import__("os").environ.get("POKE", "").split())]
    for a, v in pokes:  # env POKE: addr=val 32-bit register writes after the listen setup (reader image)
        mon.write32(a, [v])
    end = time.time() + secs
    while time.time() < end:
        for p in nfc.drain(100):
            print(f"{time.time() % 100:6.2f} " + nfcnet.describe(p))
            if p[0] == 0x10 and p[1] >> 5 == 0 and len(p) > 4:  # DATA: answer echo + 9000
                ans = p[4:] + b"\x90\x00"
                nfc.write(bytes([0x10, 0x00, 0x00, len(ans)]) + ans)
            if p[:3] == b"\x10\x61\x06" and p[4] == 0:  # deactivated to idle: listen again
                nfc.write(bytes.fromhex("10" "2103030180" "01"))
    for a, v in pokes:
        print(f"  poke {a:05X}={v:X} now {mon.read32(a, 1)[0]:X}")
    for p in nfc.cmd(bytes.fromhex("1021060100")):
        print("  " + nfcnet.describe(p))


if __name__ == "__main__":
    main()
