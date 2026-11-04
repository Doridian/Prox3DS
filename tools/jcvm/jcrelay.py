#!/usr/bin/env python3
"""Java Card applets on the 3DS: the 3DS listens as an ISO-DEP card (nfcnet OP_RELAY), this PC runs the
CAP files in the Python JCVM and answers each APDU. Prototype of Prox3DS's Java Card emulation (#19).

usage: jcrelay.py HOST CAP [CAP...] [-u UID] [-v]   relay until Ctrl-C (UID: 4 / 7 / 10 bytes hex;
                                                    default a random one per run, ATQA 0004 SAK 20)
       jcrelay.py - CAP [CAP...] APDU...            no 3DS: send the APDUs (hex) to the VM, print answers
Every applet of every CAP is installed with its default AID, in order; the first SELECTable one wins."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import card  # noqa: E402


def build(caps, trace):
    c = card.Card(trace)
    for path in caps:
        pkg = c.load(path)
        for aid, _ in pkg.cap.applets:
            c.install(pkg, aid)
            print("installed %s from %s" % (aid.hex().upper(), os.path.basename(path)))
    return c


def main():
    args = sys.argv[1:]
    verbose = "-v" in args
    if verbose:
        args.remove("-v")
    uid = None
    if "-u" in args:
        i = args.index("-u")
        uid = bytes.fromhex(args[i + 1])
        del args[i:i + 2]
    if len(args) < 2:
        sys.exit(__doc__)
    host = args.pop(0)
    caps = [a for a in args if a.lower().endswith(".cap")]
    apdus = [a for a in args if not a.lower().endswith(".cap")]
    c = build(caps, verbose)

    def answer(apdu):
        if apdu is None:
            c.reset()
            print("-- session")
            return None
        t0, s0 = time.time(), c.vm.steps
        try:
            r = c.process(apdu)
        except Exception as e:  # a VM bug: the reader gets 6F00, we get the traceback
            import traceback
            traceback.print_exc()
            r = b"\x6F\x00"
        print("> %s\n< %s  (%d bytecodes, %.0f ms)" % (apdu.hex().upper(), r.hex().upper(), c.vm.steps - s0,
                                                       1000 * (time.time() - t0)))
        return r

    if host == "-":
        for a in apdus:
            answer(bytes.fromhex(a))
        return
    from nfcnet import Nfc
    ident = b""
    if uid:
        if len(uid) not in (4, 7, 10):
            sys.exit("UID: 4, 7 or 10 bytes")
        ident = bytes([len(uid)]) + uid + b"\x04\x00" + b"\x20"
    print("listening (Ctrl-C stops)")
    fields, sessions, n = Nfc(host).relay(answer, ident)
    print("stopped: %d fields, %d sessions, %d APDUs" % (fields, sessions, n))


if __name__ == "__main__":
    main()
