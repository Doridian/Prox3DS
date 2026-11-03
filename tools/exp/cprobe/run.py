"""Runs cases.txt (gen.py) on the card in the pm3 field, inside the pm3 client:
    proxmark3 /dev/ttyACM1 -y run.py -- cases.txt out.txt [label-filter]
Writes `label apdu < answer` lines. A lost card is reselected (field off, SELECT again)."""
import re
import sys

import pm3

p = pm3.pm3()
src, dst = sys.argv[1], sys.argv[2]
filt = sys.argv[3] if len(sys.argv) > 3 else ""
lines = [l.split() for l in open(src) if l.strip()]
sel = lines[0][1]
first = True


def send(a):
    global first
    p.console(f"hf 14a apdu -{'s' if first else ''}k -d {a}")
    first = False
    m = re.search(r"<<< ([0-9A-Fa-f]+)", p.grabbed_output)
    return m.group(1).upper() if m else None


with open(dst, "w") as out:
    send(sel)
    for label, a in lines[1:]:
        if filt not in label:
            continue
        r = send(a)
        if r is None:
            p.console("hf 14a reader -x")
            first = True
            ok = send(sel)
            r = "NONE (reselect " + str(ok) + ")"
        out.write(f"{label} {a} < {r}\n")
        out.flush()
        print(label, "<", r[:80])
p.console("hf 14a reader -x")
