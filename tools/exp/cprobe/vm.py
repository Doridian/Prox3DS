"""Runs cases.txt through the C VM on the host (tools/exp/jcvm/jch with javacard/dspm-cprobe.cap) and
writes the answers as run.py does (e.g. vm.txt), then compares them with the card's:
    python3 vm.py [vm.txt] [j3h145.txt]
    python3 vm.py --cmp 3ds.txt [j3h145.txt]   only the comparison (answers from run.py: the 3DS's)
SAME = the card's answer, RANDOM = both 9000 for a case with random output (check.py checks those),
NEW = no card answer to compare with yet, DIFF = not the same."""
import os
import subprocess
import sys

D = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(D, "..", "..", "..")
args = sys.argv[1:]
run = not (args and args[0] == "--cmp")
if not run:
    args = args[1:]
out = args[0] if args else os.path.join(D, "vm.txt")
card = args[1] if len(args) > 1 else os.path.join(D, "j3h145.txt")
lines = [line.split() for line in open(os.path.join(D, "cases.txt"))]
cmds = "\n".join(a for _, a in lines) + "\n"
why = {}
if run:
    p = subprocess.run([os.path.join(ROOT, "tools/exp/jcvm/jch"), os.path.join(ROOT, "javacard/dspm-cprobe.cap")],
                       input=cmds, capture_output=True, text=True, timeout=600)
    ans = [ln for ln in p.stdout.splitlines() if ln.startswith("< ")]
    if len(ans) != len(lines):
        sys.exit(f"{len(ans)} answers for {len(lines)} commands:\n{p.stdout[-2000:]}{p.stderr[-2000:]}")
    with open(out, "w") as f:
        for (label, a), r in zip(lines[1:], ans[1:]):
            f.write(f"{label} {a} < {r.split()[1]}\n")
            if "why:" in r:
                why[label] = r.split("why:", 1)[1].strip()
cardAns = {}
for ln in open(card):
    label, a, _, r = ln.split()
    cardAns[label] = r
RANDOM = ("random", "PSS_1024_crt_sign", "PSS_2048_crt_sign")
counts = {}
for ln in open(out):
    label, a, _, r = ln.split()
    c = cardAns.get(label)
    if r == c:
        st = "SAME"
    elif c and c.endswith("9000") and r.endswith("9000") and any(x in label for x in RANDOM):
        st = "RANDOM"
    elif c is None:
        st = "NEW"  # no card answer yet
    else:
        st = "DIFF"
    counts[st] = counts.get(st, 0) + 1
    if st in ("DIFF", "NEW"):
        print(f"{st} {label}\n     vm   {r[:100]}{'  why: ' + why[label] if label in why else ''}\n     card {c[:100] if c else None}")
print(counts)
