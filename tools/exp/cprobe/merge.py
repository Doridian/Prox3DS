"""Merges run.py outputs into one answer file in cases.txt order (answers matched by APDU) and lists the
cases still without one in todo.txt.  python3 merge.py j3h145.txt [more.out ...]"""
import sys

got = {}
for f in sys.argv[1:]:
    for line in open(f):
        label, a, _, r = line.split()
        got[a] = r
lines = [line.split() for line in open("cases.txt")]
todo = [lines[0]]
with open(sys.argv[1], "w") as out:
    for label, a in lines[1:]:
        if a in got:
            out.write(f"{label} {a} < {got[a]}\n")
        else:
            todo.append((label, a))
open("todo.txt", "w").write("".join(f"{label} {a}\n" for label, a in todo))
print(len(todo) - 1, "to run")
