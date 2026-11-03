"""Java Card export files (.exp, JCVM spec chapter 5): the tokens of an API package's classes, methods
and fields, which CAP files link against. The SDK's files are in ~/Applications/javacard/sdks/<kit>/
api_export_files."""

import os
import struct

EXP_DIR = os.path.expanduser("~/Applications/javacard/sdks/jc304_kit/api_export_files")

ACC_STATIC = 0x0008
ACC_INTERFACE = 0x0200


class Reader:
    def __init__(self, data):
        self.d, self.o = data, 0

    def u1(self):
        self.o += 1
        return self.d[self.o - 1]

    def u2(self):
        self.o += 2
        return struct.unpack_from(">H", self.d, self.o - 2)[0]

    def u4(self):
        self.o += 4
        return struct.unpack_from(">I", self.d, self.o - 4)[0]

    def bytes(self, n):
        self.o += n
        return self.d[self.o - n:self.o]


class ExpClass:
    def __init__(self, token, flags, name, supers, interfaces):
        self.token, self.flags, self.name = token, flags, name
        self.supers, self.interfaces = supers, interfaces  # names, java/lang/Object first
        self.fields = {}         # name -> (token, flags, descriptor, constant or None)
        self.methods = {}        # (name, descriptor) -> (token, flags)

    @property
    def interface(self):
        return bool(self.flags & ACC_INTERFACE)


class ExpPackage:
    def __init__(self, data):
        r = Reader(data)
        if r.u4() != 0x00FACADE:
            raise ValueError("not an export file")
        self.minor, self.major = r.u1(), r.u1()
        cp = []
        for _ in range(r.u2()):
            tag = r.u1()
            if tag == 1:  # Utf8
                cp.append(r.bytes(r.u2()).decode())
            elif tag == 3:  # Integer
                cp.append(struct.unpack(">i", r.bytes(4))[0])
            elif tag == 7:  # Classref: name index
                cp.append(("class", r.u2()))
            elif tag == 13:  # Package
                flags, name, minor, major = r.u1(), r.u2(), r.u1(), r.u1()
                cp.append(("package", name, minor, major, r.bytes(r.u1())))
            else:
                raise ValueError("export cp tag %d" % tag)

        def cls(i):
            return cp[cp[i][1]]

        pkg = cp[r.u2()]
        self.name, self.version, self.aid = cp[pkg[1]], (pkg[3], pkg[2]), bytes(pkg[4])
        if (self.major, self.minor) >= (2, 3):  # referenced packages (not needed)
            for _ in range(r.u1()):
                r.u2()
        self.classes = {}  # simple name -> ExpClass
        for _ in range(r.u1()):
            token, flags, name = r.u1(), r.u2(), cls(r.u2())
            supers = [cls(r.u2()) for _ in range(r.u2())]
            ifaces = [cls(r.u2()) for _ in range(r.u1())]
            c = ExpClass(token, flags, name, supers, ifaces)
            for _ in range(r.u2()):
                ftoken, fflags, fname, fdesc = r.u1(), r.u2(), cp[r.u2()], cp[r.u2()]
                const = None
                for _ in range(r.u2()):
                    r.u2()  # attribute name: ConstantValue
                    r.u4()
                    const = cp[r.u2()]
                c.fields[fname] = (ftoken, fflags, fdesc, const)
            for _ in range(r.u2()):
                mtoken, mflags, mname, mdesc = r.u1(), r.u2(), cp[r.u2()], cp[r.u2()]
                c.methods[(mname, mdesc)] = (mtoken, mflags)
            self.classes[name.rsplit("/", 1)[-1]] = c
        self.by_token = {c.token: c for c in self.classes.values()}


def load_all(root=EXP_DIR):
    """Every export file under root, by package AID."""
    pkgs = {}
    for d, _, files in os.walk(root):
        for f in files:
            if f.endswith(".exp"):
                with open(os.path.join(d, f), "rb") as fh:
                    p = ExpPackage(fh.read())
                pkgs[p.aid] = p
    return pkgs


if __name__ == "__main__":
    import sys
    for aid, p in sorted(load_all().items(), key=lambda kv: kv[1].name):
        if len(sys.argv) > 1 and sys.argv[1] not in p.name:
            continue
        print("%s %s v%d.%d" % (p.name, aid.hex().upper(), *p.version))
        for c in sorted(p.classes.values(), key=lambda c: c.token):
            print("  %2d %s%s  < %s" % (c.token, "interface " if c.interface else "", c.name, ", ".join(c.supers)))
            for (n, d), (t, f) in sorted(c.methods.items(), key=lambda kv: (kv[1][1] & ACC_STATIC, kv[1][0])):
                print("      %s%2d %s%s" % ("static " if f & ACC_STATIC else "", t, n, d))
            for n, (t, f, d, k) in sorted(c.fields.items(), key=lambda kv: kv[1][0]):
                if k is None:
                    print("      field %2d %s %s" % (t, n, d))
