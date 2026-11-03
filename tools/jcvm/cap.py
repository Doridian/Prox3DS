"""CAP files (JCVM spec chapter 6): the components of a converted Java Card package, parsed into what
the interpreter needs. Offsets into the Class and Method components are kept as the CAP has them,
since class and method references use them."""

import struct
import zipfile

from exp import Reader

# constant pool tags
CP_CLASS, CP_IFIELD, CP_VMETHOD, CP_SUPERMETHOD, CP_SFIELD, CP_SMETHOD = 1, 2, 3, 4, 5, 6

ACC_INTERFACE, ACC_SHAREABLE, ACC_REMOTE = 0x8, 0x4, 0x2
ACC_EXTENDED, ACC_ABSTRACT = 0x8, 0x4

# array_init / newarray element types
T_BOOLEAN, T_BYTE, T_SHORT, T_INT = 10, 11, 12, 13
INIT_TYPES = {2: T_BOOLEAN, 3: T_BYTE, 4: T_SHORT, 5: T_INT}


class ClassRef:
    """A class_ref: internal (offset into the Class component) or external (package token, class token)."""
    __slots__ = ("pkg", "cls", "offset")

    def __init__(self, v):
        if v & 0x8000:
            self.pkg, self.cls, self.offset = (v >> 8) & 0x7F, v & 0xFF, None
        else:
            self.pkg, self.cls, self.offset = None, None, v

    @property
    def external(self):
        return self.offset is None

    def __repr__(self):
        return "ext(%d,%d)" % (self.pkg, self.cls) if self.external else "cls@%d" % self.offset


def class_ref(r):
    v = r.u2()
    return None if v == 0xFFFF else ClassRef(v)


class CapClass:
    def __init__(self, offset, r):
        self.offset = offset
        b = r.u1()
        self.flags, nifaces = b >> 4, b & 0xF
        self.interface = bool(self.flags & ACC_INTERFACE)
        if self.interface:
            self.supers = [class_ref(r) for _ in range(nifaces)]
            if self.flags & ACC_REMOTE:
                r.bytes(r.u1())
            return
        self.super = class_ref(r)
        self.instance_size, self.first_ref, self.ref_count = r.u1(), r.u1(), r.u1()
        self.public_base, public_count, self.package_base, package_count = r.u1(), r.u1(), r.u1(), r.u1()
        self.public_vmt = [r.u2() for _ in range(public_count)]    # method offsets, 0xFFFF = not here
        self.package_vmt = [r.u2() for _ in range(package_count)]
        self.ifaces = []  # (interface ClassRef, [vmt token per interface method token])
        for _ in range(nifaces):
            iface = class_ref(r)
            self.ifaces.append((iface, list(r.bytes(r.u1()))))
        if self.flags & ACC_REMOTE:
            raise NotImplementedError("remote classes")


class Handler:
    def __init__(self, r):
        self.start = r.u2()
        b = r.u2()
        self.last, self.end = bool(b & 0x8000), self.start + (b & 0x7FFF)
        self.handler, self.catch = r.u2(), r.u2()  # catch: cp index of the class, 0 = any (finally)


class Method:
    """A method_info at offset in the Method component; code is the whole component, pc absolute."""

    def __init__(self, cap, offset):
        d = cap.method_data
        self.cap, self.offset = cap, offset
        b = d[offset]
        if b >> 4 & ACC_EXTENDED:
            self.flags, self.max_stack, self.nargs, self.max_locals = b >> 4, d[offset + 1], d[offset + 2], d[offset + 3]
            self.code = offset + 4
        else:
            self.flags, self.max_stack = b >> 4, b & 0xF
            self.nargs, self.max_locals = d[offset + 1] >> 4, d[offset + 1] & 0xF
            self.code = offset + 2

    def __repr__(self):
        return "method@%d" % self.offset


class Cap:
    def __init__(self, path):
        with zipfile.ZipFile(path) as z:
            comps = {}
            for n in z.namelist():
                if n.endswith(".cap"):
                    data = z.read(n)
                    comps[data[0]] = data[3:3 + struct.unpack_from(">H", data, 1)[0]]
        self._header(Reader(comps[1]))
        self.applets = []  # (AID, install method offset)
        if 3 in comps:
            r = Reader(comps[3])
            for _ in range(r.u1()):
                aid = bytes(r.bytes(r.u1()))
                self.applets.append((aid, r.u2()))
        r = Reader(comps[4])
        self.imports = []  # (AID, (major, minor)) by package token
        for _ in range(r.u1()):
            minor, major = r.u1(), r.u1()
            self.imports.append((bytes(r.bytes(r.u1())), (major, minor)))
        self._cp(Reader(comps[5]))
        self._classes(comps[6])
        self.method_data = comps[7]
        r = Reader(comps[7])
        self.handlers = [Handler(r) for _ in range(r.u1())]
        self._statics(Reader(comps[8]))
        self.methods = {}

    def _header(self, r):
        if r.u4() != 0xDECAFFED:
            raise ValueError("not a CAP file")
        self.minor, self.major, self.flags = r.u1(), r.u1(), r.u1()
        pminor, pmajor = r.u1(), r.u1()
        self.version, self.aid = (pmajor, pminor), bytes(r.bytes(r.u1()))
        self.name = r.bytes(r.u1()).decode() if (self.major, self.minor) >= (2, 2) and r.o < len(r.d) else None

    def _cp(self, r):
        self.cp = [None]
        n = r.u2()
        for _ in range(n):
            tag = r.u1()
            if tag == CP_CLASS:
                e = (tag, ClassRef(r.u2()))
                r.u1()
            elif tag in (CP_IFIELD, CP_VMETHOD, CP_SUPERMETHOD):
                e = (tag, ClassRef(r.u2()), r.u1())
            else:  # static field / method: internal offset or (package, class, token)
                b = r.u1()
                if b & 0x80:
                    e = (tag, ClassRef(0x8000 | (b & 0x7F) << 8 | r.u1()), r.u1())
                else:
                    e = (tag, None, r.u2())
            self.cp.append(e)
        self.cp.pop(0)

    def _classes(self, data):
        r = Reader(data)
        if (self.major, self.minor) >= (2, 2):  # signature pool (remote methods only)
            r.bytes(r.u2())
        self.classes = {}  # offset -> CapClass
        while r.o < len(data):
            c = CapClass(r.o, r)
            self.classes[c.offset] = c

    def _statics(self, r):
        """The static field image: references (arrays from array_init, else null), then primitives."""
        size, nrefs = r.u2(), r.u2()
        self.static_arrays = []  # (element type, values) for the first references
        for _ in range(r.u2()):
            t, n = INIT_TYPES[r.u1()], r.u2()
            raw = bytes(r.bytes(n))
            if t in (T_BYTE, T_BOOLEAN):
                vals = [v - 256 if v > 127 else v for v in raw]
            elif t == T_SHORT:
                vals = list(struct.unpack(">%dh" % (n // 2), raw))
            else:
                vals = list(struct.unpack(">%di" % (n // 4), raw))
            self.static_arrays.append((t, vals))
        self.static_refs = nrefs
        defaults = r.u2()
        nondefault = bytes(r.bytes(r.u2()))
        self.static_prims = bytearray(size - 2 * nrefs)  # bytes after the references, big-endian
        self.static_prims[defaults:defaults + len(nondefault)] = nondefault

    def method(self, offset):
        m = self.methods.get(offset)
        if not m:
            m = self.methods[offset] = Method(self, offset)
        return m


if __name__ == "__main__":
    import sys
    c = Cap(sys.argv[1])
    print("package %s v%d.%d, CAP %d.%d" % (c.aid.hex().upper(), *c.version, c.major, c.minor))
    for aid, off in c.applets:
        print("applet %s install @%d" % (aid.hex().upper(), off))
    for i, (aid, v) in enumerate(c.imports):
        print("import %d: %s v%d.%d" % (i, aid.hex().upper(), *v))
    for i, e in enumerate(c.cp):
        print("cp %2d: %r" % (i, e))
    for off, k in c.classes.items():
        print("class @%d: %s" % (off, vars(k)))
