"""The Java Card virtual machine (JCVM spec chapter 7): classes from CAP files and from the native API
(api.py, linked by export file tokens), objects, arrays and the bytecode interpreter.

Stack and locals hold 16-bit cells as Python ints (signed) and references as objects (None = null);
an int takes two cells, high word first, as on a card, so dup2 / swap_x / pop2 work on words."""

import struct

import cap as capmod
from cap import CP_SUPERMETHOD, T_BOOLEAN, T_BYTE, T_SHORT, T_INT
import exp

T_REF = 14  # checkcast / instanceof array type: reference array


def s8(v):
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def int_cells(v):
    v &= 0xFFFFFFFF
    return [s16(v >> 16), s16(v)]


def cells_int(hi, lo):
    return s32((hi & 0xFFFF) << 16 | (lo & 0xFFFF))


def parse_desc(desc):
    """'(S[BLjavacard/framework/AID;I)Z' -> (['S', '[B', 'Ljavacard/framework/AID;', 'I'], 'Z')"""
    params, i = [], 1
    while desc[i] != ")":
        j = i
        while desc[j] == "[":
            j += 1
        if desc[j] == "L":
            j = desc.index(";", j)
        params.append(desc[i:j + 1])
        i = j + 1
    return params, desc[i + 1:]


class JavaThrow(Exception):
    """A Java exception on its way up the frames."""

    def __init__(self, obj):
        super().__init__(obj)
        self.obj = obj


class Native:
    """An API method in Python: fn(vm, [this,] *args) with ints as Python ints, booleans as 0/1."""
    __slots__ = ("fn", "params", "ret", "this", "nargs", "name")

    def __init__(self, fn, desc, this, name):
        self.fn, self.this, self.name = fn, this, name
        self.params, self.ret = parse_desc(desc)
        self.nargs = this + sum(2 if p == "I" else 1 for p in self.params)  # in cells


class VClass:
    """A class or interface, from a CAP (cc set) or native (natives by token)."""

    def __init__(self, name, interface=False):
        self.name, self.interface = name, interface
        self.super = None
        self.interfaces = []                  # VClass, directly implemented / extended
        self.cap = self.cc = self.pkg = self.exp = None
        self.vnatives, self.snatives = {}, {}  # token -> Native

    def subclass_of(self, other):
        c = self
        while c:
            if c is other or any(i.subclass_of(other) for i in c.interfaces):
                return True
            c = c.super
        return False

    def native_base(self):
        c = self
        while c.cc:
            c = c.super
        return c

    def __repr__(self):
        return self.name


class JObject:
    def __init__(self, cls):
        self.cls = cls
        self.fields = {}  # (declaring VClass, token) -> cell / reference

    def __repr__(self):
        return "<%s>" % self.cls.name


class JArray:
    __slots__ = ("type", "data", "elem", "transient")

    def __init__(self, t, n, elem=None, transient=0):
        self.type, self.elem, self.transient = t, elem, transient  # transient: JCSystem.CLEAR_ON_* or 0
        if t in (T_BYTE, T_BOOLEAN):
            self.data = bytearray(n)  # unsigned here, signed on the stack
        else:
            self.data = [None if t == T_REF else 0] * n

    def get(self, i):
        v = self.data[i]
        return s8(v) if self.type in (T_BYTE, T_BOOLEAN) else v

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        if self.type in (T_BYTE, T_BOOLEAN):
            return "byte[%d]%s" % (len(self.data), bytes(self.data[:16]).hex())
        return "%s[%d]" % ({T_SHORT: "short", T_INT: "int", T_REF: "ref"}[self.type], len(self.data))


class Frame:
    __slots__ = ("m", "pc", "ret", "locals", "stack", "pkg")

    def __init__(self, m, args, pkg):
        self.m, self.pc, self.ret, self.pkg = m, m.code, None, pkg
        self.locals = list(args) + [0] * m.max_locals
        self.stack = []


class Package:
    """A loaded CAP: its classes, imports and static field image."""

    def __init__(self, c):
        self.cap = c
        self.classes = {}      # Class component offset -> VClass
        self.imports = []      # package token -> Package / NativePackage
        self.static_refs = []  # reference statics (first 2 * n bytes of the image)
        self.static_prims = bytearray(c.static_prims)


class NativePackage:
    def __init__(self, e):
        self.exp, self.aid, self.name = e, e.aid, e.name
        self.by_token = {}


class VM:
    def __init__(self, natives):
        """natives: {class name: {method name + descriptor: fn, "<new>": factory(vm, cls)}}, see api.py."""
        self.packages = {}       # AID -> Package / NativePackage
        self.journal = None      # undo entries while a transaction runs
        self.natives = natives
        self.native_classes = {}  # name -> VClass
        self.steps = 0
        for e in exp.load_all().values():
            np = NativePackage(e)
            self.packages[e.aid] = np
            for c in e.classes.values():
                vc = VClass(c.name, c.interface)
                vc.exp, vc.pkg = c, np
                np.by_token[c.token] = vc
                self.native_classes[c.name] = vc
        for vc in self.native_classes.values():
            supers = vc.exp.supers
            vc.super = self.native_classes[supers[-1]] if supers else None
            vc.interfaces = [self.native_classes[i] for i in vc.exp.interfaces]
            impl = natives.get(vc.name, {})
            for (name, desc), (tok, flags) in vc.exp.methods.items():
                static = bool(flags & exp.ACC_STATIC)
                sig = name + desc
                fn = impl.get(sig) or self._missing(vc.name, sig)
                n = Native(fn, desc, not static, vc.name + "." + sig)
                (vc.snatives if static or name == "<init>" else vc.vnatives)[tok] = n

    @staticmethod
    def _missing(cls, sig):
        def fn(*a):
            raise NotImplementedError("native %s.%s" % (cls, sig))
        return fn

    def cls(self, name):
        return self.native_classes[name]

    # --- loading ---

    def load(self, c):
        p = Package(c)
        for aid, version in c.imports:
            if aid not in self.packages:
                raise LookupError("import %s not available" % aid.hex().upper())
            p.imports.append(self.packages[aid])
        self.packages[c.aid] = p
        for off, cc in c.classes.items():
            vc = VClass("%s@%d" % (c.aid.hex().upper(), off), cc.interface)
            vc.cap, vc.cc, vc.pkg = c, cc, p
            p.classes[off] = vc
        for vc in p.classes.values():
            cc = vc.cc
            if cc.interface:
                vc.interfaces = [self.resolve_class(p, r) for r in cc.supers]
            else:
                vc.super = self.resolve_class(p, cc.super) if cc.super else self.cls("java/lang/Object")
                vc.interfaces = [self.resolve_class(p, r) for r, _ in cc.ifaces]
        for t, vals in c.static_arrays:
            a = JArray(t, len(vals))
            for i, v in enumerate(vals):
                a.data[i] = v & 0xFF if t in (T_BYTE, T_BOOLEAN) else v
            p.static_refs.append(a)
        p.static_refs += [None] * (c.static_refs - len(p.static_refs))
        return p

    def resolve_class(self, p, ref):
        if ref.external:
            return p.imports[ref.pkg].by_token[ref.cls]
        return p.classes[ref.offset]

    # --- method lookup ---

    def virtual(self, cls, token, pkg=None):
        """The method for a virtual token, from cls up: a cap Method or a Native. Token bit 7: a
        package-visible method, only found in classes of pkg."""
        c = cls
        while c:
            cc = c.cc
            if cc:
                if token & 0x80:
                    t = token & 0x7F
                    if c.pkg is pkg and cc.package_base <= t < cc.package_base + len(cc.package_vmt):
                        off = cc.package_vmt[t - cc.package_base]
                        if off != 0xFFFF:
                            return c.cap.method(off)
                elif cc.public_base <= token < cc.public_base + len(cc.public_vmt):
                    off = cc.public_vmt[token - cc.public_base]
                    if off != 0xFFFF:
                        return c.cap.method(off)
            elif token in c.vnatives:
                return c.vnatives[token]
            c = c.super
        raise LookupError("no virtual method %d in %s" % (token, cls))

    def interface_method(self, cls, iface, token):
        c = cls
        while c:
            if c.cc:
                for ref, table in c.cc.ifaces:
                    if self.resolve_class(c.pkg, ref) is iface:
                        return self.virtual(cls, table[token])
            elif c.subclass_of(iface):  # a native class implementing a native interface: by name
                for (n, d), (t, f) in iface.exp.methods.items():
                    if t == token:
                        k = c
                        while k:
                            if (n, d) in k.exp.methods:
                                return k.vnatives[k.exp.methods[(n, d)][0]]
                            k = k.super
            c = c.super
        raise LookupError("%s doesn't implement %s method %d" % (cls, iface, token))

    def static_method(self, pkg, e):
        tag, ref, tok = e
        if ref is None:
            return pkg.cap.method(tok)
        return self.resolve_class(pkg, ref).snatives[tok]

    # --- objects ---

    def new(self, cls):
        factory = self.natives.get(cls.native_base().name, {}).get("<new>")
        return factory(self, cls) if factory else JObject(cls)

    def throw(self, name, reason=0):
        """Raises a new instance of the native exception class name."""
        o = self.new(self.cls(name))
        o.reason = reason
        raise JavaThrow(o)

    def instance_of(self, o, t, cls):
        if isinstance(o, JArray):
            if t == 0:
                return cls.name == "java/lang/Object"
            if t == T_REF:
                return o.type == T_REF and (o.elem is None or cls is None or o.elem.subclass_of(cls))
            return o.type == t
        return t == 0 and o.cls.subclass_of(cls)

    # Transactions: writes to persistent objects are journaled and undone on abort.
    def store(self, container, key, value, transient=False):
        if self.journal is not None and not transient:
            self.journal.append((container, key, container[key]))
        container[key] = value

    def array_store(self, a, i, v):
        self.store(a.data, i, v, a.transient)

    def field_store(self, o, key, v):
        if self.journal is not None:
            self.journal.append((o.fields, key, o.fields.get(key)))
        o.fields[key] = v

    def abort_transaction(self):
        for container, key, old in reversed(self.journal):
            container[key] = old
        self.journal = None

    # --- interpreter ---

    def call(self, target, args):
        """Runs a method (cap Method or Native) with its argument cells; the return cells."""
        if isinstance(target, Native):
            return self.call_native(target, args)
        frames = [Frame(target, args, self.packages[target.cap.aid])]
        while True:
            try:
                return self._exec(frames)
            except JavaThrow as t:
                while frames:
                    h = self._handler(frames[-1], t.obj)
                    if h is not None:
                        frames[-1].stack[:] = [t.obj]
                        frames[-1].pc = h
                        break
                    frames.pop()
                else:
                    raise

    def call_native(self, n, cells):
        args, i = [], 0
        if n.this:
            args.append(cells[0])
            i = 1
        for p in n.params:
            if p == "I":
                args.append(cells_int(cells[i], cells[i + 1]))
                i += 2
            else:
                args.append(cells[i])
                i += 1
        r = n.fn(self, *args)
        ret = n.ret
        if ret == "V":
            return []
        if ret == "I":
            return int_cells(r)
        if ret in ("B", "Z"):
            return [s8(int(r))]
        if ret == "S":
            return [s16(r)]
        return [r]

    def _handler(self, f, obj):
        c = f.m.cap
        for h in c.handlers:
            if h.start <= f.pc < h.end:
                if not h.catch or obj.cls.subclass_of(self.resolve_class(f.pkg, c.cp[h.catch][1])):
                    return h.handler
        return None

    def _exec(self, frames):
        """Runs the top frame until the bottom one returns. A Java exception leaves each frame's pc at
        the instruction that raised it or the invoke it came through."""
        f = frames[-1]
        code, cp, pkg = f.m.cap.method_data, f.m.cap.cp, f.pkg
        st, loc = f.stack, f.locals
        pc = f.pc

        def popint():
            lo = st.pop()
            return cells_int(st.pop(), lo)

        def npe(o):
            if o is None:
                self.throw("java/lang/NullPointerException")
            return o

        def arr(a, i):
            npe(a)
            if not 0 <= i < len(a.data):
                self.throw("java/lang/ArrayIndexOutOfBoundsException")
            return a

        def u2(o):
            return code[o] << 8 | code[o + 1]

        def s2(o):
            return s16(code[o] << 8 | code[o + 1])

        while True:
            self.steps += 1
            f.pc = pc
            op = code[pc]
            ln = OPLEN.get(op, 1)
            if op == 0x00:  # nop
                pass
            elif op == 0x01:  # aconst_null
                st.append(None)
            elif 0x02 <= op <= 0x08:  # sconst_m1..5
                st.append(op - 3)
            elif 0x09 <= op <= 0x0F:  # iconst_m1..5
                st += int_cells(op - 10)
            elif op == 0x10:  # bspush
                st.append(s8(code[pc + 1]))
            elif op == 0x11:  # sspush
                st.append(s2(pc + 1))
            elif op == 0x12:  # bipush
                st += int_cells(s8(code[pc + 1]))
            elif op == 0x13:  # sipush
                st += int_cells(s2(pc + 1))
            elif op == 0x14:  # iipush
                st += int_cells(int.from_bytes(code[pc + 1:pc + 5], "big"))
            elif op in (0x15, 0x16):  # aload, sload
                st.append(loc[code[pc + 1]])
            elif op == 0x17:  # iload
                i = code[pc + 1]
                st += loc[i:i + 2]
            elif 0x18 <= op <= 0x1F:  # aload_n, sload_n
                st.append(loc[(op - 0x18) & 3])
            elif 0x20 <= op <= 0x23:  # iload_n
                i = op - 0x20
                st += loc[i:i + 2]
            elif 0x24 <= op <= 0x27:  # aaload baload saload iaload
                i = st.pop()
                a = arr(st.pop(), i)
                if op == 0x27:
                    st += int_cells(a.data[i])
                else:
                    st.append(a.get(i))
            elif op in (0x28, 0x29):  # astore, sstore
                loc[code[pc + 1]] = st.pop()
            elif op == 0x2A:  # istore
                i = code[pc + 1]
                loc[i + 1] = st.pop()
                loc[i] = st.pop()
            elif 0x2B <= op <= 0x32:  # astore_n, sstore_n
                loc[(op - 0x2B) & 3] = st.pop()
            elif 0x33 <= op <= 0x36:  # istore_n
                i = op - 0x33
                loc[i + 1] = st.pop()
                loc[i] = st.pop()
            elif 0x37 <= op <= 0x3A:  # aastore bastore sastore iastore
                v = popint() if op == 0x3A else st.pop()
                i = st.pop()
                a = arr(st.pop(), i)
                if op == 0x37:
                    if v is not None and a.elem is not None and not self.instance_of(v, 0, a.elem):
                        self.throw("java/lang/ArrayStoreException")
                    self.array_store(a, i, v)
                elif op == 0x38:
                    self.array_store(a, i, v & 0xFF if a.type == T_BYTE else v & 1)
                else:
                    self.array_store(a, i, s16(v) if op == 0x39 else v)
            elif op == 0x3B:  # pop
                st.pop()
            elif op == 0x3C:  # pop2
                del st[-2:]
            elif op == 0x3D:  # dup
                st.append(st[-1])
            elif op == 0x3E:  # dup2
                st += st[-2:]
            elif op == 0x3F:  # dup_x mn: the top m words copied, inserted n words down (0: on top)
                m, n = code[pc + 1] >> 4, code[pc + 1] & 0xF
                top = st[-m:]
                if n:
                    st[len(st) - n:len(st) - n] = top
                else:
                    st += top
            elif op == 0x40:  # swap_x mn: the top m words swapped with the n words below them
                m, n = code[pc + 1] >> 4, code[pc + 1] & 0xF
                st[-m - n:] = st[-m:] + st[-m - n:-m]
            elif op == 0x4B:  # sneg
                st.append(s16(-st.pop()))
            elif op == 0x4C:  # ineg
                st += int_cells(-popint())
            elif 0x41 <= op <= 0x58:  # s/i add sub mul div rem shl shr ushr and or xor
                isint = not op & 1
                b = popint() if isint else st.pop()
                a = popint() if isint else st.pop()
                k = ARITH[op]
                if k in ("div", "rem") and b == 0:
                    self.throw("java/lang/ArithmeticException")
                if k == "add":
                    r = a + b
                elif k == "sub":
                    r = a - b
                elif k == "mul":
                    r = a * b
                elif k == "div":
                    r = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
                elif k == "rem":
                    r = a - abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1) * b
                elif k == "shl":
                    r = a << (b & 0x1F)
                elif k == "shr":
                    r = a >> (b & 0x1F)
                elif k == "ushr":  # on the int (a short sign-extended first, as Java does)
                    r = (a & 0xFFFFFFFF) >> (b & 0x1F)
                elif k == "and":
                    r = a & b
                elif k == "or":
                    r = a | b
                else:
                    r = a ^ b
                if isint:
                    st += int_cells(r)
                else:
                    st.append(s16(r))
            elif op == 0x59:  # sinc
                i = code[pc + 1]
                loc[i] = s16(loc[i] + s8(code[pc + 2]))
            elif op == 0x5A:  # iinc
                i = code[pc + 1]
                loc[i:i + 2] = int_cells(cells_int(loc[i], loc[i + 1]) + s8(code[pc + 2]))
            elif op == 0x5B:  # s2b
                st.append(s8(st.pop()))
            elif op == 0x5C:  # s2i
                st += int_cells(st.pop())
            elif op == 0x5D:  # i2b
                st.append(s8(popint()))
            elif op == 0x5E:  # i2s
                st.append(s16(popint()))
            elif op == 0x5F:  # icmp
                b = popint()
                a = popint()
                st.append((a > b) - (a < b))
            elif 0x60 <= op <= 0x67 or 0x98 <= op <= 0x9F:  # if<cond> (_w)
                w = op >= 0x98
                v = st.pop()
                k = op - (0x98 if w else 0x60)
                cond = (v is None) == (k == 6) if k >= 6 else COND[k](v, 0)
                pc += (s2(pc + 1) if w else s8(code[pc + 1])) if cond else ln
                continue
            elif 0x68 <= op <= 0x6F or 0xA0 <= op <= 0xA7:  # if_acmp<cond>, if_scmp<cond> (_w)
                w = op >= 0xA0
                b = st.pop()
                a = st.pop()
                k = op - (0xA0 if w else 0x68)
                cond = (a is b) == (k == 0) if k < 2 else COND[k - 2](a, b)
                pc += (s2(pc + 1) if w else s8(code[pc + 1])) if cond else ln
                continue
            elif op == 0x70:  # goto
                pc += s8(code[pc + 1])
                continue
            elif op == 0xA8:  # goto_w
                pc += s2(pc + 1)
                continue
            elif op == 0x73:  # stableswitch default, low, high, offsets
                v = st.pop()
                lo, hi = s2(pc + 3), s2(pc + 5)
                pc += s2(pc + 7 + 2 * (v - lo)) if lo <= v <= hi else s2(pc + 1)
                continue
            elif op == 0x74:  # itableswitch
                v = popint()
                lo = s32(int.from_bytes(code[pc + 3:pc + 7], "big"))
                hi = s32(int.from_bytes(code[pc + 7:pc + 11], "big"))
                pc += s2(pc + 11 + 2 * (v - lo)) if lo <= v <= hi else s2(pc + 1)
                continue
            elif op == 0x75:  # slookupswitch default, npairs, (match, offset)...
                v = st.pop()
                o = s2(pc + 1)
                for k in range(u2(pc + 3)):
                    if s2(pc + 5 + 4 * k) == v:
                        o = s2(pc + 7 + 4 * k)
                        break
                pc += o
                continue
            elif op == 0x76:  # ilookupswitch
                v = popint()
                o = s2(pc + 1)
                for k in range(u2(pc + 3)):
                    e = pc + 5 + 6 * k
                    if s32(int.from_bytes(code[e:e + 4], "big")) == v:
                        o = s2(e + 4)
                        break
                pc += o
                continue
            elif 0x77 <= op <= 0x7A:  # areturn sreturn ireturn return
                ret = [] if op == 0x7A else st[-2:] if op == 0x79 else st[-1:]
                frames.pop()
                if not frames:
                    return ret
                f = frames[-1]
                code, cp, pkg = f.m.cap.method_data, f.m.cap.cp, f.pkg
                st, loc = f.stack, f.locals
                st += ret
                pc = f.ret
                continue
            elif 0x7B <= op <= 0x82:  # getstatic / putstatic _a _b _s _i
                k = (op - 0x7B) & 3
                _, ref, off = cp[u2(pc + 1)]
                if ref is not None:
                    raise NotImplementedError("external static field %r" % (cp[u2(pc + 1)],))
                if k == 0:
                    if op < 0x7F:
                        st.append(pkg.static_refs[off // 2])
                    else:
                        self.store(pkg.static_refs, off // 2, st.pop())
                else:
                    o, n = off - 2 * len(pkg.static_refs), (1, 2, 4)[k - 1]
                    b = pkg.static_prims
                    if op < 0x7F:
                        v = int.from_bytes(b[o:o + n], "big", signed=True)
                        if k == 3:
                            st += int_cells(v)
                        else:
                            st.append(v)
                    else:
                        v = popint() if k == 3 else st.pop()
                        for j, x in enumerate((v & ((1 << 8 * n) - 1)).to_bytes(n, "big")):
                            self.store(b, o + j, x)
            elif 0x83 <= op <= 0x86 or 0xA9 <= op <= 0xB0:  # getfield _a _b _s _i (_w, _this)
                if op <= 0x86:
                    k, idx, o = op - 0x83, code[pc + 1], None
                elif op <= 0xAC:
                    k, idx, o = op - 0xA9, u2(pc + 1), None
                else:
                    k, idx, o = op - 0xAD, code[pc + 1], loc[0]
                o = npe(st.pop() if op < 0xAD else o)
                _, ref, tok = cp[idx]
                v = o.fields.get((self.resolve_class(pkg, ref), tok), None if k == 0 else 0)
                if k == 3:
                    st += int_cells(v)
                else:
                    st.append(v)
            elif 0x87 <= op <= 0x8A or 0xB1 <= op <= 0xB8:  # putfield _a _b _s _i (_w, _this)
                if op <= 0x8A:
                    k, idx, this = op - 0x87, code[pc + 1], False
                elif op <= 0xB4:
                    k, idx, this = op - 0xB1, u2(pc + 1), False
                else:
                    k, idx, this = op - 0xB5, code[pc + 1], True
                v = popint() if k == 3 else st.pop()
                o = npe(loc[0] if this else st.pop())
                v = s8(v) if k == 1 else s16(v) if k == 2 else v
                _, ref, tok = cp[idx]
                self.field_store(o, (self.resolve_class(pkg, ref), tok), v)
            elif 0x8B <= op <= 0x8E:  # invokevirtual, invokespecial, invokestatic, invokeinterface
                if op == 0x8B:
                    _, ref, tok = cp[u2(pc + 1)]
                    nargs = self.virtual(self.resolve_class(pkg, ref), tok, pkg).nargs
                    o = npe(st[-nargs])
                    target = self.virtual(o.cls if isinstance(o, JObject) else self.cls("java/lang/Object"), tok, pkg)
                elif op == 0x8C:
                    e = cp[u2(pc + 1)]
                    if e[0] == CP_SUPERMETHOD:
                        target = self.virtual(self.resolve_class(pkg, e[1]).super, e[2], pkg)
                    else:
                        target = self.static_method(pkg, e)
                    nargs = target.nargs
                    npe(st[-nargs])
                elif op == 0x8D:
                    target = self.static_method(pkg, cp[u2(pc + 1)])
                    nargs = target.nargs
                else:
                    nargs, tok = code[pc + 1], code[pc + 4]
                    o = npe(st[-nargs])
                    target = self.interface_method(o.cls, self.resolve_class(pkg, cp[u2(pc + 2)][1]), tok)
                args = st[len(st) - nargs:]
                del st[len(st) - nargs:]
                if isinstance(target, Native):
                    st += self.call_native(target, args)
                else:
                    if target.flags & capmod.ACC_ABSTRACT:
                        raise LookupError("abstract method %r" % target)
                    f.ret = pc + ln
                    f = Frame(target, args, self.packages[target.cap.aid])
                    frames.append(f)
                    code, cp, pkg = f.m.cap.method_data, f.m.cap.cp, f.pkg
                    st, loc = f.stack, f.locals
                    pc = f.pc
                    continue
            elif op == 0x8F:  # new
                st.append(self.new(self.resolve_class(pkg, cp[u2(pc + 1)][1])))
            elif op in (0x90, 0x91):  # newarray type, anewarray class
                n = st.pop()
                if n < 0:
                    self.throw("java/lang/NegativeArraySizeException")
                if op == 0x90:
                    st.append(JArray(code[pc + 1], n))
                else:
                    st.append(JArray(T_REF, n, self.resolve_class(pkg, cp[u2(pc + 1)][1])))
            elif op == 0x92:  # arraylength
                st.append(len(npe(st.pop())))
            elif op == 0x93:  # athrow
                raise JavaThrow(npe(st.pop()))
            elif op in (0x94, 0x95):  # checkcast, instanceof: atype, cp index
                t, idx = code[pc + 1], u2(pc + 2)
                cls = self.resolve_class(pkg, cp[idx][1]) if idx else None
                o = st[-1]
                ok = o is not None and self.instance_of(o, t, cls)
                if op == 0x95:
                    st[-1] = int(ok)
                elif o is not None and not ok:
                    self.throw("java/lang/ClassCastException")
            elif op == 0x96:  # sinc_w
                i = code[pc + 1]
                loc[i] = s16(loc[i] + s2(pc + 2))
            elif op == 0x97:  # iinc_w
                i = code[pc + 1]
                loc[i:i + 2] = int_cells(cells_int(loc[i], loc[i + 1]) + s2(pc + 2))
            else:
                raise NotImplementedError("bytecode %02X at %d" % (op, pc))
            pc += ln


# instruction length (switches handle their own)
OPLEN = {}
for _ops, _n in (((0x10, 0x12, 0x15, 0x16, 0x17, 0x28, 0x29, 0x2A, 0x3F, 0x40, 0x72, 0x90, 0x70)
                  + tuple(range(0x60, 0x70)) + tuple(range(0x83, 0x8B)) + tuple(range(0xAD, 0xB1))
                  + tuple(range(0xB5, 0xB9)), 2),
                 ((0x11, 0x13, 0x59, 0x5A, 0x71, 0x8B, 0x8C, 0x8D, 0x8F, 0x91) + tuple(range(0x7B, 0x83))
                  + tuple(range(0x98, 0xA9)) + tuple(range(0xA9, 0xAD)) + tuple(range(0xB1, 0xB5)), 3),
                 ((0x94, 0x95, 0x96, 0x97), 4),
                 ((0x14, 0x8E), 5)):
    for _o in _ops:
        OPLEN[_o] = _n

COND = (int.__eq__, int.__ne__, int.__lt__, int.__ge__, int.__gt__, int.__le__)

ARITH = {}
for _base, _k in ((0x41, "add"), (0x43, "sub"), (0x45, "mul"), (0x47, "div"), (0x49, "rem"),
                  (0x4D, "shl"), (0x4F, "shr"), (0x51, "ushr"), (0x53, "and"), (0x55, "or"), (0x57, "xor")):
    ARITH[_base] = ARITH[_base + 1] = _k
