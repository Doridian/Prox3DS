"""The card runtime around the VM (JCRE spec): installed applets, SELECT, an APDU through an applet's
process() into a response, transient memory on reset / deselect, open transactions aborted."""

import cap as capmod
import api
from vm import VM, JArray, JavaThrow, T_BYTE

CLEAR_ON_RESET, CLEAR_ON_DESELECT = 1, 2


class Instance:
    def __init__(self, aid, obj, pkg, aid_obj):
        self.aid, self.obj, self.pkg, self.aid_obj = aid, obj, pkg, aid_obj


class Card:
    def __init__(self, trace=False):
        self.vm = VM(api.NATIVES)
        self.vm.card = self
        self.applets = []          # Instance, in install order
        self.selected = None
        self.context = None        # the applet whose code runs
        self.selecting = self.reselecting = False
        self.transients = []
        self.installing = None     # (default AID, package) while an install() runs
        self.apdu = None
        self.trace = trace

    def load(self, path):
        c = capmod.Cap(path)
        return self.vm.load(c)

    def install(self, pkg, applet_aid=None, instance_aid=None, params=b""):
        """Runs the applet class's install(): bArray = instance AID, control info, applet data (each
        length-prefixed), as GlobalPlatform's INSTALL [for install] passes them."""
        c = pkg.cap
        aid, off = next((a, o) for a, o in c.applets if applet_aid in (None, a))
        inst = instance_aid or aid
        data = bytes([len(inst)]) + inst + b"\x00" + bytes([len(params)]) + params
        arr = JArray(T_BYTE, len(data))
        arr.data[:] = data
        self.installing = (inst, pkg)
        n = len(self.applets)
        try:
            self._call(c.method(off), [arr, 0, len(data)])
        finally:
            self.installing = None
        if len(self.applets) == n:
            raise RuntimeError("install() didn't register an applet")
        return self.applets[-1]

    def register(self, obj, aid):
        inst_aid, pkg = self.installing
        aid = aid or inst_aid
        if any(i.aid == aid for i in self.applets):
            self.vm.throw("javacard/framework/SystemException", 1)
        self.applets.append(Instance(aid, obj, pkg, api.Aid(self.vm, aid)))

    def _call(self, target, args):
        """Runs Java code; an uncaught Java exception comes back as JavaThrow."""
        if self.vm.journal is not None:
            self.vm.abort_transaction()
        try:
            return self.vm.call(target, args)
        finally:
            if self.vm.journal is not None:  # left open: aborted (JCRE 7.6.3)
                self.vm.abort_transaction()

    def _virtual(self, inst, name, desc):
        vc = self.vm.cls("javacard/framework/Applet")
        tok = vc.exp.methods[(name, desc)][0]
        return self.vm.virtual(inst.obj.cls, tok)

    def _clear(self, event):
        for a in self.transients:
            if a.transient == event:
                a.data[:] = bytes(len(a.data)) if isinstance(a.data, bytearray) else [None if a.type == 14 else 0] * len(a.data)

    def reset(self):
        """A new session (field on): nothing selected, CLEAR_ON_RESET and _DESELECT memory cleared."""
        self.selected = None
        self._clear(CLEAR_ON_RESET)
        self._clear(CLEAR_ON_DESELECT)

    def _deselect(self):
        if self.selected:
            self.context = self.selected
            try:
                self._call(self._virtual(self.selected, "deselect", "()V"), [self.selected.obj])
            except JavaThrow:
                pass
            self._clear(CLEAR_ON_DESELECT)
        self.selected = None

    def _find(self, aid):
        for inst in self.applets:
            if inst.aid == aid:
                return inst
        for inst in self.applets:  # a partial AID: the first that starts with it
            if inst.aid.startswith(aid):
                return inst
        return None

    def process(self, cmd):
        """One command APDU -> the response (data + SW)."""
        cmd = bytes(cmd)
        if len(cmd) < 4:
            return b"\x67\x00"
        if self.apdu is None:
            self.apdu = api.Apdu(self.vm, cmd)
        else:
            self.apdu.reset(cmd)
        self.selecting = self.reselecting = False
        if cmd[0] & 0xFC == 0 and cmd[1] == 0xA4 and cmd[2] == 0x04 and len(cmd) >= 5:
            inst = self._find(cmd[5:5 + cmd[4]])
            if inst:
                self.reselecting = inst is self.selected
                self._deselect()
                self.context = inst
                try:
                    ok = self._call(self._virtual(inst, "select", "()Z"), [inst.obj])[0]
                except JavaThrow:
                    ok = 0
                if not ok:
                    return b"\x69\x99"  # SW_APPLET_SELECT_FAILED
                self.selected = inst
                self.selecting = True
            elif not self.selected:
                return b"\x6A\x82"
        if not self.selected:
            return b"\x6D\x00"
        inst = self.context = self.selected
        sw = 0x9000
        try:
            self._call(self._virtual(inst, "process", "(Ljavacard/framework/APDU;)V"), [inst.obj, self.apdu])
        except JavaThrow as t:
            o = t.obj
            sw = o.reason & 0xFFFF if o.cls.subclass_of(self.vm.cls("javacard/framework/ISOException")) else 0x6F00
            if self.trace and sw == 0x6F00:
                print("  uncaught %s reason %s" % (o.cls.native_base().name, getattr(o, "reason", None)))
        finally:
            self.selecting = self.reselecting = False
        return bytes(self.apdu.out) + bytes([sw >> 8, sw & 0xFF])
