"""The Java Card API in Python: native methods by class and name + descriptor, linked to CAPs through
the export file tokens (vm.py). vm.card is the runtime (card.py): applets, selection, the APDU."""

import hashlib
import os

from cap import T_BOOLEAN, T_BYTE, T_SHORT
from vm import JArray, JObject, JavaThrow, T_REF, s8

NATIVES = {}


def native(cls, *sigs):
    def reg(fn):
        for s in sigs:
            NATIVES.setdefault(cls, {})[s] = fn
        return fn
    return reg


def npe(vm, o):
    if o is None:
        vm.throw("java/lang/NullPointerException")
    return o


def span(vm, a, off, n):
    """Checks a[off:off + n] (a byte / boolean / short array)."""
    npe(vm, a)
    if off < 0 or n < 0 or off + n > len(a.data):
        vm.throw("java/lang/ArrayIndexOutOfBoundsException")
    return a


def get_bytes(vm, a, off, n):
    return bytes(span(vm, a, off, n).data[off:off + n])


def put_bytes(vm, a, off, data, atomic=True):
    span(vm, a, off, len(data))
    if atomic and vm.journal is not None and not a.transient:
        for i, b in enumerate(data):
            vm.array_store(a, off + i, b)
    else:
        a.data[off:off + len(data)] = data


# --- java.lang ---

@native("java/lang/Object", "<init>()V")
def object_init(vm, this):
    pass


@native("java/lang/Object", "equals(Ljava/lang/Object;)Z")
def object_equals(vm, this, o):
    return this is o


for _c in ("Throwable", "Exception", "RuntimeException", "IndexOutOfBoundsException",
           "ArrayIndexOutOfBoundsException", "NegativeArraySizeException", "NullPointerException",
           "ClassCastException", "ArithmeticException", "SecurityException", "ArrayStoreException"):
    native("java/lang/" + _c, "<init>()V")(object_init)

# --- exceptions with a reason: CardException, CardRuntimeException and their subclasses ---

REASON_EXCEPTIONS = ("javacard/framework/CardException", "javacard/framework/CardRuntimeException",
                     "javacard/framework/ISOException", "javacard/framework/PINException",
                     "javacard/framework/APDUException", "javacard/framework/SystemException",
                     "javacard/framework/TransactionException", "javacard/framework/UserException",
                     "javacard/security/CryptoException", "javacardx/external/ExternalException",
                     "javacardx/biometry/BioException", "javacard/framework/service/ServiceException")


def _reason_class(name):
    def init(vm, this, reason):
        this.reason = reason

    def get(vm, this):
        return this.reason

    def setr(vm, this, reason):
        this.reason = reason

    def throw_it(vm, reason):
        vm.throw(name, reason)

    native(name, "<init>(S)V")(init)
    native(name, "<init>()V")(lambda vm, this: setattr(this, "reason", 0))
    native(name, "getReason()S")(get)
    native(name, "setReason(S)V")(setr)
    native(name, "throwIt(S)V")(throw_it)


for _c in REASON_EXCEPTIONS:
    _reason_class(_c)

# --- javacard.framework.Applet ---


@native("javacard/framework/Applet", "<init>()V")
def applet_init(vm, this):
    pass


@native("javacard/framework/Applet", "register()V")
def applet_register(vm, this):
    vm.card.register(this, None)


@native("javacard/framework/Applet", "register([BSB)V")
def applet_register_aid(vm, this, a, off, n):
    if n < 5 or n > 16:
        vm.throw("javacard/framework/SystemException", 1)  # ILLEGAL_VALUE
    vm.card.register(this, get_bytes(vm, a, off, n))


@native("javacard/framework/Applet", "selectingApplet()Z")
def applet_selecting(vm, this):
    return vm.card.selecting


@native("javacard/framework/Applet", "reSelectingApplet()Z")
def applet_reselecting(vm):
    return vm.card.reselecting


@native("javacard/framework/Applet", "select()Z")
def applet_select(vm, this):
    return 1


@native("javacard/framework/Applet", "deselect()V")
def applet_deselect(vm, this):
    pass


@native("javacard/framework/Applet",
        "getShareableInterfaceObject(Ljavacard/framework/AID;B)Ljavacard/framework/Shareable;")
def applet_sio(vm, this, aid, param):
    return None

# --- javacard.framework.APDU ---

# states (APDU.STATE_*) and APDUException reasons
INITIAL, PARTIAL_INCOMING, FULL_INCOMING, OUTGOING, OUTGOING_LENGTH_KNOWN, PARTIAL_OUTGOING, FULL_OUTGOING = range(7)
ILLEGAL_USE, BUFFER_BOUNDS, BAD_LENGTH = 1, 2, 3
BUFFER_SIZE = 261  # header + 255 bytes + Le, as JCOP


class Apdu(JObject):
    def __init__(self, vm, cmd):
        super().__init__(vm.cls("javacard/framework/APDU"))
        self.buf = JArray(T_BYTE, BUFFER_SIZE, transient=1)
        self.reset(cmd)

    def reset(self, cmd):
        """A new command: header in the buffer, the body waits for setIncomingAndReceive."""
        self.cmd, self.out, self.state, self.out_len = cmd, bytearray(), INITIAL, None
        self.buf.data[:] = bytes(BUFFER_SIZE)
        self.buf.data[:min(5, len(cmd))] = cmd[:5]
        self.lc, self.le = 0, 256  # no Le: up to 256 (T=1 / contactless)
        if len(cmd) > 5:
            self.lc = cmd[4]
            if len(cmd) > 5 + self.lc:
                self.le = cmd[5 + self.lc] or 256
        elif len(cmd) == 5:
            self.le = cmd[4] or 256
        self.received = 0


def _apdu_err(vm, reason):
    vm.throw("javacard/framework/APDUException", reason)


@native("javacard/framework/APDU", "getBuffer()[B")
def apdu_buffer(vm, this):
    return this.buf


@native("javacard/framework/APDU", "getCurrentAPDU()Ljavacard/framework/APDU;")
def apdu_current(vm):
    return vm.card.apdu


@native("javacard/framework/APDU", "getCurrentAPDUBuffer()[B")
def apdu_current_buffer(vm):
    return vm.card.apdu.buf


@native("javacard/framework/APDU", "setIncomingAndReceive()S")
def apdu_set_incoming(vm, this):
    if this.state != INITIAL:
        _apdu_err(vm, ILLEGAL_USE)
    return apdu_receive(vm, this, 5, first=True)


@native("javacard/framework/APDU", "receiveBytes(S)S")
def apdu_receive(vm, this, off, first=False):
    if not first and this.state not in (PARTIAL_INCOMING, FULL_INCOMING):
        _apdu_err(vm, ILLEGAL_USE)
    n = this.lc - this.received
    if off < 0 or off + n > BUFFER_SIZE:
        _apdu_err(vm, BUFFER_BOUNDS)
    this.buf.data[off:off + n] = this.cmd[5 + this.received:5 + this.lc]
    this.received = this.lc
    this.state = FULL_INCOMING
    return n


@native("javacard/framework/APDU", "getIncomingLength()S")
def apdu_incoming_length(vm, this):
    return this.lc


@native("javacard/framework/APDU", "getOffsetCdata()S")
def apdu_offset_cdata(vm, this):
    return 5


@native("javacard/framework/APDU", "setOutgoing()S", "setOutgoingNoChaining()S")
def apdu_set_outgoing(vm, this):
    if this.state >= OUTGOING:
        _apdu_err(vm, ILLEGAL_USE)
    this.state = OUTGOING
    return this.le


@native("javacard/framework/APDU", "setOutgoingLength(S)V")
def apdu_set_outgoing_length(vm, this, n):
    if this.state != OUTGOING:
        _apdu_err(vm, ILLEGAL_USE)
    if n < 0 or n > 256:
        _apdu_err(vm, BAD_LENGTH)
    this.out_len, this.state = n, OUTGOING_LENGTH_KNOWN


def _send(vm, this, data):
    if this.state not in (OUTGOING_LENGTH_KNOWN, PARTIAL_OUTGOING):
        _apdu_err(vm, ILLEGAL_USE)
    if len(this.out) + len(data) > this.out_len:
        _apdu_err(vm, ILLEGAL_USE)
    this.out += data
    this.state = FULL_OUTGOING if len(this.out) == this.out_len else PARTIAL_OUTGOING


@native("javacard/framework/APDU", "sendBytes(SS)V")
def apdu_send_bytes(vm, this, off, n):
    if off < 0 or n < 0 or off + n > BUFFER_SIZE:
        _apdu_err(vm, BUFFER_BOUNDS)
    _send(vm, this, bytes(this.buf.data[off:off + n]))


@native("javacard/framework/APDU", "sendBytesLong([BSS)V")
def apdu_send_long(vm, this, a, off, n):
    _send(vm, this, get_bytes(vm, a, off, n))


@native("javacard/framework/APDU", "setOutgoingAndSend(SS)V")
def apdu_outgoing_and_send(vm, this, off, n):
    apdu_set_outgoing(vm, this)
    apdu_set_outgoing_length(vm, this, n)
    apdu_send_bytes(vm, this, off, n)


@native("javacard/framework/APDU", "getCurrentState()B")
def apdu_state(vm, this):
    return this.state


@native("javacard/framework/APDU", "getNAD()B")
def apdu_nad(vm, this):
    return 0


@native("javacard/framework/APDU", "isCommandChainingCLA()Z")
def apdu_chaining(vm, this):
    return bool(this.cmd[0] & 0x10)


@native("javacard/framework/APDU", "isSecureMessagingCLA()Z")
def apdu_sm(vm, this):
    c = this.cmd[0]
    return bool(c & 0x0C) if not c & 0x40 else bool(c & 0x20)


@native("javacard/framework/APDU", "isISOInterindustryCLA()Z")
def apdu_interindustry(vm, this):
    return not this.cmd[0] & 0x80


@native("javacard/framework/APDU", "isValidCLA()Z")
def apdu_valid_cla(vm, this):
    return this.cmd[0] != 0xFF


@native("javacard/framework/APDU", "getCLAChannel()B")
def apdu_channel(vm):
    return 0


@native("javacard/framework/APDU", "getInBlockSize()S", "getOutBlockSize()S")
def apdu_block_size(vm):
    return 0xFE


@native("javacard/framework/APDU", "getProtocol()B")
def apdu_protocol(vm):
    return 0x91 - 0x100  # PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | PROTOCOL_T1


@native("javacard/framework/APDU", "waitExtension()V")
def apdu_wait(vm):
    pass

# --- javacard.framework.JCSystem ---


def _transient(t):
    def make(vm, n, event):
        if event not in (1, 2):
            vm.throw("javacard/framework/SystemException", 1)  # ILLEGAL_VALUE
        if n < 0:
            vm.throw("java/lang/NegativeArraySizeException")
        a = JArray(t, n, transient=event)
        vm.card.transients.append(a)
        return a
    return make


native("javacard/framework/JCSystem", "makeTransientByteArray(SB)[B")(_transient(T_BYTE))
native("javacard/framework/JCSystem", "makeTransientBooleanArray(SB)[Z")(_transient(T_BOOLEAN))
native("javacard/framework/JCSystem", "makeTransientShortArray(SB)[S")(_transient(T_SHORT))
native("javacard/framework/JCSystem", "makeTransientObjectArray(SB)[Ljava/lang/Object;")(_transient(T_REF))


@native("javacard/framework/JCSystem", "isTransient(Ljava/lang/Object;)B")
def jc_is_transient(vm, o):
    return o.transient if isinstance(o, JArray) else 0


@native("javacard/framework/JCSystem", "beginTransaction()V")
def jc_begin(vm):
    if vm.journal is not None:
        vm.throw("javacard/framework/TransactionException", 1)  # IN_PROGRESS
    vm.journal = []


@native("javacard/framework/JCSystem", "commitTransaction()V")
def jc_commit(vm):
    if vm.journal is None:
        vm.throw("javacard/framework/TransactionException", 2)  # NOT_IN_PROGRESS
    vm.journal = None


@native("javacard/framework/JCSystem", "abortTransaction()V")
def jc_abort(vm):
    if vm.journal is None:
        vm.throw("javacard/framework/TransactionException", 2)
    vm.abort_transaction()


@native("javacard/framework/JCSystem", "getTransactionDepth()B")
def jc_depth(vm):
    return vm.journal is not None


@native("javacard/framework/JCSystem", "getMaxCommitCapacity()S", "getUnusedCommitCapacity()S")
def jc_capacity(vm):
    return 0x7FFF


@native("javacard/framework/JCSystem", "getAvailableMemory(B)S")
def jc_memory(vm, kind):
    return 0x7FFF


@native("javacard/framework/JCSystem", "getVersion()S")
def jc_version(vm):
    return 0x0304


@native("javacard/framework/JCSystem", "getAID()Ljavacard/framework/AID;")
def jc_get_aid(vm):
    return vm.card.context.aid_obj if vm.card.context else None


@native("javacard/framework/JCSystem", "getPreviousContextAID()Ljavacard/framework/AID;")
def jc_prev_aid(vm):
    return None


@native("javacard/framework/JCSystem", "lookupAID([BSB)Ljavacard/framework/AID;")
def jc_lookup(vm, a, off, n):
    want = get_bytes(vm, a, off, n)
    for inst in vm.card.applets:
        if inst.aid == want:
            return inst.aid_obj
    return None


@native("javacard/framework/JCSystem", "isAppletActive(Ljavacard/framework/AID;)Z")
def jc_active(vm, aid):
    return bool(vm.card.selected) and vm.card.selected.aid_obj is aid


@native("javacard/framework/JCSystem", "isObjectDeletionSupported()Z")
def jc_deletion(vm):
    return 0


@native("javacard/framework/JCSystem", "requestObjectDeletion()V")
def jc_request_deletion(vm):
    pass


@native("javacard/framework/JCSystem", "getAssignedChannel()B")
def jc_channel(vm):
    return 0


@native("javacard/framework/JCSystem",
        "getAppletShareableInterfaceObject(Ljavacard/framework/AID;B)Ljavacard/framework/Shareable;")
def jc_sio(vm, aid, param):
    return None

# --- javacard.framework.Util ---


@native("javacard/framework/Util", "arrayCompare([BS[BSS)B")
def util_compare(vm, src, so, dst, do, n):
    a, b = get_bytes(vm, src, so, n), get_bytes(vm, dst, do, n)
    for x, y in zip(a, b):
        if x != y:
            return -1 if s8(x) < s8(y) else 1
    return 0


@native("javacard/framework/Util", "arrayCopy([BS[BSS)S")
def util_copy(vm, src, so, dst, do, n):
    put_bytes(vm, npe(vm, dst), do, get_bytes(vm, src, so, n))
    return do + n


@native("javacard/framework/Util", "arrayCopyNonAtomic([BS[BSS)S")
def util_copy_na(vm, src, so, dst, do, n):
    put_bytes(vm, npe(vm, dst), do, get_bytes(vm, src, so, n), atomic=False)
    return do + n


@native("javacard/framework/Util", "arrayFillNonAtomic([BSSB)S")
def util_fill(vm, a, off, n, v):
    put_bytes(vm, a, off, bytes([v & 0xFF]) * n, atomic=False)
    return off + n


@native("javacard/framework/Util", "getShort([BS)S")
def util_get_short(vm, a, off):
    b = get_bytes(vm, a, off, 2)
    return b[0] << 8 | b[1]


@native("javacard/framework/Util", "makeShort(BB)S")
def util_make_short(vm, hi, lo):
    return (hi & 0xFF) << 8 | lo & 0xFF


@native("javacard/framework/Util", "setShort([BSS)S")
def util_set_short(vm, a, off, v):
    put_bytes(vm, a, off, bytes([v >> 8 & 0xFF, v & 0xFF]))
    return off + 2

# --- javacard.framework.AID ---


class Aid(JObject):
    def __init__(self, vm, data):
        super().__init__(vm.cls("javacard/framework/AID"))
        self.data = data


@native("javacard/framework/AID", "<new>")
def aid_new(vm, cls):
    o = JObject(cls)
    o.data = b""
    return o


@native("javacard/framework/AID", "<init>([BSB)V")
def aid_init(vm, this, a, off, n):
    if n < 5 or n > 16:
        vm.throw("javacard/framework/SystemException", 1)
    this.data = get_bytes(vm, a, off, n)


@native("javacard/framework/AID", "equals(Ljava/lang/Object;)Z")
def aid_equals_obj(vm, this, o):
    return hasattr(o, "data") and isinstance(o.data, bytes) and o.data == this.data


@native("javacard/framework/AID", "equals([BSB)Z")
def aid_equals(vm, this, a, off, n):
    return a is not None and get_bytes(vm, a, off, n) == this.data


@native("javacard/framework/AID", "partialEquals([BSB)Z")
def aid_partial(vm, this, a, off, n):
    return a is not None and n <= len(this.data) and get_bytes(vm, a, off, n) == this.data[:n]


@native("javacard/framework/AID", "RIDEquals(Ljavacard/framework/AID;)Z")
def aid_rid(vm, this, o):
    return o is not None and o.data[:5] == this.data[:5]


@native("javacard/framework/AID", "getBytes([BS)B")
def aid_get_bytes(vm, this, a, off):
    put_bytes(vm, a, off, this.data)
    return len(this.data)


@native("javacard/framework/AID", "getPartialBytes(S[BSB)B")
def aid_get_partial(vm, this, aoff, a, off, n):
    d = this.data[aoff:aoff + n] if n else this.data[aoff:]
    put_bytes(vm, a, off, d)
    return len(d)

# --- javacard.framework.OwnerPIN ---


@native("javacard/framework/OwnerPIN", "<init>(BB)V")
def pin_init(vm, this, tries, size):
    if tries < 1 or size < 1:
        vm.throw("javacard/framework/PINException", 1)  # ILLEGAL_VALUE
    this.limit, this.size, this.tries, this.pin = tries, size, tries, b""
    this.validated = JArray(T_BOOLEAN, 1, transient=1)
    vm.card.transients.append(this.validated)


@native("javacard/framework/OwnerPIN", "check([BSB)Z")
def pin_check(vm, this, a, off, n):
    this.validated.data[0] = 0
    if this.tries == 0:
        return 0
    vm.store(this.__dict__, "tries", this.tries - 1)
    if n == len(this.pin) and get_bytes(vm, a, off, n) == this.pin:
        vm.store(this.__dict__, "tries", this.limit)
        this.validated.data[0] = 1
        return 1
    return 0


@native("javacard/framework/OwnerPIN", "getTriesRemaining()B")
def pin_tries(vm, this):
    return this.tries


@native("javacard/framework/OwnerPIN", "isValidated()Z", "getValidatedFlag()Z")
def pin_validated(vm, this):
    return this.validated.data[0]


@native("javacard/framework/OwnerPIN", "setValidatedFlag(Z)V")
def pin_set_validated(vm, this, v):
    this.validated.data[0] = v & 1


@native("javacard/framework/OwnerPIN", "reset()V")
def pin_reset(vm, this):
    if this.validated.data[0]:
        vm.store(this.__dict__, "tries", this.limit)
    this.validated.data[0] = 0


@native("javacard/framework/OwnerPIN", "resetAndUnblock()V")
def pin_unblock(vm, this):
    vm.store(this.__dict__, "tries", this.limit)
    this.validated.data[0] = 0


@native("javacard/framework/OwnerPIN", "update([BSB)V")
def pin_update(vm, this, a, off, n):
    if n > this.size:
        vm.throw("javacard/framework/PINException", 1)
    vm.store(this.__dict__, "pin", get_bytes(vm, a, off, n))
    vm.store(this.__dict__, "tries", this.limit)
    this.validated.data[0] = 0

# --- javacard.security: MessageDigest, RandomData ---


DIGESTS = {1: "sha1", 2: "md5", 3: "ripemd160", 4: "sha256", 5: "sha384", 6: "sha512", 7: "sha224"}


@native("javacard/security/MessageDigest", "getInstance(BZ)Ljavacard/security/MessageDigest;")
def md_get(vm, alg, shared):
    if alg not in DIGESTS:
        vm.throw("javacard/security/CryptoException", 3)  # NO_SUCH_ALGORITHM
    o = JObject(vm.cls("javacard/security/MessageDigest"))
    o.alg, o.h = alg, hashlib.new(DIGESTS[alg])
    return o


@native("javacard/security/MessageDigest", "update([BSS)V")
def md_update(vm, this, a, off, n):
    this.h.update(get_bytes(vm, a, off, n))


@native("javacard/security/MessageDigest", "doFinal([BSS[BS)S")
def md_final(vm, this, a, off, n, out, ooff):
    this.h.update(get_bytes(vm, a, off, n))
    d = this.h.digest()
    this.h = hashlib.new(DIGESTS[this.alg])
    put_bytes(vm, out, ooff, d, atomic=False)
    return len(d)


@native("javacard/security/MessageDigest", "reset()V")
def md_reset(vm, this):
    this.h = hashlib.new(DIGESTS[this.alg])


@native("javacard/security/MessageDigest", "getAlgorithm()B")
def md_alg(vm, this):
    return this.alg


@native("javacard/security/MessageDigest", "getLength()B")
def md_len(vm, this):
    return this.h.digest_size


@native("javacard/security/RandomData", "getInstance(B)Ljavacard/security/RandomData;")
def rnd_get(vm, alg):
    if alg not in (1, 2):  # ALG_PSEUDO_RANDOM, ALG_SECURE_RANDOM
        vm.throw("javacard/security/CryptoException", 3)
    return JObject(vm.cls("javacard/security/RandomData"))


@native("javacard/security/RandomData", "generateData([BSS)V")
def rnd_gen(vm, this, a, off, n):
    put_bytes(vm, a, off, os.urandom(n), atomic=False)


@native("javacard/security/RandomData", "setSeed([BSS)V")
def rnd_seed(vm, this, a, off, n):
    pass
