// The Java Card API in C: the natives jcapitab.c links by export token (tools/gen_jcapi.py names them
// jn_<package>_<Class>_<method>[_<params>]). a[] holds the argument cells, this first; results go back
// to a[0]. The Python prototype is tools/jcvm/api.py.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "jccard.h"
#include "jccrypto.h"

#define CARD ((JcCard *)vm->card)
#define S(i) ((s16)a[i])
#define RET(v) return a[0] = (u16)(v), 1

// --- helpers ---

// a[off .. off + len) of a byte (or boolean) array; NULL after throwing.
u8 *jcBytes(JcVm *vm, u16 h, s16 off, s16 len)
{
	JcObj *o = jcObj(vm, h);
	if (!o) return jcThrow(vm, JCC_lang_NullPointerException, 0), NULL;
	if ((o->type != JT_BYTE && o->type != JT_BOOLEAN) || off < 0 || len < 0 || off + len > o->len)
		return jcThrow(vm, JCC_lang_ArrayIndexOutOfBoundsException, 0), NULL;
	return o->data + off;
}

// Copies into a byte array; atomic: through the transaction journal (persistent arrays).
bool jcPut(JcVm *vm, u16 h, s16 off, const u8 *src, s16 len, bool atomic)
{
	u8 *d = jcBytes(vm, h, off, len);
	if (!d) return false;
	if (atomic) {
		for (s16 i = 0; i < len; i += 4) jcStore(vm, h, off + i, src + i, len - i < 4 ? len - i : 4);
		return !vm->exc;
	}
	memmove(d, src, len);
	return true;
}

static bool isA(int cls, int of)
{
	for (; cls >= 0; cls = jcApiClasses[cls].super)
		if (cls == of) return true;
	return false;
}

typedef struct {
	u8 len, aid[16];
} NatAid;

typedef struct {
	u8 limit, size, tries, len;
	u16 validated; // transient boolean[1]
	u8 pin[32];
} NatPin;

u16 jcNatSize(int c)
{
	if (isA(c, JCC_framework_CardException) || isA(c, JCC_framework_CardRuntimeException)) return 2;
	if (c == JCC_framework_AID) return sizeof(NatAid);
	if (c == JCC_framework_OwnerPIN) return sizeof(NatPin);
	return jcCryptoNatSize(c);
}

void jcNatClear(int c, void *nat)
{
	jcCryptoNatClear(c, nat);
}

// --- java.lang ---

int jn_lang_Object_init(JcVm *vm, u16 *a)
{
	return 0;
}

int jn_lang_Object_equals(JcVm *vm, u16 *a)
{
	RET(a[0] == a[1]);
}

#define NOP_INIT(n) int jn_lang_##n##_init(JcVm *vm, u16 *a) { return 0; }
NOP_INIT(Throwable)
NOP_INIT(Exception)
NOP_INIT(RuntimeException)
NOP_INIT(IndexOutOfBoundsException)
NOP_INIT(ArrayIndexOutOfBoundsException)
NOP_INIT(NegativeArraySizeException)
NOP_INIT(NullPointerException)
NOP_INIT(ClassCastException)
NOP_INIT(ArithmeticException)
NOP_INIT(SecurityException)
NOP_INIT(ArrayStoreException)

// --- exceptions with a reason ---

static int reasonSet(JcVm *vm, u16 *a)
{
	s16 *r = jcNat(vm, a[0]);
	if (r) jcStore(vm, a[0], jcNatOff(jcObj(vm, a[0])->len), &a[1], 2);
	(void)r;
	return 0;
}

static int reasonGet(JcVm *vm, u16 *a)
{
	RET(jcReason(vm, a[0]));
}

#define REASON_EX(pkg, n) \
	int jn_##pkg##_##n##_throwIt(JcVm *vm, u16 *a) { return jcThrow(vm, JCC_##pkg##_##n, S(0)); } \
	int jn_##pkg##_##n##_getReason(JcVm *vm, u16 *a) { return reasonGet(vm, a); } \
	int jn_##pkg##_##n##_setReason(JcVm *vm, u16 *a) { return reasonSet(vm, a); }
#define REASON_INIT(pkg, n) int jn_##pkg##_##n##_init(JcVm *vm, u16 *a) { return reasonSet(vm, a); }
REASON_EX(framework, CardException)
REASON_EX(framework, CardRuntimeException)
REASON_EX(framework, ISOException)
REASON_EX(framework, PINException)
REASON_EX(framework, APDUException)
REASON_EX(framework, SystemException)
REASON_EX(framework, TransactionException)
REASON_EX(framework, UserException)
REASON_EX(security, CryptoException)
REASON_INIT(framework, CardException)
REASON_INIT(framework, CardRuntimeException)
REASON_INIT(framework, ISOException)
REASON_INIT(framework, PINException)
REASON_INIT(framework, APDUException)
REASON_INIT(framework, SystemException)
REASON_INIT(framework, TransactionException)
REASON_INIT(security, CryptoException)

int jn_framework_UserException_init_S(JcVm *vm, u16 *a)
{
	return reasonSet(vm, a);
}

int jn_framework_UserException_init_V(JcVm *vm, u16 *a)
{
	return 0;
}

// --- javacard.framework.Applet ---

int jn_framework_Applet_init(JcVm *vm, u16 *a)
{
	return 0;
}

static int registerAs(JcVm *vm, u16 obj, const u8 *aid, u8 len)
{
	JcCard *c = CARD;
	if (len < 5 || len > 16 || c->installPkg < 0) return jcThrow(vm, JCC_framework_SystemException, 1); // ILLEGAL_VALUE
	for (int i = 0; i < c->napplets; i++)
		if (c->applets[i].aidLen == len && !memcmp(c->applets[i].aid, aid, len))
			return jcThrow(vm, JCC_framework_SystemException, 1);
	if (c->napplets >= JC_APPLETS) return jcThrow(vm, JCC_framework_SystemException, 3); // NO_RESOURCE
	u16 ao = jcNew(vm, JCC_framework_AID);
	if (!ao) return jcThrow(vm, JCC_framework_SystemException, 3);
	NatAid *n = jcNat(vm, ao);
	n->len = len;
	memcpy(n->aid, aid, len);
	JcApplet *ap = &c->applets[c->napplets++];
	memcpy(ap->aid, aid, len);
	ap->aidLen = len, ap->pkg = c->installPkg, ap->obj = obj, ap->aidObj = ao;
	c->dirty = true;
	return 0;
}

int jn_framework_Applet_register_V(JcVm *vm, u16 *a)
{
	return registerAs(vm, a[0], CARD->instAid, CARD->instAidLen);
}

int jn_framework_Applet_register_aBSB(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[1], S(2), (s8)a[3]);
	return d ? registerAs(vm, a[0], d, (s8)a[3]) : -1;
}

int jn_framework_Applet_selectingApplet(JcVm *vm, u16 *a)
{
	RET(CARD->selecting);
}

int jn_framework_Applet_reSelectingApplet(JcVm *vm, u16 *a)
{
	RET(CARD->reselecting);
}

int jn_framework_Applet_select(JcVm *vm, u16 *a)
{
	RET(1);
}

int jn_framework_Applet_deselect(JcVm *vm, u16 *a)
{
	return 0;
}

int jn_framework_Applet_getShareableInterfaceObject(JcVm *vm, u16 *a)
{
	RET(0);
}

// --- javacard.framework.APDU ---

enum { ST_INITIAL, ST_PARTIAL_INCOMING, ST_FULL_INCOMING, ST_OUTGOING, ST_OUTGOING_LENGTH_KNOWN, ST_PARTIAL_OUTGOING,
	ST_FULL_OUTGOING };
enum { AE_ILLEGAL_USE = 1, AE_BUFFER_BOUNDS, AE_BAD_LENGTH };

static int apduErr(JcVm *vm, s16 reason)
{
	return jcThrow(vm, JCC_framework_APDUException, reason);
}

int jn_framework_APDU_getBuffer(JcVm *vm, u16 *a)
{
	RET(CARD->buf);
}

int jn_framework_APDU_getCurrentAPDU(JcVm *vm, u16 *a)
{
	RET(CARD->apdu);
}

int jn_framework_APDU_getCurrentAPDUBuffer(JcVm *vm, u16 *a)
{
	RET(CARD->buf);
}

// The next block of the command data into the buffer at off: at most 255 bytes (what is left), which must
// fit (as the J3H145: an extended APDU's next blocks go at 0, at offsetCdata they don't).
static int receive(JcVm *vm, u16 *a, s16 off, s16 max)
{
	JcCard *c = CARD;
	s16 n = c->lc - c->received;
	if (n > max) n = max;
	if (off < 0 || off + n > JC_BUF) return apduErr(vm, AE_BUFFER_BOUNDS);
	memcpy(jcObj(vm, c->buf)->data + off, c->cmd + c->cdata + c->received, n);
	c->received += n;
	c->state = c->received == c->lc ? ST_FULL_INCOMING : ST_PARTIAL_INCOMING;
	RET(n);
}

int jn_framework_APDU_setIncomingAndReceive(JcVm *vm, u16 *a)
{
	if (CARD->state != ST_INITIAL) return apduErr(vm, AE_ILLEGAL_USE);
	return receive(vm, a, CARD->cdata, JC_BUF - CARD->cdata);
}

int jn_framework_APDU_receiveBytes(JcVm *vm, u16 *a)
{
	u8 st = CARD->state;
	if (st != ST_PARTIAL_INCOMING && st != ST_FULL_INCOMING) return apduErr(vm, AE_ILLEGAL_USE);
	return receive(vm, a, S(1), 255);
}

int jn_framework_APDU_getIncomingLength(JcVm *vm, u16 *a)
{
	RET(CARD->lc);
}

int jn_framework_APDU_getOffsetCdata(JcVm *vm, u16 *a)
{
	RET(CARD->cdata);
}

int jn_framework_APDU_setOutgoing(JcVm *vm, u16 *a)
{
	if (CARD->state >= ST_OUTGOING) return apduErr(vm, AE_ILLEGAL_USE);
	CARD->state = ST_OUTGOING;
	RET(CARD->le);
}

int jn_framework_APDU_setOutgoingNoChaining(JcVm *vm, u16 *a)
{
	return jn_framework_APDU_setOutgoing(vm, a);
}

int jn_framework_APDU_setOutgoingLength(JcVm *vm, u16 *a)
{
	JcCard *c = CARD;
	if (c->state != ST_OUTGOING) return apduErr(vm, AE_ILLEGAL_USE);
	if (S(1) < 0 || S(1) > (c->ext ? JC_EXT - 2 : 256)) return apduErr(vm, AE_BAD_LENGTH);
	c->outExpected = S(1);
	c->state = ST_OUTGOING_LENGTH_KNOWN;
	return 0;
}

static int apduSend(JcVm *vm, const u8 *d, s16 n)
{
	JcCard *c = CARD;
	if (c->state != ST_OUTGOING_LENGTH_KNOWN && c->state != ST_PARTIAL_OUTGOING) return apduErr(vm, AE_ILLEGAL_USE);
	if (n < 0 || c->outLen + n > c->outExpected) return apduErr(vm, AE_ILLEGAL_USE);
	memcpy(c->out + c->outLen, d, n);
	c->outLen += n;
	c->state = c->outLen == c->outExpected ? ST_FULL_OUTGOING : ST_PARTIAL_OUTGOING;
	return 0;
}

int jn_framework_APDU_sendBytes(JcVm *vm, u16 *a)
{
	if (S(1) < 0 || S(2) < 0 || S(1) + S(2) > JC_BUF) return apduErr(vm, AE_BUFFER_BOUNDS);
	return apduSend(vm, jcObj(vm, CARD->buf)->data + S(1), S(2));
}

int jn_framework_APDU_sendBytesLong(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[1], S(2), S(3));
	return d ? apduSend(vm, d, S(3)) : -1;
}

int jn_framework_APDU_setOutgoingAndSend(JcVm *vm, u16 *a)
{
	u16 b[3] = { a[0], a[2] };
	if (jn_framework_APDU_setOutgoing(vm, b) < 0 || jn_framework_APDU_setOutgoingLength(vm, b) < 0) return -1;
	return jn_framework_APDU_sendBytes(vm, a) < 0 ? -1 : 0;
}

int jn_framework_APDU_getCurrentState(JcVm *vm, u16 *a)
{
	RET(CARD->state);
}

int jn_framework_APDU_getNAD(JcVm *vm, u16 *a)
{
	RET(0);
}

int jn_framework_APDU_isCommandChainingCLA(JcVm *vm, u16 *a)
{
	RET((CARD->cmd[0] & 0x10) != 0);
}

int jn_framework_APDU_isSecureMessagingCLA(JcVm *vm, u16 *a)
{
	u8 cla = CARD->cmd[0];
	RET(cla & 0x40 ? (cla & 0x20) != 0 : (cla & 0x0C) != 0);
}

int jn_framework_APDU_isISOInterindustryCLA(JcVm *vm, u16 *a)
{
	RET(!(CARD->cmd[0] & 0x80));
}

int jn_framework_APDU_isValidCLA(JcVm *vm, u16 *a)
{
	RET(CARD->cmd[0] != 0xFF);
}

int jn_framework_APDU_getCLAChannel(JcVm *vm, u16 *a)
{
	RET(0);
}

int jn_framework_APDU_getInBlockSize(JcVm *vm, u16 *a)
{
	RET(0xFE);
}

int jn_framework_APDU_getOutBlockSize(JcVm *vm, u16 *a)
{
	RET(0xFC); // the J3H145's
}

int jn_framework_APDU_getProtocol(JcVm *vm, u16 *a)
{
	RET((s8)0x81); // PROTOCOL_MEDIA_CONTACTLESS_TYPE_A | PROTOCOL_T1
}

int jn_framework_APDU_waitExtension(JcVm *vm, u16 *a)
{
	return 0;
}

// --- javacard.framework.JCSystem ---

static int transientArray(JcVm *vm, u16 *a, u8 type)
{
	if (S(1) != 1 && S(1) != 2) return jcThrow(vm, JCC_framework_SystemException, 1); // ILLEGAL_VALUE
	if (S(0) < 0) return jcThrow(vm, JCC_lang_NegativeArraySizeException, 0);
	u16 h = jcNewArray(vm, type, S(0), 0xFFFF);
	if (!h) return jcThrow(vm, JCC_framework_SystemException, 3);
	jcObj(vm, h)->flags |= S(1) == 1 ? JO_RESET : JO_DESELECT;
	RET(h);
}

int jn_framework_JCSystem_makeTransientByteArray(JcVm *vm, u16 *a)
{
	return transientArray(vm, a, JT_BYTE);
}

int jn_framework_JCSystem_makeTransientBooleanArray(JcVm *vm, u16 *a)
{
	return transientArray(vm, a, JT_BOOLEAN);
}

int jn_framework_JCSystem_makeTransientShortArray(JcVm *vm, u16 *a)
{
	return transientArray(vm, a, JT_SHORT);
}

int jn_framework_JCSystem_makeTransientObjectArray(JcVm *vm, u16 *a)
{
	return transientArray(vm, a, JT_REF);
}

int jn_framework_JCSystem_isTransient(JcVm *vm, u16 *a)
{
	JcObj *o = jcObj(vm, a[0]);
	RET(o && o->type != JT_INSTANCE ? o->flags & (JO_RESET | JO_DESELECT) : 0);
}

int jn_framework_JCSystem_beginTransaction(JcVm *vm, u16 *a)
{
	if (vm->njournal >= 0) return jcThrow(vm, JCC_framework_TransactionException, 1); // IN_PROGRESS
	jcBeginTransaction(vm);
	return 0;
}

int jn_framework_JCSystem_commitTransaction(JcVm *vm, u16 *a)
{
	if (vm->njournal < 0) return jcThrow(vm, JCC_framework_TransactionException, 2); // NOT_IN_PROGRESS
	jcCommit(vm);
	return 0;
}

int jn_framework_JCSystem_abortTransaction(JcVm *vm, u16 *a)
{
	if (vm->njournal < 0) return jcThrow(vm, JCC_framework_TransactionException, 2);
	jcAbort(vm);
	return 0;
}

int jn_framework_JCSystem_getTransactionDepth(JcVm *vm, u16 *a)
{
	RET(vm->njournal >= 0);
}

int jn_framework_JCSystem_getMaxCommitCapacity(JcVm *vm, u16 *a)
{
	RET(JC_JOURNAL * 4);
}

int jn_framework_JCSystem_getUnusedCommitCapacity(JcVm *vm, u16 *a)
{
	RET(vm->njournal < 0 ? JC_JOURNAL * 4 : (JC_JOURNAL - vm->njournal) * 4);
}

int jn_framework_JCSystem_getAvailableMemory_B(JcVm *vm, u16 *a)
{
	RET(0x7FFF);
}

int jn_framework_JCSystem_getAvailableMemory_aSSB(JcVm *vm, u16 *a)
{
	JcObj *o = jcObj(vm, a[0]);
	if (!o) return jcThrow(vm, JCC_lang_NullPointerException, 0);
	if (o->type != JT_SHORT || S(1) < 0 || S(1) + 2 > o->len) return jcThrow(vm, JCC_lang_ArrayIndexOutOfBoundsException, 0);
	s16 v[2] = { 0, 0x7FFF };
	jcStore(vm, a[0], 2 * S(1), v, 4);
	return 0;
}

int jn_framework_JCSystem_getVersion(JcVm *vm, u16 *a)
{
	RET(0x0304);
}

int jn_framework_JCSystem_getAID(JcVm *vm, u16 *a)
{
	JcCard *c = CARD;
	RET(c->context >= 0 ? c->applets[c->context].aidObj : 0);
}

int jn_framework_JCSystem_getPreviousContextAID(JcVm *vm, u16 *a)
{
	RET(0);
}

int jn_framework_JCSystem_lookupAID(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[0], S(1), (s8)a[2]);
	if (!d) return -1;
	JcCard *c = CARD;
	for (int i = 0; i < c->napplets; i++)
		if (c->applets[i].aidLen == (s8)a[2] && !memcmp(c->applets[i].aid, d, (s8)a[2])) RET(c->applets[i].aidObj);
	RET(0);
}

int jn_framework_JCSystem_isAppletActive(JcVm *vm, u16 *a)
{
	JcCard *c = CARD;
	RET(c->selected >= 0 && c->applets[c->selected].aidObj == a[0]);
}

int jn_framework_JCSystem_isObjectDeletionSupported(JcVm *vm, u16 *a)
{
	RET(0);
}

int jn_framework_JCSystem_requestObjectDeletion(JcVm *vm, u16 *a)
{
	return 0;
}

int jn_framework_JCSystem_getAssignedChannel(JcVm *vm, u16 *a)
{
	RET(0);
}

// --- javacard.framework.Util ---

int jn_framework_Util_arrayCompare(JcVm *vm, u16 *a)
{
	u8 *x = jcBytes(vm, a[0], S(1), S(4)), *y = x ? jcBytes(vm, a[2], S(3), S(4)) : NULL;
	if (!y) return -1;
	for (s16 i = 0; i < S(4); i++)
		if (x[i] != y[i]) RET((s8)x[i] < (s8)y[i] ? -1 : 1);
	RET(0);
}

static int copy(JcVm *vm, u16 *a, bool atomic)
{
	u8 *src = jcBytes(vm, a[0], S(1), S(4));
	if (!src || !jcObj(vm, a[2]) || !jcPut(vm, a[2], S(3), src, S(4), atomic)) {
		if (!vm->exc) jcThrow(vm, JCC_lang_NullPointerException, 0);
		return -1;
	}
	RET(S(3) + S(4));
}

int jn_framework_Util_arrayCopy(JcVm *vm, u16 *a)
{
	return copy(vm, a, true);
}

int jn_framework_Util_arrayCopyNonAtomic(JcVm *vm, u16 *a)
{
	return copy(vm, a, false);
}

int jn_framework_Util_arrayFillNonAtomic(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[0], S(1), S(2));
	if (!d) return -1;
	memset(d, (u8)a[3], S(2));
	RET(S(1) + S(2));
}

int jn_framework_Util_getShort(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[0], S(1), 2);
	if (!d) return -1;
	RET(d[0] << 8 | d[1]);
}

int jn_framework_Util_makeShort(JcVm *vm, u16 *a)
{
	RET((a[0] & 0xFF) << 8 | (a[1] & 0xFF));
}

int jn_framework_Util_setShort(JcVm *vm, u16 *a)
{
	u8 v[2] = { a[2] >> 8, a[2] };
	if (!jcPut(vm, a[0], S(1), v, 2, true)) return -1;
	RET(S(1) + 2);
}

// --- javacard.framework.AID ---

int jn_framework_AID_init(JcVm *vm, u16 *a)
{
	s8 n = a[3];
	u8 *d = jcBytes(vm, a[1], S(2), n);
	if (!d) return -1;
	if (n < 5 || n > 16) return jcThrow(vm, JCC_framework_SystemException, 1);
	NatAid *x = jcNat(vm, a[0]);
	x->len = n;
	memcpy(x->aid, d, n);
	return 0;
}

int jn_framework_AID_equals_Object(JcVm *vm, u16 *a)
{
	JcObj *o = jcObj(vm, a[1]);
	if (!o || o->type != JT_INSTANCE || o->cls != JCC_framework_AID) RET(0);
	NatAid *x = jcNat(vm, a[0]), *y = jcNat(vm, a[1]);
	RET(x->len == y->len && !memcmp(x->aid, y->aid, x->len));
}

int jn_framework_AID_equals_aBSB(JcVm *vm, u16 *a)
{
	NatAid *x = jcNat(vm, a[0]);
	if (!a[1]) RET(0);
	u8 *d = jcBytes(vm, a[1], S(2), (s8)a[3]);
	if (!d) return -1;
	RET(x->len == (s8)a[3] && !memcmp(x->aid, d, x->len));
}

int jn_framework_AID_partialEquals(JcVm *vm, u16 *a)
{
	NatAid *x = jcNat(vm, a[0]);
	if (!a[1]) RET(0);
	u8 *d = jcBytes(vm, a[1], S(2), (s8)a[3]);
	if (!d) return -1;
	RET((s8)a[3] <= x->len && !memcmp(x->aid, d, (s8)a[3]));
}

int jn_framework_AID_RIDEquals(JcVm *vm, u16 *a)
{
	if (!jcObj(vm, a[1])) RET(0);
	NatAid *x = jcNat(vm, a[0]), *y = jcNat(vm, a[1]);
	RET(y && !memcmp(x->aid, y->aid, 5));
}

int jn_framework_AID_getBytes(JcVm *vm, u16 *a)
{
	NatAid *x = jcNat(vm, a[0]);
	if (!jcPut(vm, a[1], S(2), x->aid, x->len, true)) return -1;
	RET(x->len);
}

int jn_framework_AID_getPartialBytes(JcVm *vm, u16 *a)
{
	NatAid *x = jcNat(vm, a[0]);
	s16 from = S(1), n = (s8)a[4];
	if (from < 0 || from > x->len) return jcThrow(vm, JCC_lang_ArrayIndexOutOfBoundsException, 0);
	if (!n || n > x->len - from) n = x->len - from;
	if (!jcPut(vm, a[2], S(3), x->aid + from, n, true)) return -1;
	RET(n);
}

// --- javacard.framework.OwnerPIN (and the PIN interface) ---

static NatPin *pinOf(JcVm *vm, u16 h)
{
	JcObj *o = jcObj(vm, h);
	return o && o->type == JT_INSTANCE && o->natLen == sizeof(NatPin) ? jcNat(vm, h) : NULL;
}

static u8 *validated(JcVm *vm, NatPin *p)
{
	return jcObj(vm, p->validated)->data;
}

static void pinSet(JcVm *vm, u16 h, size_t field, const void *v, u8 len)
{
	jcStore(vm, h, jcNatOff(jcObj(vm, h)->len) + field, v, len);
}

int jn_framework_OwnerPIN_init(JcVm *vm, u16 *a)
{
	s8 tries = a[1], size = a[2];
	if (tries < 1 || size < 1) return jcThrow(vm, JCC_framework_PINException, 1); // ILLEGAL_VALUE
	if (size > 32) return jcThrow(vm, JCC_framework_PINException, 1);
	NatPin *p = jcNat(vm, a[0]);
	u16 v = jcNewArray(vm, JT_BOOLEAN, 1, 0);
	if (!v) return jcThrow(vm, JCC_framework_SystemException, 3);
	jcObj(vm, v)->flags |= JO_RESET;
	p = jcNat(vm, a[0]);
	p->limit = p->tries = tries, p->size = size, p->len = 0, p->validated = v;
	return 0;
}

int jn_framework_OwnerPIN_check(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	if (!p) return jcThrow(vm, JCC_lang_NullPointerException, 0);
	validated(vm, p)[0] = 0;
	if (!p->tries) RET(0);
	s8 n = a[3];
	u8 *d = jcBytes(vm, a[1], S(2), n);
	if (!d) return -1;
	u8 t = p->tries - 1;
	pinSet(vm, a[0], offsetof(NatPin, tries), &t, 1); // counted before the compare
	if (n != p->len || memcmp(d, p->pin, n)) RET(0);
	pinSet(vm, a[0], offsetof(NatPin, tries), &p->limit, 1);
	validated(vm, p)[0] = 1;
	RET(1);
}

int jn_framework_OwnerPIN_getTriesRemaining(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	RET(p ? p->tries : 0);
}

int jn_framework_OwnerPIN_isValidated(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	RET(p && validated(vm, p)[0]);
}

int jn_framework_OwnerPIN_getValidatedFlag(JcVm *vm, u16 *a)
{
	return jn_framework_OwnerPIN_isValidated(vm, a);
}

int jn_framework_OwnerPIN_setValidatedFlag(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	if (p) validated(vm, p)[0] = a[1] & 1;
	return 0;
}

int jn_framework_OwnerPIN_reset(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	if (p && validated(vm, p)[0]) pinSet(vm, a[0], offsetof(NatPin, tries), &p->limit, 1);
	if (p) validated(vm, p)[0] = 0;
	return 0;
}

int jn_framework_OwnerPIN_resetAndUnblock(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	if (p) {
		pinSet(vm, a[0], offsetof(NatPin, tries), &p->limit, 1);
		validated(vm, p)[0] = 0;
	}
	return 0;
}

int jn_framework_OwnerPIN_update(JcVm *vm, u16 *a)
{
	NatPin *p = pinOf(vm, a[0]);
	s8 n = a[3];
	u8 *d = jcBytes(vm, a[1], S(2), n);
	if (!p || !d) return -1;
	if (n > p->size) return jcThrow(vm, JCC_framework_PINException, 1);
	u8 len = n;
	pinSet(vm, a[0], offsetof(NatPin, pin), d, n);
	pinSet(vm, a[0], offsetof(NatPin, len), &len, 1);
	pinSet(vm, a[0], offsetof(NatPin, tries), &p->limit, 1);
	validated(vm, p)[0] = 0;
	return 0;
}

int jn_framework_PIN_check(JcVm *vm, u16 *a)
{
	return jn_framework_OwnerPIN_check(vm, a);
}

int jn_framework_PIN_getTriesRemaining(JcVm *vm, u16 *a)
{
	return jn_framework_OwnerPIN_getTriesRemaining(vm, a);
}

int jn_framework_PIN_isValidated(JcVm *vm, u16 *a)
{
	return jn_framework_OwnerPIN_isValidated(vm, a);
}

int jn_framework_PIN_reset(JcVm *vm, u16 *a)
{
	return jn_framework_OwnerPIN_reset(vm, a);
}

// --- javacard.security.RandomData (the rest of the crypto: jccrypto.c) ---

int jn_security_RandomData_getInstance(JcVm *vm, u16 *a)
{
	if ((s8)a[0] != 1 && (s8)a[0] != 2) return jcThrow(vm, JCC_security_CryptoException, 3);
	u16 h = jcNew(vm, JCC_security_RandomData);
	if (!h) return jcThrow(vm, JCC_framework_SystemException, 3);
	RET(h);
}

int jn_security_RandomData_generateData(JcVm *vm, u16 *a)
{
	u8 *d = jcBytes(vm, a[1], S(2), S(3));
	if (!d) return -1;
	jcRandom(d, S(3));
	return 0;
}

int jn_security_RandomData_setSeed(JcVm *vm, u16 *a)
{
	return jcBytes(vm, a[1], S(2), S(3)) ? 0 : -1;
}
