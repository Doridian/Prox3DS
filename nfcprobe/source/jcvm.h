#pragma once
#include <3ds.h>
#include <stdint.h>

// Java Card virtual machine (issue #19; the Python prototype in tools/jcvm/ is the reference): CAP files
// loaded into packages and classes (library packages too, linked by their Export component), the API in C
// (jcapi.c) linked by the export file tokens
// (jcapitab.c, tools/gen_jcapi.py), a heap of objects behind 16-bit handles, the bytecode interpreter.
// Cells are 16 bits; an int takes two (high word first), a reference is a handle (0 = null).
// The card around it (applets, SELECT, APDUs, saving the heap) is jccard.c.

#define JC_PKGS    12   // loaded CAP packages
#define JC_CLASSES 512  // API + CAP classes
#define JC_OBJS    4096 // handles
#define JC_STACK   4096 // cells for all frames
#define JC_FRAMES  96
#define JC_JOURNAL 1024 // transaction undo entries
#define JC_APPLETS 16

// newarray element types, and object types
enum { JT_INSTANCE = 0, JT_BOOLEAN = 10, JT_BYTE = 11, JT_SHORT = 12, JT_INT = 13, JT_REF = 14 };
// object flags: transient (JCSystem.CLEAR_ON_RESET / _DESELECT), system-owned (not saved)
enum { JO_RESET = 1, JO_DESELECT = 2, JO_SYSTEM = 4 };

typedef struct JcVm JcVm;

// A native method: a = its argument cells (this first). Writes the result cells at a[0] and returns how
// many (0-2), or -1 after jcThrow.
typedef int (*JcNative)(JcVm *vm, u16 *a);

typedef struct {
	u8 token, nargs; // nargs in cells, this included
	JcNative fn;     // NULL: not implemented
	const char *name;
} JcNativeMethod;

typedef struct {
	const char *name;
	u8 token;
	s16 super; // jcApiClasses index, -1: none
	u8 interface;
	const s16 *ifaces; // -1 terminated
	const JcNativeMethod *vm;
	u8 nvm;
	const JcNativeMethod *sm; // static methods and constructors
	u8 nsm;
} JcApiClass;

typedef struct {
	const u8 *aid;
	u8 aidLen, major, minor;
	u16 first, count; // jcApiClasses[first .. first + count)
} JcApiPkg;

#include "jcapitab.h"
extern const JcApiClass jcApiClasses[JC_API_CLASSES];
extern const JcApiPkg jcApiPkgs[JC_API_PKGS];

// A constant pool entry, resolved at load.
typedef struct {
	u8 tag;      // 1 class, 2 instance field, 3 virtual method, 4 super method, 5 static field, 6 static method
	u8 token;    // methods
	s16 cls;     // class index (classes, fields, virtual / super methods)
	s8 pkg;      // static fields and methods: the package (this one or a library)
	u16 off;     // instance field: cell offset; static field: image offset (pkg's); static method: method offset
	const JcNativeMethod *nat; // static method / constructor of the API
} JcCp;

typedef struct {
	u8 aid[16], aidLen, major, minor;
	char path[128];        // the CAP file ("" = deleted: not saved)
	u8 *mem;               // the components, one allocation
	u8 *comp[12];          // components by tag (data after tag and size), in mem
	u16 compLen[12];
	u8 nimports;
	s16 imports[16];       // package token -> JC_API_PKGS + loaded index, or API package index
	JcCp *cp;
	u16 ncp;
	u16 classBase, nclasses; // class indices; Class component offset -> index via classOff
	u16 *classOff;
	u16 *srefs;            // reference statics (handles)
	u16 nsrefs;
	u8 *sprims;            // primitive statics (big-endian, as in the image)
	u16 nsprims;
} JcPkg;

typedef struct {
	const JcApiClass *api; // NULL: from a CAP
	s16 pkg;               // CAP package index (-1: API)
	s16 super;             // class index, -1: none
	u16 size;              // instance cells, supers included
	u16 natSize;           // native state bytes (from the API base class)
	u8 interface;
	u8 pubBase, pubCount, pkgBase, pkgCount;
	const u8 *pubVmt, *pkgVmt; // big-endian method offsets, FFFF = inherited
	const u8 *ifaces;      // CAP: interfaces (class_ref, count, tokens...) / superinterfaces (class_ref...)
	u8 nifaces;
} JcClass;

typedef struct {
	u16 cls;   // instance: class; reference array: element class (0xFFFF: any)
	u8 type;   // JT_*
	u8 flags;  // JO_*
	u16 len;   // array length; instance: cells
	u16 natLen;
	u8 *data;  // array elements (u8 / s16 / s32 / u16 handles) or cells (u16) then native state
} JcObj;

typedef struct {
	const u8 *m; // method header
	const u8 *code;
	u16 pc;      // offset in the Method component of the instruction running (or the invoke out)
	s16 pkg;
	u16 base;    // locals start (cells), the operand stack follows them
	u16 sp;
} JcFrame;

struct JcVm {
	JcPkg pkgs[JC_PKGS];
	u8 npkgs;
	JcClass classes[JC_CLASSES];
	u16 nclasses;
	JcObj objs[JC_OBJS]; // handle h = objs[h - 1]
	u16 stack[JC_STACK];
	JcFrame frames[JC_FRAMES];
	u8 nframes;
	u16 exc;             // the exception in flight, 0 = none
	u16 sysExc[JC_API_CLASSES]; // one system-owned instance per API exception class
	struct { u8 kind, len; u16 h; u32 off, old; } journal[JC_JOURNAL];
	s16 njournal;        // -1: no transaction
	u32 steps;
	char why[96];        // why the last call failed (not a Java exception: a VM limit, a bad CAP)
	void *card;          // jccard.c
};

void jcInit(JcVm *vm); // the API classes; no packages, no objects
void jcFree(JcVm *vm); // every package and object
// Loads a CAP file (its bytes); the package index, -1 = can't (vm->why).
int jcLoadCap(JcVm *vm, const u8 *cap, u32 len, const char *path);
int jcFindPkg(JcVm *vm, const u8 *aid, u8 aidLen);

// Objects. 0 = out of memory.
u16 jcNew(JcVm *vm, u16 cls);
u16 jcNewArray(JcVm *vm, u8 type, u16 len, u16 elemCls);
static inline JcObj *jcObj(JcVm *vm, u16 h)
{
	return h && h <= JC_OBJS && vm->objs[h - 1].data ? &vm->objs[h - 1] : NULL;
}
// An instance's native state starts after its cells, 8-aligned (ARM: LDRD / STRD on u64 fields).
static inline u32 jcNatOff(u16 cells)
{
	return (2u * cells + 7) & ~7u;
}
// An object's data size in bytes.
static inline u32 jcObjSize(const JcObj *o)
{
	if (o->type == JT_INSTANCE) return jcNatOff(o->len) + o->natLen;
	return (u32)o->len * (o->type == JT_SHORT || o->type == JT_REF ? 2 : o->type == JT_INT ? 4 : 1);
}
void *jcNat(JcVm *vm, u16 h); // an object's native state
// For natives (jcapi.c): a[off .. off + len) of a byte (or boolean) array, NULL after throwing; jcPut copies
// into one (atomic: through the transaction journal), false after throwing.
u8 *jcBytes(JcVm *vm, u16 h, s16 off, s16 len);
bool jcPut(JcVm *vm, u16 h, s16 off, const u8 *src, s16 len, bool atomic);
bool jcSubclass(JcVm *vm, int cls, int of);
bool jcInstanceOf(JcVm *vm, u16 h, int cls);

// Runs a method (CAP method offset in pkg, or a native) with nargs argument cells; the return cells into
// ret (if not NULL). 1 = returned, 0 = a Java exception came out (vm->exc), -1 = the VM failed (vm->why).
int jcCall(JcVm *vm, int pkg, u16 methodOff, const u16 *args, int nargs, u16 *ret);
// The method a virtual token of cls resolves to: pkg + method offset, or a native. false = none.
bool jcVirtual(JcVm *vm, int cls, u8 token, int *pkg, u16 *off, const JcNativeMethod **nat);
// The same for a virtual method of the object in args[0] (applet select / process / deselect).
int jcInvokeVirtual(JcVm *vm, u8 token, const u16 *args, int nargs, u16 *ret);

// Throws an instance of an API exception class (JCC_*) with a reason; returns -1 for natives to pass on.
int jcThrow(JcVm *vm, int apiCls, s16 reason);
s16 jcReason(JcVm *vm, u16 h); // CardException / CardRuntimeException reason

// Writes to persistent memory (the transaction journal sees them).
void jcStore(JcVm *vm, u16 h, u32 off, const void *v, u8 len);
void jcBeginTransaction(JcVm *vm);
void jcCommit(JcVm *vm);
void jcAbort(JcVm *vm);
void jcClearTransients(JcVm *vm, u8 event);
void jcClearObj(JcObj *o); // a transient object's contents (an instance: its native state, jcNatClear)

// The native state size of an API class's instances, and clearing a transient one (a transient key) (jcapi.c).
u16 jcNatSize(int apiCls);
void jcNatClear(int apiCls, void *nat);
