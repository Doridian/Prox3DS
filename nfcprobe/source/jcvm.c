// Java Card virtual machine: CAP loading, objects, the interpreter. See jcvm.h; the Python prototype
// (tools/jcvm/vm.py) is the reference, NOTES.md "Java Card VM" has the CAP / JCVM details.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jcvm.h"
#include "zip.h"

#define ACC_INTERFACE 0x8
#define ACC_EXTENDED  0x8
#define ACC_ABSTRACT  0x4

enum { CP_CLASS = 1, CP_IFIELD, CP_VMETHOD, CP_SUPERMETHOD, CP_SFIELD, CP_SMETHOD };
enum { JE_OBJ, JE_SPRIM, JE_SREF };

static u16 be16(const u8 *p)
{
	return p[0] << 8 | p[1];
}

static s16 sbe16(const u8 *p)
{
	return (s16)(p[0] << 8 | p[1]);
}

static int fail(JcVm *vm, const char *fmt, const char *arg)
{
	snprintf(vm->why, sizeof(vm->why), fmt, arg);
	return -1;
}

void jcInit(JcVm *vm)
{
	memset(vm, 0, sizeof(*vm));
	vm->njournal = -1;
	for (int i = 0; i < JC_API_CLASSES; i++) {
		JcClass *c = &vm->classes[i];
		c->api = &jcApiClasses[i];
		c->pkg = -1;
		c->super = c->api->super;
		c->interface = c->api->interface;
		c->natSize = jcNatSize(i);
	}
	vm->nclasses = JC_API_CLASSES;
}

void jcFree(JcVm *vm)
{
	for (int i = 0; i < JC_OBJS; i++) free(vm->objs[i].data);
	for (int i = 0; i < vm->npkgs; i++) {
		JcPkg *p = &vm->pkgs[i];
		free(p->mem), free(p->cp), free(p->classOff), free(p->srefs), free(p->sprims);
	}
	jcInit(vm);
}

// --- loading ---

typedef struct {
	const u8 *zip;
	u32 len;
	u8 *buf;
	u32 used;
	JcPkg *p;
	bool bad;
} Extract;

static bool takeComp(const ZipEntry *e, void *ctx)
{
	Extract *x = ctx;
	u32 n = strlen(e->name);
	if (n < 4 || strcmp(e->name + n - 4, ".cap") || e->size < 3) return true;
	u8 *d = x->buf + x->used;
	if (!zipExtract(x->zip, x->len, e, d)) {
		x->bad = true;
		return false;
	}
	u8 tag = d[0];
	u32 len = be16(d + 1);
	if (tag >= 1 && tag < 12 && len + 3 <= e->size) {
		x->p->comp[tag] = d + 3;
		x->p->compLen[tag] = len;
	}
	x->used += e->size;
	return true;
}

static bool sizeCaps(const ZipEntry *e, void *ctx)
{
	u32 n = strlen(e->name);
	if (n >= 4 && !strcmp(e->name + n - 4, ".cap")) *(u32 *)ctx += e->size;
	return true;
}

// A library package's Export component: class token tok's class_export_info (class offset, static field
// and method counts, their offsets); NULL = no such class.
static const u8 *exportClass(const JcPkg *q, int tok)
{
	const u8 *e = q->comp[10];
	if (!e || q->compLen[10] < 1 || tok >= e[0]) return NULL;
	const u8 *end = e + q->compLen[10];
	e++;
	for (int i = 0; i < tok && e + 4 <= end; i++) e += 4 + 2 * (e[2] + e[3]);
	return e + 4 <= end && e + 4 + 2 * (e[2] + e[3]) <= end ? e : NULL;
}

// A class_ref of package p -> class index; -1 = unknown.
static int classRef(JcVm *vm, const JcPkg *p, u16 ref)
{
	if (!(ref & 0x8000)) {
		for (int i = 0; i < p->nclasses; i++)
			if (p->classOff[i] == ref) return p->classBase + i;
		return -1;
	}
	int t = (ref >> 8) & 0x7F, tok = ref & 0xFF;
	if (t >= p->nimports) return -1;
	int ip = p->imports[t];
	if (ip < JC_API_PKGS) {
		const JcApiPkg *a = &jcApiPkgs[ip];
		for (int i = a->first; i < a->first + a->count; i++)
			if (jcApiClasses[i].token == tok) return i;
		return -1;
	}
	const JcPkg *q = &vm->pkgs[ip - JC_API_PKGS];
	const u8 *x = exportClass(q, tok);
	for (int i = 0; x && i < q->nclasses; i++)
		if (q->classOff[i] == be16(x)) return q->classBase + i;
	return -1;
}

// Instance cells (supers included) and native state size of class ci of the package being loaded; its
// size holds the declared cells until done[] says otherwise.
static void sizeClass(JcVm *vm, const JcPkg *p, int ci, bool *done, int depth)
{
	JcClass *k = &vm->classes[ci];
	int i = ci - p->classBase;
	if (done[i] || depth > 64) return;
	done[i] = true;
	if (k->interface) return;
	int s = k->super;
	if (s >= 0 && !vm->classes[s].api) {
		if (s >= p->classBase && s < p->classBase + p->nclasses) sizeClass(vm, p, s, done, depth + 1);
		k->size += vm->classes[s].size;
		k->natSize = vm->classes[s].natSize;
	} else {
		k->natSize = s >= 0 ? vm->classes[s].natSize : 0;
	}
}

int jcFindPkg(JcVm *vm, const u8 *aid, u8 aidLen)
{
	for (int i = 0; i < vm->npkgs; i++)
		if (vm->pkgs[i].aidLen == aidLen && !memcmp(vm->pkgs[i].aid, aid, aidLen)) return i;
	return -1;
}

int jcLoadCap(JcVm *vm, const u8 *zip, u32 zlen, const char *path)
{
	if (vm->npkgs >= JC_PKGS) return fail(vm, "%s", "too many packages");
	JcPkg *p = &vm->pkgs[vm->npkgs];
	memset(p, 0, sizeof(*p));
	u32 total = 0;
	if (zipList(zip, zlen, sizeCaps, &total) < 0 || !total) return fail(vm, "%s", "not a CAP file");
	Extract x = { zip, zlen, malloc(total), 0, p, false };
	if (!x.buf) return fail(vm, "%s", "out of memory");
	zipList(zip, zlen, takeComp, &x);
	const u8 *h = p->comp[1];
	p->mem = x.buf;
	if (x.bad || !h || p->compLen[1] < 10 || be16(h) != 0xDECA || be16(h + 2) != 0xFFED || !p->comp[4] ||
		!p->comp[5] || !p->comp[6] || !p->comp[7] || !p->comp[8]) {
		free(x.buf);
		return fail(vm, "%s", "not a CAP file (components missing)");
	}
	snprintf(p->path, sizeof(p->path), "%s", path ? path : "");
	u8 capMinor = h[4], capMajor = h[5];
	p->minor = h[7], p->major = h[8];
	p->aidLen = h[9] > 16 ? 16 : h[9];
	memcpy(p->aid, h + 10, p->aidLen);
	if (jcFindPkg(vm, p->aid, p->aidLen) >= 0) {
		free(x.buf);
		return fail(vm, "%s", "package already loaded");
	}
	// imports: API packages, then library packages loaded before (a major version that matches, a minor at
	// least as new as needed)
	const u8 *im = p->comp[4];
	p->nimports = im[0];
	if (p->nimports > 16) {
		free(x.buf);
		return fail(vm, "%s", "too many imports");
	}
	for (int i = 0, o = 1; i < p->nimports; i++) {
		u8 minor = im[o], major = im[o + 1], alen = im[o + 2];
		const u8 *aid = im + o + 3;
		p->imports[i] = -1;
		for (int k = 0; k < JC_API_PKGS; k++)
			if (jcApiPkgs[k].aidLen == alen && !memcmp(jcApiPkgs[k].aid, aid, alen) && jcApiPkgs[k].major == major &&
				jcApiPkgs[k].minor >= minor)
				p->imports[i] = k;
		for (int k = 0; k < vm->npkgs && p->imports[i] < 0; k++) {
			const JcPkg *q = &vm->pkgs[k];
			if (q->aidLen == alen && !memcmp(q->aid, aid, alen) && q->major == major && q->minor >= minor)
				p->imports[i] = JC_API_PKGS + k;
		}
		if (p->imports[i] < 0) {
			char hex[40];
			for (int k = 0; k < alen && k < 16; k++) sprintf(hex + 2 * k, "%02X", aid[k]);
			free(x.buf);
			return fail(vm, "imports %s (not available)", hex);
		}
		o += 3 + alen;
	}
	// classes
	const u8 *cc = p->comp[6], *ce = cc + p->compLen[6];
	if (capMajor > 2 || (capMajor == 2 && capMinor >= 2)) cc += 2 + be16(cc); // signature pool
	u16 offs[256];
	const u8 *start = p->comp[6];
	p->classBase = vm->nclasses;
	for (const u8 *c = cc; c < ce;) {
		if (vm->nclasses >= JC_CLASSES || p->nclasses >= 256) {
			free(x.buf);
			return fail(vm, "%s", "too many classes");
		}
		JcClass *k = &vm->classes[vm->nclasses++];
		memset(k, 0, sizeof(*k));
		k->pkg = vm->npkgs;
		offs[p->nclasses++] = c - start;
		u8 flags = c[0] >> 4, nif = c[0] & 0xF;
		k->interface = flags & ACC_INTERFACE;
		k->nifaces = nif;
		if (k->interface) {
			k->super = JCC_lang_Object;
			k->ifaces = c + 1;
			c += 1 + 2 * nif;
			if (flags & 0x2) c += 1 + c[0]; // remote: interface name
			continue;
		}
		k->super = be16(c + 1); // resolved below
		k->size = c[3];         // declared: supers added below
		k->pubBase = c[6], k->pubCount = c[7], k->pkgBase = c[8], k->pkgCount = c[9];
		k->pubVmt = c + 10;
		k->pkgVmt = k->pubVmt + 2 * k->pubCount;
		k->ifaces = k->pkgVmt + 2 * k->pkgCount;
		c = k->ifaces;
		for (int i = 0; i < nif; i++) c += 3 + c[2];
		if (flags & 0x2) {
			free(x.buf);
			return fail(vm, "%s", "remote classes");
		}
	}
	p->classOff = malloc(2 * p->nclasses);
	memcpy(p->classOff, offs, 2 * p->nclasses);
	vm->npkgs++; // classRef needs it in place; undone on failure below
	// supers, then sizes in order (a super from this package may come later in the component)
	for (int i = 0; i < p->nclasses; i++) {
		JcClass *k = &vm->classes[p->classBase + i];
		if (k->interface) continue;
		u16 ref = k->super;
		k->super = ref == 0xFFFF ? -1 : classRef(vm, p, ref);
		if (ref != 0xFFFF && k->super < 0) goto badref;
	}
	{
		bool done[256] = { false };
		for (int i = 0; i < p->nclasses; i++) sizeClass(vm, p, p->classBase + i, done, 0);
	}
	// constant pool
	const u8 *cp = p->comp[5];
	p->ncp = be16(cp);
	p->cp = calloc(p->ncp ? p->ncp : 1, sizeof(JcCp));
	for (int i = 0; i < p->ncp; i++) {
		const u8 *e = cp + 2 + 4 * i;
		JcCp *r = &p->cp[i];
		r->tag = e[0];
		r->pkg = vm->npkgs - 1;
		switch (e[0]) {
		case CP_CLASS:
			if ((r->cls = classRef(vm, p, be16(e + 1))) < 0) goto badref;
			break;
		case CP_IFIELD:
			if ((r->cls = classRef(vm, p, be16(e + 1))) < 0) goto badref;
			{
				// the token is a cell index in the declaring class, after its supers' cells
				int s = vm->classes[r->cls].super;
				r->off = e[3] + (s >= 0 && !vm->classes[s].api ? vm->classes[s].size : 0);
			}
			break;
		case CP_VMETHOD:
		case CP_SUPERMETHOD:
			if ((r->cls = classRef(vm, p, be16(e + 1))) < 0) goto badref;
			r->token = e[3];
			break;
		case CP_SFIELD:
		case CP_SMETHOD:
			if (e[1] & 0x80 && (e[1] & 0x7F) < p->nimports && p->imports[e[1] & 0x7F] >= JC_API_PKGS) {
				// a library package's: its offsets from the Export component (static fields: in its image)
				int ip = p->imports[e[1] & 0x7F] - JC_API_PKGS;
				const u8 *x = exportClass(&vm->pkgs[ip], e[2]);
				int k = e[0] == CP_SFIELD ? e[3] : x ? x[2] + e[3] : 0;
				if (!x || e[3] >= (e[0] == CP_SFIELD ? x[2] : x[3])) goto badref;
				r->cls = -1;
				r->pkg = ip;
				r->off = be16(x + 4 + 2 * k);
			} else if (e[1] & 0x80) {
				if ((r->cls = classRef(vm, p, 0x8000 | (e[1] & 0x7F) << 8 | e[2])) < 0) goto badref;
				r->token = e[3];
				if (e[0] == CP_SMETHOD) {
					const JcApiClass *a = vm->classes[r->cls].api;
					for (int k = 0; a && k < a->nsm; k++)
						if (a->sm[k].token == r->token) r->nat = &a->sm[k];
					if (!r->nat) goto badref;
				}
			} else {
				r->cls = -1;
				r->off = be16(e + 2);
			}
			break;
		default:
			goto badref;
		}
	}
	// static field image: references (array_init arrays first), defaults, non-defaults
	{
		const u8 *s = p->comp[8];
		u16 size = be16(s), nrefs = be16(s + 2), ninit = be16(s + 4);
		p->nsrefs = nrefs;
		p->srefs = calloc(nrefs ? nrefs : 1, 2);
		p->nsprims = size - 2 * nrefs;
		p->sprims = calloc(p->nsprims ? p->nsprims : 1, 1);
		const u8 *a = s + 6;
		for (int i = 0; i < ninit && i < nrefs; i++) {
			static const u8 types[] = { 0, 0, JT_BOOLEAN, JT_BYTE, JT_SHORT, JT_INT };
			u8 t = a[0] < 6 ? types[a[0]] : 0;
			u16 n = be16(a + 1);
			u8 esz = t == JT_SHORT ? 2 : t == JT_INT ? 4 : 1;
			u16 h = t ? jcNewArray(vm, t, n / esz, 0) : 0;
			if (!h) goto nomem;
			JcObj *o = jcObj(vm, h);
			for (int k = 0; k < n / esz; k++) {
				if (t == JT_SHORT) ((s16 *)o->data)[k] = sbe16(a + 3 + 2 * k);
				else if (t == JT_INT) ((int32_t *)o->data)[k] = (int32_t)(be16(a + 3 + 4 * k) << 16 | be16(a + 5 + 4 * k));
				else o->data[k] = a[3 + k];
			}
			p->srefs[i] = h;
			a += 3 + n;
		}
		u16 ndef = be16(a), nnon = be16(a + 2);
		if (ndef + nnon <= p->nsprims) memcpy(p->sprims + ndef, a + 4, nnon);
	}
	return vm->npkgs - 1;
badref:
	vm->npkgs--;
	vm->nclasses = p->classBase;
	free(x.buf);
	return fail(vm, "%s", "a reference the VM can't resolve");
nomem:
	vm->npkgs--;
	vm->nclasses = p->classBase;
	free(x.buf);
	return fail(vm, "%s", "out of memory");
}

// --- objects ---

static u16 alloc(JcVm *vm, u32 bytes)
{
	static u16 hint;
	for (int n = 0; n < JC_OBJS; n++) {
		u16 i = (hint + n) % JC_OBJS;
		if (!vm->objs[i].data) {
			u8 *d = calloc(bytes ? bytes : 1, 1);
			if (!d) break;
			memset(&vm->objs[i], 0, sizeof(JcObj));
			vm->objs[i].data = d;
			hint = i + 1;
			return i + 1;
		}
	}
	return 0;
}

u16 jcNew(JcVm *vm, u16 cls)
{
	JcClass *c = &vm->classes[cls];
	u16 h = alloc(vm, jcNatOff(c->size) + c->natSize);
	if (!h) return 0;
	JcObj *o = &vm->objs[h - 1];
	o->cls = cls, o->type = JT_INSTANCE, o->len = c->size, o->natLen = c->natSize;
	return h;
}

static u8 elemSize(u8 type)
{
	return type == JT_SHORT || type == JT_REF ? 2 : type == JT_INT ? 4 : 1;
}

u16 jcNewArray(JcVm *vm, u8 type, u16 len, u16 elemCls)
{
	u16 h = alloc(vm, (u32)elemSize(type) * len);
	if (!h) return 0;
	JcObj *o = &vm->objs[h - 1];
	o->type = type, o->len = len, o->cls = elemCls;
	return h;
}

void *jcNat(JcVm *vm, u16 h)
{
	JcObj *o = jcObj(vm, h);
	return o && o->type == JT_INSTANCE ? o->data + jcNatOff(o->len) : NULL;
}

bool jcSubclass(JcVm *vm, int cls, int of)
{
	for (int depth = 0; cls >= 0 && depth < 64; depth++) {
		if (cls == of) return true;
		JcClass *c = &vm->classes[cls];
		if (c->api) {
			for (const s16 *i = c->api->ifaces; i && *i >= 0; i++)
				if (jcSubclass(vm, *i, of)) return true;
		} else if (c->ifaces) {
			const JcPkg *p = &vm->pkgs[c->pkg];
			const u8 *f = c->ifaces;
			for (int i = 0; i < c->nifaces; i++) {
				int ic = classRef(vm, p, be16(f));
				if (ic >= 0 && jcSubclass(vm, ic, of)) return true;
				f += c->interface ? 2 : 3 + f[2];
			}
		}
		cls = c->super;
	}
	return false;
}

bool jcInstanceOf(JcVm *vm, u16 h, int cls)
{
	JcObj *o = jcObj(vm, h);
	if (!o) return false;
	if (o->type != JT_INSTANCE) return cls == JCC_lang_Object;
	return jcSubclass(vm, o->cls, cls);
}

// --- transactions ---

void jcBeginTransaction(JcVm *vm)
{
	vm->njournal = 0;
}

void jcCommit(JcVm *vm)
{
	vm->njournal = -1;
}

static u8 *journalTarget(JcVm *vm, int k)
{
	u8 kind = vm->journal[k].kind;
	u16 h = vm->journal[k].h;
	u32 off = vm->journal[k].off;
	if (kind == JE_OBJ) return vm->objs[h - 1].data + off;
	if (kind == JE_SPRIM) return vm->pkgs[h].sprims + off;
	return (u8 *)(vm->pkgs[h].srefs + off);
}

void jcAbort(JcVm *vm)
{
	for (int k = vm->njournal - 1; k >= 0; k--) memcpy(journalTarget(vm, k), &vm->journal[k].old, vm->journal[k].len);
	vm->njournal = -1;
}

static bool journal(JcVm *vm, u8 kind, u16 h, u32 off, const u8 *now, u8 len)
{
	if (vm->njournal < 0) return true;
	if (vm->njournal >= JC_JOURNAL) {
		jcThrow(vm, JCC_framework_TransactionException, 3); // BUFFER_FULL
		return false;
	}
	int k = vm->njournal++;
	vm->journal[k].kind = kind, vm->journal[k].h = h, vm->journal[k].off = off, vm->journal[k].len = len;
	memcpy(&vm->journal[k].old, now, len);
	return true;
}

void jcStore(JcVm *vm, u16 h, u32 off, const void *v, u8 len)
{
	JcObj *o = &vm->objs[h - 1];
	if (!(o->flags & (JO_RESET | JO_DESELECT | JO_SYSTEM)))
		for (u8 i = 0; i < len; i += 4) journal(vm, JE_OBJ, h, off + i, o->data + off + i, len - i < 4 ? len - i : 4);
	memcpy(o->data + off, v, len);
}

void jcClearObj(JcObj *o)
{
	if (o->type == JT_INSTANCE) jcNatClear(o->cls, o->data + jcNatOff(o->len));
	else memset(o->data, 0, (u32)elemSize(o->type) * o->len);
}

void jcClearTransients(JcVm *vm, u8 event)
{
	for (int i = 0; i < JC_OBJS; i++) {
		JcObj *o = &vm->objs[i];
		if (o->data && o->flags & event) jcClearObj(o);
	}
}

// --- exceptions ---

int jcThrow(JcVm *vm, int apiCls, s16 reason)
{
	u16 h = vm->sysExc[apiCls];
	vm->exc = 0;
	if (!jcObj(vm, h)) {
		h = jcNew(vm, apiCls);
		if (!h) return -1; // no memory left even for that: a VM failure
		vm->objs[h - 1].flags |= JO_SYSTEM;
		vm->sysExc[apiCls] = h;
	}
	s16 *r = jcNat(vm, h);
	if (r && vm->classes[apiCls].natSize >= 2) *r = reason;
	vm->exc = h;
	return -1;
}

s16 jcReason(JcVm *vm, u16 h)
{
	JcObj *o = jcObj(vm, h);
	if (!o || o->type != JT_INSTANCE || o->natLen < 2) return 0;
	return *(s16 *)jcNat(vm, h);
}

// --- methods ---

static const JcNativeMethod *apiVirtual(const JcApiClass *a, u8 token)
{
	for (int i = 0; i < a->nvm; i++)
		if (a->vm[i].token == token) return &a->vm[i];
	return NULL;
}

// From cls up; token bit 7: package-visible, only in classes of package fromPkg.
static bool virtualFrom(JcVm *vm, int cls, u8 token, int fromPkg, int *pkg, u16 *off, const JcNativeMethod **nat)
{
	for (int depth = 0; cls >= 0 && depth < 64; depth++) {
		JcClass *c = &vm->classes[cls];
		if (c->api) {
			const JcNativeMethod *m = apiVirtual(c->api, token);
			if (m && m->fn) {
				*nat = m;
				return true;
			}
		} else if (token & 0x80) {
			u8 t = token & 0x7F;
			if (c->pkg == fromPkg && t >= c->pkgBase && t < c->pkgBase + c->pkgCount) {
				u16 o = be16(c->pkgVmt + 2 * (t - c->pkgBase));
				if (o != 0xFFFF) {
					*pkg = c->pkg, *off = o, *nat = NULL;
					return true;
				}
			}
		} else if (token >= c->pubBase && token < c->pubBase + c->pubCount) {
			u16 o = be16(c->pubVmt + 2 * (token - c->pubBase));
			if (o != 0xFFFF) {
				*pkg = c->pkg, *off = o, *nat = NULL;
				return true;
			}
		}
		cls = c->super;
	}
	return false;
}

bool jcVirtual(JcVm *vm, int cls, u8 token, int *pkg, u16 *off, const JcNativeMethod **nat)
{
	return virtualFrom(vm, cls, token, -1, pkg, off, nat);
}

static bool interfaceMethod(JcVm *vm, int cls, int iface, u8 token, int *pkg, u16 *off, const JcNativeMethod **nat)
{
	for (int c = cls, depth = 0; c >= 0 && depth < 64; depth++) {
		JcClass *k = &vm->classes[c];
		if (!k->api && k->ifaces) {
			const u8 *f = k->ifaces;
			for (int i = 0; i < k->nifaces; i++) {
				if (classRef(vm, &vm->pkgs[k->pkg], be16(f)) == iface && token < f[2])
					return virtualFrom(vm, cls, f[3 + token], k->pkg, pkg, off, nat);
				f += 3 + f[2];
			}
		}
		c = k->super;
	}
	// an API object: the interface's own native, which looks at the object
	const JcApiClass *a = vm->classes[iface].api;
	const JcNativeMethod *m = a ? apiVirtual(a, token) : NULL;
	if (m && m->fn) {
		*nat = m;
		return true;
	}
	return false;
}

static int methodNargs(const u8 *m)
{
	return m[0] >> 4 & ACC_EXTENDED ? m[2] : m[1] >> 4;
}

// The argument cells of virtual method token as declared from cls up (an API method may have no native:
// abstract, overridden). -1 = none.
static int declaredNargs(JcVm *vm, int cls, u8 token, int fromPkg)
{
	for (int depth = 0; cls >= 0 && depth < 64; depth++) {
		JcClass *c = &vm->classes[cls];
		if (c->api) {
			const JcNativeMethod *m = apiVirtual(c->api, token);
			if (m) return m->nargs;
		} else {
			int pkg;
			u16 off;
			const JcNativeMethod *nat;
			if (virtualFrom(vm, cls, token, fromPkg, &pkg, &off, &nat))
				return nat ? nat->nargs : methodNargs(vm->pkgs[pkg].comp[7] + off);
		}
		cls = c->super;
	}
	return -1;
}

// --- the interpreter ---

static int i2s(int32_t v)
{
	return (s16)v;
}

#define PUSH(v)    (*S++ = (u16)(v))
#define POP()      ((s16)*--S)
#define POPH()     (*--S)
#define PUSHI(v)   do { int32_t _v = (v); S[0] = (u32)_v >> 16; S[1] = (u16)_v; S += 2; } while (0)
#define POPI()     (S -= 2, (int32_t)((u32)S[0] << 16 | S[1]))
#define THROW(c)   do { jcThrow(vm, (c), 0); goto exception; } while (0)
#define NPE(h)     do { if (!jcObj(vm, (h))) THROW(JCC_lang_NullPointerException); } while (0)
#define OOM()      do { jcThrow(vm, JCC_framework_SystemException, 3); goto exception; } while (0) // NO_RESOURCE

static int run(JcVm *vm, int stopAt);

int jcCall(JcVm *vm, int pkg, u16 off, const u16 *args, int nargs, u16 *ret)
{
	int depth = vm->nframes;
	u16 base = depth ? vm->frames[depth - 1].sp : 0;
	if (base + nargs + 256 > JC_STACK || depth >= JC_FRAMES) return fail(vm, "%s", "stack overflow");
	memcpy(vm->stack + base, args, 2 * nargs);
	vm->exc = 0;
	JcPkg *p = &vm->pkgs[pkg];
	const u8 *m = p->comp[7] + off;
	JcFrame *f = &vm->frames[vm->nframes++];
	f->m = m, f->pkg = pkg;
	f->code = m + (m[0] >> 4 & ACC_EXTENDED ? 4 : 2);
	f->pc = f->code - p->comp[7];
	f->base = base;
	u16 nloc = m[0] >> 4 & ACC_EXTENDED ? m[3] : m[1] & 0xF;
	memset(vm->stack + base + nargs, 0, 2 * nloc);
	f->sp = base + nargs + nloc;
	int r = run(vm, depth);
	vm->nframes = depth;
	if (r == 1 && ret) {
		// the return cells were left at base
		memcpy(ret, vm->stack + base, 2 * 2);
	}
	return r;
}

int jcInvokeVirtual(JcVm *vm, u8 token, const u16 *args, int nargs, u16 *ret)
{
	JcObj *o = jcObj(vm, args[0]);
	if (!o) return fail(vm, "%s", "null applet");
	int pkg;
	u16 off;
	const JcNativeMethod *nat;
	if (!jcVirtual(vm, o->cls, token, &pkg, &off, &nat)) return fail(vm, "%s", "no such method");
	if (nat) {
		u16 a[8];
		memcpy(a, args, 2 * nargs);
		vm->exc = 0;
		int r = nat->fn(vm, a);
		if (r < 0) return vm->exc ? 0 : -1;
		if (ret) memcpy(ret, a, 2 * r);
		return 1;
	}
	return jcCall(vm, pkg, off, args, nargs, ret);
}

// Runs frames until the one at index stopAt returns (1) or an exception leaves it (0); -1 = VM failure.
static int run(JcVm *vm, int stopAt)
{
	JcFrame *f;
	JcPkg *p;
	const u8 *mc; // Method component
	const u8 *pc;
	u16 *L, *S;
	const JcCp *cp;

#define LOAD_FRAME() do { f = &vm->frames[vm->nframes - 1]; p = &vm->pkgs[f->pkg]; mc = p->comp[7]; \
		cp = p->cp; pc = mc + f->pc; L = vm->stack + f->base; S = vm->stack + f->sp; } while (0)
#define SAVE_FRAME() do { f->pc = pc - mc; f->sp = S - vm->stack; } while (0)

	LOAD_FRAME();
	for (;;) {
		vm->steps++;
		f->pc = pc - mc;
		u8 op = *pc;
		int len = 1;
		switch (op) {
		case 0x00: break; // nop
		case 0x01: PUSH(0); break; // aconst_null
		case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07: case 0x08: PUSH(op - 3); break; // sconst
		case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E: case 0x0F: PUSHI(op - 10); break; // iconst
		case 0x10: PUSH((s8)pc[1]); len = 2; break; // bspush
		case 0x11: PUSH(sbe16(pc + 1)); len = 3; break; // sspush
		case 0x12: PUSHI((s8)pc[1]); len = 2; break; // bipush
		case 0x13: PUSHI(sbe16(pc + 1)); len = 3; break; // sipush
		case 0x14: PUSHI((int32_t)((u32)be16(pc + 1) << 16 | be16(pc + 3))); len = 5; break; // iipush
		case 0x15: case 0x16: PUSH(L[pc[1]]); len = 2; break; // aload, sload
		case 0x17: PUSH(L[pc[1]]); PUSH(L[pc[1] + 1]); len = 2; break; // iload
		case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E: case 0x1F:
			PUSH(L[(op - 0x18) & 3]);
			break;
		case 0x20: case 0x21: case 0x22: case 0x23: PUSH(L[op - 0x20]); PUSH(L[op - 0x20 + 1]); break;
		case 0x24: case 0x25: case 0x26: case 0x27: { // aaload baload saload iaload
			s16 i = POP();
			u16 h = POPH();
			NPE(h);
			JcObj *o = jcObj(vm, h);
			if (o->type == JT_INSTANCE) THROW(JCC_lang_ClassCastException);
			if (i < 0 || i >= o->len) THROW(JCC_lang_ArrayIndexOutOfBoundsException);
			if (op == 0x24) PUSH(((u16 *)o->data)[i]);
			else if (op == 0x25) PUSH((s8)o->data[i]);
			else if (op == 0x26) PUSH(((s16 *)o->data)[i]);
			else PUSHI(((int32_t *)o->data)[i]);
			break;
		}
		case 0x28: case 0x29: L[pc[1]] = POPH(); len = 2; break; // astore, sstore
		case 0x2A: L[pc[1] + 1] = POPH(); L[pc[1]] = POPH(); len = 2; break; // istore
		case 0x2B: case 0x2C: case 0x2D: case 0x2E: case 0x2F: case 0x30: case 0x31: case 0x32:
			L[(op - 0x2B) & 3] = POPH();
			break;
		case 0x33: case 0x34: case 0x35: case 0x36: L[op - 0x33 + 1] = POPH(); L[op - 0x33] = POPH(); break;
		case 0x37: case 0x38: case 0x39: case 0x3A: { // aastore bastore sastore iastore
			int32_t v = op == 0x3A ? POPI() : POP();
			s16 i = POP();
			u16 h = POPH();
			NPE(h);
			JcObj *o = jcObj(vm, h);
			if (o->type == JT_INSTANCE) THROW(JCC_lang_ClassCastException);
			if (i < 0 || i >= o->len) THROW(JCC_lang_ArrayIndexOutOfBoundsException);
			if (op == 0x37) {
				u16 r = (u16)v;
				if (r && o->cls != 0xFFFF && !jcInstanceOf(vm, r, o->cls) && jcObj(vm, r)->type == JT_INSTANCE)
					THROW(JCC_lang_ArrayStoreException);
				jcStore(vm, h, 2 * i, &r, 2);
			} else if (op == 0x38) {
				u8 b = o->type == JT_BOOLEAN ? v & 1 : (u8)v;
				jcStore(vm, h, i, &b, 1);
			} else if (op == 0x39) {
				s16 s = v;
				jcStore(vm, h, 2 * i, &s, 2);
			} else {
				jcStore(vm, h, 4 * i, &v, 4);
			}
			if (vm->exc) goto exception;
			break;
		}
		case 0x3B: S--; break; // pop
		case 0x3C: S -= 2; break; // pop2
		case 0x3D: S[0] = S[-1]; S++; break; // dup
		case 0x3E: S[0] = S[-2]; S[1] = S[-1]; S += 2; break; // dup2
		case 0x3F: { // dup_x mn: the top m words copied, inserted n words down (n 0: on top)
			int m = pc[1] >> 4, n = pc[1] & 0xF;
			u16 t[8];
			memcpy(t, S - m, 2 * m);
			if (n) {
				memmove(S - n + m, S - n, 2 * n);
				memcpy(S - n, t, 2 * m);
			} else {
				memcpy(S, t, 2 * m);
			}
			S += m;
			len = 2;
			break;
		}
		case 0x40: { // swap_x mn: the top m words swapped with the n words below them
			int m = pc[1] >> 4, n = pc[1] & 0xF;
			u16 t[8];
			memcpy(t, S - m, 2 * m);
			memmove(S - n, S - m - n, 2 * n);
			memcpy(S - m - n, t, 2 * m);
			len = 2;
			break;
		}
		case 0x41: { s16 b = POP(), a = POP(); PUSH(i2s(a + b)); break; } // sadd
		case 0x42: { int32_t b = POPI(), a = POPI(); PUSHI((int32_t)((u32)a + (u32)b)); break; }
		case 0x43: { s16 b = POP(), a = POP(); PUSH(i2s(a - b)); break; }
		case 0x44: { int32_t b = POPI(), a = POPI(); PUSHI((int32_t)((u32)a - (u32)b)); break; }
		case 0x45: { s16 b = POP(), a = POP(); PUSH(i2s(a * b)); break; }
		case 0x46: { int32_t b = POPI(), a = POPI(); PUSHI((int32_t)((u32)a * (u32)b)); break; }
		case 0x47: case 0x49: { // sdiv srem
			s16 b = POP(), a = POP();
			if (!b) THROW(JCC_lang_ArithmeticException);
			PUSH(i2s(op == 0x47 ? a / b : a % b)); // (s16 -32768 / -1 = 32768 as int: truncated)
			break;
		}
		case 0x48: case 0x4A: { // idiv irem
			int32_t b = POPI(), a = POPI();
			if (!b) THROW(JCC_lang_ArithmeticException);
			if (b == -1) PUSHI(op == 0x48 ? (int32_t)(0u - (u32)a) : 0);
			else PUSHI(op == 0x48 ? a / b : a % b);
			break;
		}
		case 0x4B: { s16 a = POP(); PUSH(i2s(-a)); break; } // sneg
		case 0x4C: { int32_t a = POPI(); PUSHI((int32_t)(0u - (u32)a)); break; } // ineg
		case 0x4D: { s16 b = POP(), a = POP(); PUSH(i2s((int32_t)((u32)a << (b & 0x1F)))); break; } // sshl
		case 0x4E: { int32_t b = POPI(), a = POPI(); PUSHI((int32_t)((u32)a << (b & 0x1F))); break; }
		case 0x4F: { s16 b = POP(), a = POP(); PUSH(i2s((int32_t)a >> (b & 0x1F))); break; } // sshr
		case 0x50: { int32_t b = POPI(), a = POPI(); PUSHI(a >> (b & 0x1F)); break; }
		case 0x51: { s16 b = POP(), a = POP(); PUSH(i2s((int32_t)((u32)(int32_t)a >> (b & 0x1F)))); break; } // sushr
		case 0x52: { int32_t b = POPI(), a = POPI(); PUSHI((int32_t)((u32)a >> (b & 0x1F))); break; }
		case 0x53: { s16 b = POP(), a = POP(); PUSH(a & b); break; }
		case 0x54: { int32_t b = POPI(), a = POPI(); PUSHI(a & b); break; }
		case 0x55: { s16 b = POP(), a = POP(); PUSH(a | b); break; }
		case 0x56: { int32_t b = POPI(), a = POPI(); PUSHI(a | b); break; }
		case 0x57: { s16 b = POP(), a = POP(); PUSH(a ^ b); break; }
		case 0x58: { int32_t b = POPI(), a = POPI(); PUSHI(a ^ b); break; }
		case 0x59: L[pc[1]] = i2s((s16)L[pc[1]] + (s8)pc[2]); len = 3; break; // sinc
		case 0x5A: case 0x97: { // iinc, iinc_w
			u8 i = pc[1];
			int32_t v = (int32_t)((u32)L[i] << 16 | L[i + 1]) + (op == 0x5A ? (s8)pc[2] : sbe16(pc + 2));
			L[i] = (u32)v >> 16, L[i + 1] = (u16)v;
			len = op == 0x5A ? 3 : 4;
			break;
		}
		case 0x5B: { s16 a = POP(); PUSH((s8)a); break; } // s2b
		case 0x5C: { s16 a = POP(); PUSHI(a); break; } // s2i
		case 0x5D: { int32_t a = POPI(); PUSH((s8)a); break; } // i2b
		case 0x5E: { int32_t a = POPI(); PUSH((s16)a); break; } // i2s
		case 0x5F: { int32_t b = POPI(), a = POPI(); PUSH((a > b) - (a < b)); break; } // icmp
		case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
		case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
			bool w = op >= 0x98;
			int k = op - (w ? 0x98 : 0x60);
			s16 v = POP();
			bool c = k == 0 ? v == 0 : k == 1 ? v != 0 : k == 2 ? v < 0 : k == 3 ? v >= 0 : k == 4 ? v > 0 :
				k == 5 ? v <= 0 : k == 6 ? !v : v != 0; // ifnull / ifnonnull: handle 0
			if (c) {
				pc += w ? sbe16(pc + 1) : (s8)pc[1];
				continue;
			}
			len = w ? 3 : 2;
			break;
		}
		case 0x68: case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D: case 0x6E: case 0x6F:
		case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4: case 0xA5: case 0xA6: case 0xA7: {
			bool w = op >= 0xA0;
			int k = op - (w ? 0xA0 : 0x68);
			s16 b = POP(), a = POP();
			bool c = k == 0 || k == 2 ? a == b : k == 1 || k == 3 ? a != b : k == 4 ? a < b : k == 5 ? a >= b :
				k == 6 ? a > b : a <= b;
			if (c) {
				pc += w ? sbe16(pc + 1) : (s8)pc[1];
				continue;
			}
			len = w ? 3 : 2;
			break;
		}
		case 0x70: pc += (s8)pc[1]; continue; // goto
		case 0xA8: pc += sbe16(pc + 1); continue; // goto_w
		case 0x73: { // stableswitch default, low, high, offsets
			s16 v = POP(), lo = sbe16(pc + 3), hi = sbe16(pc + 5);
			pc += v >= lo && v <= hi ? sbe16(pc + 7 + 2 * (v - lo)) : sbe16(pc + 1);
			continue;
		}
		case 0x74: { // itableswitch
			int32_t v = POPI();
			int32_t lo = (int32_t)((u32)be16(pc + 3) << 16 | be16(pc + 5)), hi = (int32_t)((u32)be16(pc + 7) << 16 | be16(pc + 9));
			pc += v >= lo && v <= hi ? sbe16(pc + 11 + 2 * (v - lo)) : sbe16(pc + 1);
			continue;
		}
		case 0x75: { // slookupswitch default, npairs, (match, offset)...
			s16 v = POP();
			int o = sbe16(pc + 1);
			for (int k = 0, n = be16(pc + 3); k < n; k++)
				if (sbe16(pc + 5 + 4 * k) == v) {
					o = sbe16(pc + 7 + 4 * k);
					break;
				}
			pc += o;
			continue;
		}
		case 0x76: { // ilookupswitch
			int32_t v = POPI();
			int o = sbe16(pc + 1);
			for (int k = 0, n = be16(pc + 3); k < n; k++) {
				const u8 *e = pc + 5 + 6 * k;
				if ((int32_t)((u32)be16(e) << 16 | be16(e + 2)) == v) {
					o = sbe16(e + 4);
					break;
				}
			}
			pc += o;
			continue;
		}
		case 0x77: case 0x78: case 0x79: case 0x7A: { // areturn sreturn ireturn return
			int n = op == 0x7A ? 0 : op == 0x79 ? 2 : 1;
			u16 *dst = vm->stack + f->base;
			memmove(dst, S - n, 2 * n);
			vm->nframes--;
			if (vm->nframes == stopAt) return 1;
			LOAD_FRAME();
			S = dst + n;
			pc += *pc == 0x8E ? 5 : 3; // past the invoke
			continue;
		}
		case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: case 0x80: case 0x81: case 0x82: {
			int k = (op - 0x7B) & 3;
			const JcCp *e = &cp[be16(pc + 1)];
			len = 3;
			if (e->cls >= 0) {
				fail(vm, "%s", "static field of an API class");
				goto vmfail;
			}
			JcPkg *q = &vm->pkgs[e->pkg]; // this package or a library
			if (k == 0) {
				u16 i = e->off / 2;
				if (op < 0x7F) PUSH(q->srefs[i]);
				else {
					u16 v = POPH();
					if (!journal(vm, JE_SREF, e->pkg, i, (u8 *)&q->srefs[i], 2)) goto exception;
					q->srefs[i] = v;
				}
				break;
			}
			u16 o = e->off - 2 * q->nsrefs;
			int n = k == 1 ? 1 : k == 2 ? 2 : 4;
			u8 *b = q->sprims + o;
			if (op < 0x7F) {
				if (k == 1) PUSH((s8)b[0]);
				else if (k == 2) PUSH(sbe16(b));
				else PUSHI((int32_t)((u32)be16(b) << 16 | be16(b + 2)));
			} else {
				int32_t v = k == 3 ? POPI() : POP();
				if (!journal(vm, JE_SPRIM, e->pkg, o, b, n)) goto exception;
				for (int i = 0; i < n; i++) b[i] = v >> 8 * (n - 1 - i);
			}
			break;
		}
		case 0x83: case 0x84: case 0x85: case 0x86: case 0xA9: case 0xAA: case 0xAB: case 0xAC:
		case 0xAD: case 0xAE: case 0xAF: case 0xB0: { // getfield _a _b _s _i (_w, _this)
			int k = op <= 0x86 ? op - 0x83 : op <= 0xAC ? op - 0xA9 : op - 0xAD;
			u16 idx = op >= 0xA9 && op <= 0xAC ? be16(pc + 1) : pc[1];
			len = op >= 0xA9 && op <= 0xAC ? 3 : 2;
			u16 h = op >= 0xAD ? L[0] : POPH();
			NPE(h);
			JcObj *o = jcObj(vm, h);
			u16 c = cp[idx].off;
			if (o->type != JT_INSTANCE || c + (k == 3) >= o->len) THROW(JCC_lang_SecurityException);
			u16 *cells = (u16 *)o->data;
			PUSH(cells[c]);
			if (k == 3) PUSH(cells[c + 1]);
			break;
		}
		case 0x87: case 0x88: case 0x89: case 0x8A: case 0xB1: case 0xB2: case 0xB3: case 0xB4:
		case 0xB5: case 0xB6: case 0xB7: case 0xB8: { // putfield _a _b _s _i (_w, _this)
			int k = op <= 0x8A ? op - 0x87 : op <= 0xB4 ? op - 0xB1 : op - 0xB5;
			u16 idx = op >= 0xB1 && op <= 0xB4 ? be16(pc + 1) : pc[1];
			len = op >= 0xB1 && op <= 0xB4 ? 3 : 2;
			u16 v[2];
			if (k == 3) v[1] = POPH(), v[0] = POPH();
			else v[0] = POPH();
			if (k == 1) v[0] = (u16)(s16)(s8)v[0];
			u16 h = op >= 0xB5 ? L[0] : POPH();
			NPE(h);
			JcObj *o = jcObj(vm, h);
			u16 c = cp[idx].off;
			if (o->type != JT_INSTANCE || c + (k == 3) >= o->len) THROW(JCC_lang_SecurityException);
			jcStore(vm, h, 2 * c, v, k == 3 ? 4 : 2);
			if (vm->exc) goto exception;
			break;
		}
		case 0x8B: case 0x8C: case 0x8D: case 0x8E: { // invokevirtual / special / static / interface
			int tpkg = -1;
			u16 toff = 0;
			const JcNativeMethod *nat = NULL;
			int nargs;
			len = op == 0x8E ? 5 : 3;
			if (op == 0x8E) {
				nargs = pc[1];
				const JcCp *e = &cp[be16(pc + 2)];
				u16 h = S[-nargs];
				NPE(h);
				JcObj *o = jcObj(vm, h);
				int oc = o->type == JT_INSTANCE ? o->cls : JCC_lang_Object;
				if (!interfaceMethod(vm, oc, e->cls, pc[4], &tpkg, &toff, &nat)) {
					fail(vm, "%s", "interface method not found");
					goto vmfail;
				}
			} else {
				const JcCp *e = &cp[be16(pc + 1)];
				if (op == 0x8B || e->tag == CP_SUPERMETHOD) {
					// nargs from the declared method, then the object's own (super: from the super class)
					int from = op == 0x8B ? e->cls : vm->classes[e->cls].super;
					nargs = declaredNargs(vm, from, e->token, f->pkg);
					if (nargs < 1) {
						fail(vm, "%s", "virtual method not found");
						goto vmfail;
					}
					u16 h = S[-nargs];
					NPE(h);
					JcObj *o = jcObj(vm, h);
					if (op == 0x8B) from = o->type == JT_INSTANCE ? o->cls : JCC_lang_Object;
					if (!virtualFrom(vm, from, e->token, f->pkg, &tpkg, &toff, &nat)) {
						fail(vm, "%s", "virtual method not found");
						goto vmfail;
					}
				} else if (e->nat) {
					nat = e->nat;
					nargs = nat->nargs;
					if (op == 0x8C) NPE(S[-nargs]);
				} else {
					tpkg = e->pkg, toff = e->off;
					nargs = methodNargs(vm->pkgs[tpkg].comp[7] + toff);
					if (op == 0x8C) NPE(S[-nargs]);
				}
			}
			if (nat) {
				if (!nat->fn) {
					fail(vm, "native %s not implemented", nat->name);
					goto vmfail;
				}
				SAVE_FRAME();
				u16 *a = S - nargs;
				int r = nat->fn(vm, a);
				if (r < 0) {
					if (!vm->exc) goto vmfail;
					goto exception;
				}
				S = a + r;
				break;
			}
			JcPkg *tp = &vm->pkgs[tpkg];
			const u8 *m = tp->comp[7] + toff;
			if (m[0] >> 4 & ACC_ABSTRACT) {
				fail(vm, "%s", "abstract method called");
				goto vmfail;
			}
			bool ext = m[0] >> 4 & ACC_EXTENDED;
			u16 nloc = ext ? m[3] : m[1] & 0xF, nstk = ext ? m[1] : m[0] & 0xF;
			u16 base = S - nargs - vm->stack;
			if (vm->nframes >= JC_FRAMES || base + nargs + nloc + nstk > JC_STACK) {
				fail(vm, "%s", "stack overflow");
				goto vmfail;
			}
			SAVE_FRAME(); // pc stays at the invoke
			JcFrame *nf = &vm->frames[vm->nframes++];
			nf->m = m, nf->pkg = tpkg, nf->code = m + (ext ? 4 : 2), nf->pc = nf->code - tp->comp[7];
			nf->base = base;
			memset(vm->stack + base + nargs, 0, 2 * nloc);
			nf->sp = base + nargs + nloc;
			LOAD_FRAME();
			continue;
		}
		case 0x8F: { // new
			u16 h = jcNew(vm, cp[be16(pc + 1)].cls);
			if (!h) OOM();
			PUSH(h);
			len = 3;
			break;
		}
		case 0x90: case 0x91: { // newarray type, anewarray class
			s16 n = POP();
			if (n < 0) THROW(JCC_lang_NegativeArraySizeException);
			u16 h = op == 0x90 ? jcNewArray(vm, pc[1], n, 0) : jcNewArray(vm, JT_REF, n, cp[be16(pc + 1)].cls);
			if (!h) OOM();
			PUSH(h);
			len = op == 0x90 ? 2 : 3;
			break;
		}
		case 0x92: { // arraylength
			u16 h = POPH();
			NPE(h);
			PUSH(jcObj(vm, h)->len);
			break;
		}
		case 0x93: { // athrow
			u16 h = POPH();
			NPE(h);
			vm->exc = h;
			goto exception;
		}
		case 0x94: case 0x95: { // checkcast, instanceof: atype, cp index
			u8 t = pc[1];
			u16 idx = be16(pc + 2);
			u16 h = S[-1];
			JcObj *o = jcObj(vm, h);
			bool ok = false;
			if (o) {
				int cls = idx ? cp[idx].cls : -1;
				if (o->type == JT_INSTANCE) ok = !t && jcSubclass(vm, o->cls, cls);
				else if (!t) ok = cls == JCC_lang_Object;
				else if (t == JT_REF) ok = o->type == JT_REF && (o->cls == 0xFFFF || cls < 0 || jcSubclass(vm, o->cls, cls));
				else ok = o->type == t;
			}
			if (op == 0x95) S[-1] = ok;
			else if (o && !ok) THROW(JCC_lang_ClassCastException);
			len = 4;
			break;
		}
		case 0x96: L[pc[1]] = i2s((s16)L[pc[1]] + sbe16(pc + 2)); len = 4; break; // sinc_w
		default:
			snprintf(vm->why, sizeof(vm->why), "bytecode %02X", op);
			goto vmfail;
		}
		pc += len;
		continue;

	exception: {
		// the handler for the pc of the frame on top, else the next frame down (at its invoke)
		u16 ex = vm->exc;
		if (!ex) {
			fail(vm, "%s", "out of memory");
			goto vmfail;
		}
		for (;;) {
			SAVE_FRAME();
			const u8 *hs = mc + 1;
			int nh = mc[0];
			for (int i = 0; i < nh; i++, hs += 8) {
				u16 start = be16(hs), end = start + (be16(hs + 2) & 0x7FFF), catchIdx = be16(hs + 6);
				if (f->pc >= start && f->pc < end && (!catchIdx || jcInstanceOf(vm, ex, cp[catchIdx].cls))) {
					pc = mc + be16(hs + 4);
					S = L + ((f->m[0] >> 4 & ACC_EXTENDED ? f->m[2] + f->m[3] : (f->m[1] >> 4) + (f->m[1] & 0xF)));
					PUSH(ex);
					vm->exc = 0;
					goto handled;
				}
			}
			vm->nframes--;
			if (vm->nframes == stopAt) {
				vm->exc = ex;
				return 0;
			}
			LOAD_FRAME();
		}
	handled:
		continue;
	}
	vmfail:
		vm->nframes = stopAt;
		return -1;
	}
}
