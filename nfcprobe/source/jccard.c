// A Java Card around the VM: see jccard.h. The Python prototype is tools/jcvm/card.py.

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "jccard.h"

JcCard jcCard;

// Applet method tokens (javacard.framework.Applet, export file)
enum { TOK_DESELECT = 4, TOK_SELECT = 6, TOK_PROCESS = 7 };

void jcRandom(u8 *out, u32 len)
{
	if (R_FAILED(PS_GenerateRandomBytes(out, len)))
		for (u32 i = 0; i < len; i++) out[i] = rand();
}

static void sysObjects(void)
{
	JcCard *c = &jcCard;
	c->apdu = jcNew(&c->vm, JCC_framework_APDU);
	c->buf = jcNewArray(&c->vm, JT_BYTE, JC_BUF, 0);
	jcObj(&c->vm, c->apdu)->flags |= JO_SYSTEM;
	jcObj(&c->vm, c->buf)->flags |= JO_SYSTEM;
}

void jcCardInit(void)
{
	JcCard *c = &jcCard;
	jcFree(&c->vm); // (leaves it initialised; the rest of the card starts from zero. JcVm is ~100 KB: never
	                // on a stack, the UI thread's is 32 KB)
	memset((u8 *)c + sizeof(c->vm), 0, sizeof(*c) - sizeof(c->vm));
	c->vm.card = c;
	c->selected = c->context = c->installPkg = -1;
	sysObjects();
}

static u8 *readFile(const char *path, u32 *len)
{
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	u8 *d = n > 0 && n < 0x100000 ? malloc(n) : NULL;
	if (d && fread(d, 1, n, f) != (size_t)n) free(d), d = NULL;
	fclose(f);
	*len = n;
	return d;
}

static int loadCap(const char *path)
{
	u32 len;
	u8 *d = readFile(path, &len);
	if (!d) {
		snprintf(jcCard.vm.why, sizeof(jcCard.vm.why), "can't read %s", path);
		return -1;
	}
	int p = jcLoadCap(&jcCard.vm, d, len, path);
	free(d);
	return p;
}

// Runs Java code from the card: a transaction left open is aborted (JCRE 7.6.3). 1 = returned, 0 = a
// Java exception (vm.exc), -1 = VM failure (vm.why).
static int invoke(u8 token, int applet, u16 *ret)
{
	JcCard *c = &jcCard;
	u16 args[2] = { c->applets[applet].obj, c->apdu };
	c->context = applet;
	int r = jcInvokeVirtual(&c->vm, token, args, token == TOK_PROCESS ? 2 : 1, ret);
	if (c->vm.njournal >= 0) jcAbort(&c->vm);
	return r;
}

int jcCardInstall(int pkg, const u8 *appletAid, u8 appletAidLen, const u8 *instAid, u8 instAidLen)
{
	JcCard *c = &jcCard;
	JcPkg *p = &c->vm.pkgs[pkg];
	const u8 *ac = p->comp[3];
	if (!ac) {
		snprintf(c->vm.why, sizeof(c->vm.why), "no applets in the package");
		return -1;
	}
	for (int i = 0, o = 1; i < ac[0]; i++) {
		const u8 *aid = ac + o + 1;
		u8 alen = ac[o];
		u16 install = ac[o + 1 + alen] << 8 | ac[o + 2 + alen];
		o += 3 + alen;
		if (appletAid && (alen != appletAidLen || memcmp(aid, appletAid, alen))) continue;
		if (!instAid) instAid = aid, instAidLen = alen;
		// bArray: instance AID, control info, applet data (each length-prefixed), as GlobalPlatform's
		// INSTALL [for install] passes them
		u16 arr = jcNewArray(&c->vm, JT_BYTE, instAidLen + 3, 0);
		if (!arr) {
			snprintf(c->vm.why, sizeof(c->vm.why), "out of memory");
			return -1;
		}
		u8 *b = jcObj(&c->vm, arr)->data;
		b[0] = instAidLen;
		memcpy(b + 1, instAid, instAidLen);
		u16 args[3] = { arr, 0, instAidLen + 3 };
		int n = c->napplets;
		c->instAid = instAid, c->instAidLen = instAidLen, c->installPkg = pkg;
		c->context = -1;
		int r = jcCall(&c->vm, pkg, install, args, 3, NULL);
		if (c->vm.njournal >= 0) jcAbort(&c->vm);
		c->installPkg = -1, c->instAid = NULL;
		c->dirty = true;
		if (r < 0) return -1;
		if (r == 0) {
			JcObj *e = jcObj(&c->vm, c->vm.exc);
			snprintf(c->vm.why, sizeof(c->vm.why), "install() threw %s, reason %04X",
				e && e->cls < JC_API_CLASSES ? jcApiClasses[e->cls].name : "an exception", (u16)jcReason(&c->vm, c->vm.exc));
			return -1;
		}
		if (c->napplets == n) {
			snprintf(c->vm.why, sizeof(c->vm.why), "install() didn't register");
			return -1;
		}
		return c->napplets - 1;
	}
	snprintf(c->vm.why, sizeof(c->vm.why), "no such applet in the package");
	return -1;
}

int jcCardInstallCap(const char *path)
{
	JcCard *c = &jcCard;
	int p = loadCap(path);
	if (p < 0) return -1;
	const u8 *ac = c->vm.pkgs[p].comp[3];
	for (int i = 0, o = 1; ac && i < ac[0]; i++) {
		if (jcCardInstall(p, ac + o + 1, ac[o], NULL, 0) < 0) return -1;
		o += 3 + ac[o];
	}
	return p;
}

bool jcCardDeletePkg(int pkg)
{
	JcCard *c = &jcCard;
	if (pkg < 0 || pkg >= c->vm.npkgs) return false;
	for (int i = 0; i < c->napplets;)
		if (c->applets[i].pkg == pkg) {
			memmove(&c->applets[i], &c->applets[i + 1], (c->napplets - i - 1) * sizeof(JcApplet));
			c->napplets--;
		} else {
			i++;
		}
	// the package stays loaded until the card is saved and restored without it
	c->vm.pkgs[pkg].path[0] = 0;
	c->selected = -1;
	c->dirty = true;
	return true;
}

static void deselect(void)
{
	JcCard *c = &jcCard;
	if (c->selected >= 0) {
		invoke(TOK_DESELECT, c->selected, NULL);
		jcClearTransients(&c->vm, JO_DESELECT);
	}
	c->selected = -1;
}

void jcCardReset(void)
{
	JcCard *c = &jcCard;
	c->selected = -1;
	jcClearTransients(&c->vm, JO_RESET | JO_DESELECT);
}

static u32 sw(u8 *resp, u32 at, u16 s)
{
	resp[at] = s >> 8;
	resp[at + 1] = s;
	return at + 2;
}

static int findApplet(const u8 *aid, u8 len)
{
	JcCard *c = &jcCard;
	for (int i = 0; i < c->napplets; i++)
		if (c->applets[i].aidLen == len && !memcmp(c->applets[i].aid, aid, len)) return i;
	for (int i = 0; i < c->napplets; i++) // a partial AID: the first that starts with it
		if (c->applets[i].aidLen > len && !memcmp(c->applets[i].aid, aid, len)) return i;
	return -1;
}

u32 jcCardApdu(const u8 *cmd, u32 len, u8 *resp, u32 max)
{
	JcCard *c = &jcCard;
	if (!cmd) {
		if (c->dirty) jcCardSave();
		jcCardReset();
		return 0;
	}
	if (len < 4 || max < 2) return sw(resp, 0, 0x6700);
	if (len > JC_BUF) return sw(resp, 0, 0x6700); // extended length: not yet
	memcpy(c->cmd, cmd, len);
	c->cmdLen = len, c->lc = 0, c->le = 256, c->received = 0, c->state = 0, c->outLen = c->outExpected = 0;
	if (len > 5) {
		c->lc = cmd[4];
		if (len < 5u + c->lc) return sw(resp, 0, 0x6700);
		if (len > 5u + c->lc) c->le = cmd[5 + c->lc] ? cmd[5 + c->lc] : 256;
	} else if (len == 5) {
		c->le = cmd[4] ? cmd[4] : 256;
	}
	JcObj *b = jcObj(&c->vm, c->buf);
	memset(b->data, 0, JC_BUF);
	memcpy(b->data, cmd, len < 5 ? len : 5);
	c->apdus++;
	c->selecting = c->reselecting = false;
	if ((cmd[0] & 0xFC) == 0 && cmd[1] == 0xA4 && cmd[2] == 0x04 && len >= 5) {
		int i = findApplet(cmd + 5, len > 5 ? c->lc : 0);
		if (len > 5 && i >= 0) {
			c->reselecting = i == c->selected;
			deselect();
			u16 ok = 0;
			int r = invoke(TOK_SELECT, i, &ok);
			if (r != 1 || !ok) return sw(resp, 0, 0x6999); // SW_APPLET_SELECT_FAILED
			c->selected = i;
			c->selecting = true;
		} else if (c->selected < 0) {
			return sw(resp, 0, 0x6A82);
		}
	}
	if (c->selected < 0) return sw(resp, 0, 0x6D00);
	c->dirty = true;
	u16 s = 0x9000;
	int r = invoke(TOK_PROCESS, c->selected, NULL);
	c->selecting = c->reselecting = false;
	if (r == 0) {
		u16 ex = c->vm.exc;
		s = jcInstanceOf(&c->vm, ex, JCC_framework_ISOException) ? (u16)jcReason(&c->vm, ex) : 0x6F00;
	} else if (r < 0) {
		s = 0x6F00;
	}
	u32 n = c->outLen + 2 <= max ? c->outLen : max - 2;
	memcpy(resp, c->out, n);
	return sw(resp, n, s);
}

// --- saving: packages by path, the heap, statics, applets ---

#define JC_MAGIC 0x4A435332 // "JCS2"

// Class indices in the file: API classes C000 + index, CAP classes package << 8 | number in the package
// (packages are numbered as saved), FFFF stays (a reference array of any class).
static u16 clsOut(JcVm *vm, u16 cls)
{
	if (cls == 0xFFFF) return cls;
	if (cls < JC_API_CLASSES) return 0xC000 | cls;
	int p = vm->classes[cls].pkg;
	return p << 8 | (cls - vm->pkgs[p].classBase);
}

static int clsIn(JcVm *vm, u16 v, const s8 *map, int npkgs)
{
	if (v == 0xFFFF) return v;
	if ((v & 0xC000) == 0xC000) return (v & 0xFFF) < JC_API_CLASSES ? v & 0xFFF : -1;
	int p = v >> 8;
	if (p >= npkgs || map[p] < 0 || (v & 0xFF) >= vm->pkgs[(int)map[p]].nclasses) return -1;
	return vm->pkgs[(int)map[p]].classBase + (v & 0xFF);
}

static bool wr(FILE *f, const void *d, u32 n)
{
	return fwrite(d, 1, n, f) == n;
}

static bool rd(FILE *f, void *d, u32 n)
{
	return fread(d, 1, n, f) == n;
}

bool jcCardSave(void)
{
	JcCard *c = &jcCard;
	JcVm *vm = &c->vm;
	mkdir(JC_DIR, 0777);
	FILE *f = fopen(JC_STATE ".new", "wb");
	if (!f) return false;
	u32 magic = JC_MAGIC;
	bool ok = wr(f, &magic, 4) && wr(f, &vm->npkgs, 1);
	for (int i = 0; ok && i < vm->npkgs; i++) {
		JcPkg *p = &vm->pkgs[i];
		ok = wr(f, p->path, sizeof(p->path)) && wr(f, &p->nsrefs, 2) && wr(f, p->srefs, 2 * p->nsrefs) &&
			wr(f, &p->nsprims, 2) && wr(f, p->sprims, p->nsprims);
	}
	u16 n = 0;
	for (int i = 0; i < JC_OBJS; i++) n += vm->objs[i].data && !(vm->objs[i].flags & JO_SYSTEM);
	ok = ok && wr(f, &n, 2);
	for (int i = 0; ok && i < JC_OBJS; i++) {
		JcObj *o = &vm->objs[i];
		if (!o->data || o->flags & JO_SYSTEM) continue;
		u16 h = i + 1;
		u32 size = jcObjSize(o);
		JcObj s = *o;
		s.cls = clsOut(vm, o->cls);
		ok = wr(f, &h, 2) && wr(f, &s, offsetof(JcObj, data)) && wr(f, o->data, size);
	}
	ok = ok && wr(f, &c->napplets, 1) && wr(f, c->applets, sizeof(JcApplet) * c->napplets);
	if (fclose(f) || !ok) return false;
	remove(JC_STATE);
	if (rename(JC_STATE ".new", JC_STATE)) return false;
	c->dirty = false;
	return true;
}

bool jcCardRestore(void)
{
	JcCard *c = &jcCard;
	JcVm *vm = &c->vm;
	jcCardInit();
	FILE *f = fopen(JC_STATE, "rb");
	if (!f) return false;
	u32 magic = 0;
	u8 npkgs = 0;
	bool ok = rd(f, &magic, 4) && magic == JC_MAGIC && rd(f, &npkgs, 1) && npkgs <= JC_PKGS;
	// the packages again from their CAP files (deleted ones: a placeholder that keeps the numbering)
	s8 map[JC_PKGS];
	for (int i = 0; ok && i < npkgs; i++) {
		char path[128];
		u16 n;
		ok = rd(f, path, sizeof(path));
		map[i] = ok && path[0] ? loadCap(path) : -1;
		ok = ok && rd(f, &n, 2);
		JcPkg *p = map[i] >= 0 ? &vm->pkgs[map[i]] : NULL;
		if (ok && p && n != p->nsrefs) ok = false;
		u16 tmp[256];
		ok = ok && n <= 256 && rd(f, p ? p->srefs : tmp, 2 * n) && rd(f, &n, 2);
		if (ok && p && n != p->nsprims) ok = false;
		u8 skip[1024];
		ok = ok && n <= 1024 && rd(f, p ? p->sprims : skip, n);
	}
	// the heap as saved (the static arrays loading made are replaced by the saved ones)
	for (int i = 0; ok && i < JC_OBJS; i++) {
		free(vm->objs[i].data);
		memset(&vm->objs[i], 0, sizeof(JcObj));
	}
	u16 n = 0;
	ok = ok && rd(f, &n, 2);
	for (int k = 0; ok && k < n; k++) {
		u16 h;
		JcObj o;
		ok = rd(f, &h, 2) && h && h <= JC_OBJS && rd(f, &o, offsetof(JcObj, data));
		u32 size = jcObjSize(&o);
		o.data = ok ? calloc(size ? size : 1, 1) : NULL;
		ok = ok && o.data && rd(f, o.data, size);
		int cls = ok ? clsIn(vm, o.cls, map, npkgs) : -1;
		if (ok && cls < 0) { // a class of a package that is gone: the object goes too
			free(o.data);
			continue;
		}
		o.cls = cls;
		if (ok) {
			if (o.flags & (JO_RESET | JO_DESELECT)) memset(o.data, 0, size);
			vm->objs[h - 1] = o;
		} else {
			free(o.data);
		}
	}
	ok = ok && rd(f, &c->napplets, 1) && c->napplets <= JC_APPLETS && rd(f, c->applets, sizeof(JcApplet) * c->napplets);
	fclose(f);
	if (!ok) {
		jcCardInit();
		return false;
	}
	for (int i = 0; i < c->napplets; i++) // packages renumbered by the reload
		c->applets[i].pkg = c->applets[i].pkg < npkgs ? map[(int)c->applets[i].pkg] : -1;
	int k = 0;
	for (int i = 0; i < c->napplets; i++)
		if (c->applets[i].pkg >= 0) c->applets[k++] = c->applets[i];
	c->napplets = k;
	sysObjects();
	c->dirty = false;
	return true;
}
