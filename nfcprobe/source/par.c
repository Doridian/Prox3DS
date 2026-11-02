// parFor (par.h): one helper thread per other usable core, made for each call (a call is a whole
// table pass of a recovery, so the thread setup is noise).

#include "par.h"

#define MAX_HELPERS 3

typedef struct {
	void (*fn)(void *arg, int i);
	void *arg;
	int n;
	volatile int next;
} Par;

static __thread bool helper;

bool parMain(void)
{
	return !helper;
}

static void run(Par *p)
{
	for (int i; (i = __atomic_fetch_add(&p->next, 1, __ATOMIC_RELAXED)) < p->n;)
		p->fn(p->arg, i);
}

static void helperMain(void *arg)
{
	helper = true;
	run(arg);
	helper = false;
}

#ifdef __3DS__
#include <3ds.h>
#include "probe.h"

void parFor(int n, void (*fn)(void *arg, int i), void *arg)
{
	// Cores that took a thread before; core 1 needs a CPU time share for the app first. Cores that
	// refuse are dropped for good.
	static int usable = -1;
	if (usable < 0) {
		usable = 0;
		if (R_SUCCEEDED(APT_SetAppCpuTimeLimit(80))) usable |= 1 << 1;
		bool n3ds = false;
		APT_CheckNew3DS(&n3ds);
		if (n3ds) usable |= 1 << 2;
	}
	Par p = { fn, arg, n, 0 };
	Thread t[MAX_HELPERS];
	int nt = 0, self = svcGetProcessorID();
	s32 prio = 0x30;
	svcGetThreadPriority(&prio, CUR_THREAD_HANDLE);
	for (int core = 0; core < 4 && nt < MAX_HELPERS; core++) {
		if (core == self || !(usable & 1 << core)) continue;
		if ((t[nt] = threadCreate(helperMain, &p, 0x8000, prio, core, false))) nt++;
		else {
			usable &= ~(1 << core);
			logp("par: no thread on core %d\n", core);
		}
	}
	static bool told;
	if (!told) {
		told = true;
		logp("par: core %d + %d helper threads\n", self, nt);
	}
	run(&p);
	for (int i = 0; i < nt; i++) {
		threadJoin(t[i], U64_MAX);
		threadFree(t[i]);
	}
}

#else
// Host builds (the UI simulator, PC tests of crapto1): pthreads.
#include <pthread.h>

static void *hostMain(void *arg)
{
	helperMain(arg);
	return NULL;
}

void parFor(int n, void (*fn)(void *arg, int i), void *arg)
{
	Par p = { fn, arg, n, 0 };
	pthread_t t[MAX_HELPERS];
	int nt = 0;
	while (nt < MAX_HELPERS && !pthread_create(&t[nt], NULL, hostMain, &p)) nt++;
	run(&p);
	for (int i = 0; i < nt; i++) pthread_join(t[i], NULL);
}
#endif
