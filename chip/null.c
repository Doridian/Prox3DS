// Bisect helper: an SRAM init that does nothing.
int init(void);
__attribute__((section(".entry"), used)) int (*const entry)(void) = init;
int init(void) { return 0; }
