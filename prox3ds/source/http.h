#pragma once
#include <3ds.h>

// HTTPS GET over the console's Wi-Fi (httpc) into path, at most max bytes. No certificate checks: the
// SSL module's root CAs may be too old (and the clock may be off), so callers must only fetch data a
// forgery can't do harm with. 1 = written, 0 = failed (why).
int httpGetFile(const char *url, const char *path, u32 max, char *why, u32 whyLen);
