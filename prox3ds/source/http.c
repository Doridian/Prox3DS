// Downloads over httpc (the Amiibo figure list, pm3's iClass dictionaries).

#include <stdio.h>
#include <stdlib.h>

#include "http.h"

int httpGetFile(const char *url, const char *path, u32 max, char *why, u32 whyLen)
{
	Result r = httpcInit(0);
	if (R_FAILED(r)) return snprintf(why, whyLen, "httpc: %08lX", r), 0;
	httpcContext c;
	u32 status = 0, len = 0, cap = 64 << 10, got;
	u8 *buf = NULL;
	int ok = 0;
	if (R_FAILED(r = httpcOpenContext(&c, HTTPC_METHOD_GET, url, 1))) {
		httpcExit();
		return snprintf(why, whyLen, "httpc open: %08lX", r), 0;
	}
	httpcSetSSLOpt(&c, SSLCOPT_DisableVerify);
	httpcAddRequestHeaderField(&c, "User-Agent", "Prox3DS");
	if (R_FAILED(r = httpcBeginRequest(&c)) || R_FAILED(r = httpcGetResponseStatusCode(&c, &status))) {
		snprintf(why, whyLen, "request: %08lX", r);
		goto out;
	}
	if (status != 200) {
		snprintf(why, whyLen, "HTTP %lu", (unsigned long)status);
		goto out;
	}
	buf = malloc(cap);
	do {
		if (len == cap) {
			u8 *b = len < max ? realloc(buf, cap *= 2) : NULL;
			if (!b) {
				snprintf(why, whyLen, "too big (over %lu bytes)", (unsigned long)len);
				goto out;
			}
			buf = b;
		}
		got = 0;
		r = httpcDownloadData(&c, buf + len, cap - len, &got);
		len += got;
	} while (r == (Result)HTTPC_RESULTCODE_DOWNLOADPENDING);
	if (R_FAILED(r)) {
		snprintf(why, whyLen, "download: %08lX after %lu bytes", r, (unsigned long)len);
		goto out;
	}
	FILE *f = fopen(path, "wb");
	if (!f || fwrite(buf, 1, len, f) != len) {
		snprintf(why, whyLen, "can't write %s", path);
		if (f) fclose(f);
		goto out;
	}
	fclose(f);
	ok = 1;
out:
	free(buf);
	httpcCloseContext(&c);
	httpcExit();
	return ok;
}
