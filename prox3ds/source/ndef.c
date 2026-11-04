// NDEF records and Type 2 TLVs, see ndef.h.

#include <stdio.h>
#include <string.h>

#include "ndef.h"

// NFC Forum URI RTD: the prefix codes (0 = none)
static const char *uriPrefix[] = {
	"", "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:", "ftp://anonymous:anonymous@",
	"ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:", "telnet://", "imap:",
	"rtsp://", "urn:", "pop:", "sip:", "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
	"irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
	"urn:nfc:",
};
#define NPREFIX (sizeof(uriPrefix) / sizeof(uriPrefix[0]))

int ndefFindTlv(const u8 *mem, u32 n, u32 *off, u32 *len)
{
	for (u32 i = 0; i < n;) {
		u8 t = mem[i++];
		if (t == 0x00) continue; // NULL TLV: no length
		if (t == 0xFE) return 0;  // terminator
		if (i >= n) return -1;
		u32 l = mem[i++];
		if (l == 0xFF) {
			if (i + 2 > n) return -1;
			l = mem[i] << 8 | mem[i + 1];
			i += 2;
		}
		if (i + l > n) return -1;
		if (t == 0x03) {
			*off = i, *len = l;
			return 1;
		}
		i += l; // 01 lock control, 02 memory control, FD proprietary
	}
	return 0;
}

int ndefParse(const u8 *msg, u32 len, NdefRec *recs, int max)
{
	int n = 0;
	for (u32 i = 0; i < len && n < max;) {
		u8 h = msg[i++];
		NdefRec *r = &recs[n];
		r->mb = h & 0x80, r->me = h & 0x40, r->chunk = h & 0x20, r->tnf = h & 7;
		bool sr = h & 0x10, il = h & 0x08;
		if (i >= len) return -1;
		r->typeLen = msg[i++];
		if (sr) {
			if (i >= len) return -1;
			r->payloadLen = msg[i++];
		} else {
			if (i + 4 > len) return -1;
			r->payloadLen = (u32)msg[i] << 24 | msg[i + 1] << 16 | msg[i + 2] << 8 | msg[i + 3];
			i += 4;
		}
		r->idLen = 0;
		if (il) {
			if (i >= len) return -1;
			r->idLen = msg[i++];
		}
		if (r->typeLen > len - i) return -1;
		r->type = msg + i, i += r->typeLen;
		if (r->idLen > len - i) return -1;
		r->id = msg + i, i += r->idLen;
		if (r->payloadLen > len - i) return -1;
		r->payload = msg + i, i += r->payloadLen;
		n++;
		if (r->me) break;
	}
	return n;
}

static bool isType(const NdefRec *r, const char *t)
{
	return r->typeLen == strlen(t) && !memcmp(r->type, t, r->typeLen);
}

// Printable (UTF-8 passes through, control bytes become '.')
static void clip(char *out, u32 max, const u8 *p, u32 n)
{
	u32 o = 0;
	for (u32 i = 0; i < n && o + 1 < max; i++) out[o++] = p[i] < 0x20 || p[i] == 0x7F ? '.' : p[i];
	out[o] = 0;
}

static void describeUri(const u8 *p, u32 n, char *out, u32 max)
{
	char rest[200];
	clip(rest, sizeof(rest), p + 1, n ? n - 1 : 0);
	snprintf(out, max, "%s%.150s", n && p[0] < NPREFIX ? uriPrefix[p[0]] : "?", rest);
}

void ndefDescribe(const NdefRec *r, char *out, u32 max)
{
	char a[200], b[64];
	if (r->chunk) {
		snprintf(out, max, "Chunked record (%lu bytes)", (unsigned long)r->payloadLen);
		return;
	}
	switch (r->tnf) {
	case 0:
		snprintf(out, max, "Empty record");
		return;
	case 1:
		if (isType(r, "U") && r->payloadLen) {
			describeUri(r->payload, r->payloadLen, a, sizeof(a));
			snprintf(out, max, "URI  %s", a);
		} else if (isType(r, "T") && r->payloadLen) {
			u8 st = r->payload[0];
			u32 ll = st & 0x3F;
			if (1 + ll > r->payloadLen) ll = r->payloadLen - 1;
			clip(b, sizeof(b), r->payload + 1, ll);
			if (st & 0x80) snprintf(out, max, "Text (%s, UTF-16, %lu bytes)", b, (unsigned long)(r->payloadLen - 1 - ll));
			else {
				clip(a, sizeof(a), r->payload + 1 + ll, r->payloadLen - 1 - ll);
				snprintf(out, max, "Text (%s)  %s", b, a);
			}
		} else if (isType(r, "Sp")) {
			NdefRec in[8];
			int k = ndefParse(r->payload, r->payloadLen, in, 8);
			a[0] = 0;
			for (int i = 0; i < k; i++)
				if (in[i].tnf == 1 && isType(&in[i], "U") && in[i].payloadLen) describeUri(in[i].payload, in[i].payloadLen, a, sizeof(a));
			snprintf(out, max, "Smart poster  %s", a[0] ? a : "(no URI)");
		} else {
			clip(b, sizeof(b), r->type, r->typeLen);
			snprintf(out, max, "Well-known \"%s\", %lu bytes", b, (unsigned long)r->payloadLen);
		}
		return;
	case 2:
		clip(b, sizeof(b), r->type, r->typeLen);
		snprintf(out, max, "MIME %s, %lu bytes", b, (unsigned long)r->payloadLen);
		return;
	case 3:
		clip(a, sizeof(a), r->type, r->typeLen);
		snprintf(out, max, "Absolute URI  %s", a);
		return;
	case 4:
		clip(b, sizeof(b), r->type, r->typeLen);
		if (isType(r, "android.com:pkg")) {
			clip(a, sizeof(a), r->payload, r->payloadLen);
			snprintf(out, max, "Android app  %s", a);
		} else {
			snprintf(out, max, "External %s, %lu bytes", b, (unsigned long)r->payloadLen);
		}
		return;
	default:
		snprintf(out, max, "TNF %d, %lu bytes", r->tnf, (unsigned long)r->payloadLen);
	}
}

// One record (MB ME), short (SR, payload < 256) or with the 4-byte payload length
static u32 record(u8 tnf, const char *type, const u8 *p1, u32 n1, const u8 *p2, u32 n2, u8 *out, u32 max)
{
	u32 tl = strlen(type), pl = n1 + n2, h = pl < 256 ? 3 : 6;
	if (h + tl + pl > max) return 0;
	out[0] = 0xC0 | (pl < 256 ? 0x10 : 0) | tnf;
	out[1] = tl;
	if (h == 3) out[2] = pl;
	else out[2] = pl >> 24, out[3] = pl >> 16, out[4] = pl >> 8, out[5] = pl;
	memcpy(out + h, type, tl);
	memcpy(out + h + tl, p1, n1);
	memcpy(out + h + tl + n1, p2, n2);
	return h + tl + pl;
}

u32 ndefUri(const char *uri, u8 *out, u32 max)
{
	u8 code = 0;
	u32 best = 0;
	for (u32 i = 1; i < NPREFIX; i++) {
		u32 l = strlen(uriPrefix[i]);
		if (l > best && !strncmp(uri, uriPrefix[i], l)) best = l, code = i;
	}
	return record(1, "U", &code, 1, (const u8 *)uri + best, strlen(uri) - best, out, max);
}

u32 ndefText(const char *lang, const char *text, u8 *out, u32 max)
{
	u8 st = strlen(lang) & 0x3F; // UTF-8
	u8 head[64];
	head[0] = st;
	memcpy(head + 1, lang, st);
	return record(1, "T", head, 1 + st, (const u8 *)text, strlen(text), out, max);
}

u32 ndefTlv(const u8 *msg, u32 len, u8 *out, u32 max)
{
	u32 h = len < 0xFF ? 2 : 4;
	if (len > 0xFFFE || h + len + 1 > max) return 0;
	out[0] = 0x03;
	if (h == 2) out[1] = len;
	else out[1] = 0xFF, out[2] = len >> 8, out[3] = len;
	memcpy(out + h, msg, len);
	out[h + len] = 0xFE;
	return h + len + 1;
}
