#pragma once
#include <3ds.h>

#include "mfc.h"
#include "scard.h"

// EMV contactless payment cards, read only (pm3 `emv reader` / `emv scan`): the PPSE directory (or the
// known AIDs one by one), each application's SELECT, GET PROCESSING OPTIONS with the PDOL filled the way
// a terminal does, the records the AFL names, GET DATA (ATC, PIN tries, log format) and the transaction
// log. No GENERATE AC: nothing is paid or signed. GPO does count up the card's transaction counter (ATC),
// like any tap at a terminal.

#define EMV_MAX_APPS 4
#define EMV_MAX_LOG 30
#define EMV_RAW 4096

enum { LOG_DATE = 1, LOG_TIME = 2, LOG_AMOUNT = 4, LOG_CUR = 8, LOG_COUNTRY = 16, LOG_TYPE = 32, LOG_ATC = 64,
	LOG_MERCHANT = 128 };

typedef struct {
	u8 has;              // LOG_*: what the log format holds
	u8 date[3], time[3]; // BCD YYMMDD, HHMMSS
	u8 amount[6];        // BCD, in the currency's minor unit
	u16 currency, country; // ISO 4217 / ISO 3166 numeric (as the BCD digits read)
	u8 type;             // 9C: 00 purchase, 01 cash, 09 cashback, 20 refund
	u16 atc;
	char merchant[24];
} EmvLog;

typedef struct {
	u8 aidLen, aid[16];
	char label[33];      // 9F12 (preferred name), else 50
	u8 prio;             // 87, 0 = none
	bool selected;       // SELECT answered 9000
	char why[64];        // what went wrong (SELECT / GPO / log), "" = nothing
	char pan[20];        // digits, "" = not found
	bool hasExp, hasEff;
	u8 exp[3], eff[3];   // BCD YYMMDD (from track 2: day 00)
	char name[27];       // 5F20, trimmed
	u16 country, currency; // 5F28, 9F42 (0 = none)
	int panSeq, svc;     // 5F34, service code; -1 = none
	bool hasAip;
	u16 aip;
	int atc, lastOnlineAtc, pinTries; // GET DATA / GPO; -1 = none
	u8 logSfi, logMax;   // 9F4D, logSfi 0 = no log
	int nlog, nrec;      // log entries, records read
	EmvLog log[EMV_MAX_LOG];
	// every answer, for the save file: kind u8 ('S' select, 'G' GPO, 'R' record, 'D' GET DATA, 'L' log),
	// p1 u8, p2 u8, len u16 (LE), data
	u16 rawLen;
	u8 raw[EMV_RAW];
} EmvApp;

typedef struct {
	bool ppse;           // the directory answered (else the known AIDs were tried)
	int napps;
	EmvApp app[EMV_MAX_APPS];
} EmvCard;

const char *emvWhy(void);
// In a job, card active: ISO-DEP, then everything above. 1 = at least one application, 0 = none / no
// ISO-DEP (emvWhy), -1 = monitor error.
int emvRead(EmvCard *e);
// SC_DIR/emv-<last 4 digits>.txt (numbered, never overwrites), the full card number in it.
bool emvSave(const EmvCard *e, char *path, u32 max);

const char *emvBrand(const u8 *aid, u32 len); // "Visa", "Mastercard", ...; "" unknown
const char *emvCountry(u16 code);             // "Germany"; NULL unknown
const char *emvCurrency(u16 code, int *digits); // "EUR" and its minor digits; NULL unknown (2 digits)
void emvAmount(const u8 bcd[6], u16 currency, char *out); // "12.34 EUR" (JPY / KRW / ISK: no minor unit); out: 32 chars
// The card number in groups of four from the left; masked: only the last four digits. out: 32 chars.
void emvPanText(const char *pan, bool full, char *out);
void emvAuthText(u16 aip, char *out); // "SDA DDA CDA, cardholder verification"; out: 64 chars
