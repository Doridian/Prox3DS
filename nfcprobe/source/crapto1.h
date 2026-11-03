#pragma once
#include <stdint.h>

// Crypto1 key recovery (crapto1 port), running on the ARM11. See tools/crapto1.py for the reference
// and NOTES.md for the nested attack. ks = enc_nt ^ nt_T (32 target-cipher keystream bits).
// Derived from crapto1 (C) 2008-2014 bla <blapost@gmail.com> and the Proxmark3 contributors, GPL; see CREDITS.md.

// The long recoveries (all but crapto1_nt_decrypt / crapto1_ks32) spread over every core (par.h), one
// at a time; their results are the same as on one core.
// Progress hook for them, may be NULL: called on the calling thread with 0..1000 as the work goes (the
// table setup is the first quarter); returning nonzero stops the recovery early (no candidates then).
extern int (*crapto1_tick)(int permille);

// Candidate 48-bit keys from one nested nonce; returns the count written to out (capped at max).
int crapto1_recover(uint32_t uid, uint32_t nt, uint32_t ks, uint64_t *out, int max);

// Recover the key from two nested nonces of the same target sector: recovers candidates from the
// first and keeps the one consistent with the second. Returns the 48-bit key, or 0 if none.
uint64_t crapto1_nested(uint32_t uid, uint32_t nt1, uint32_t ks1, uint32_t nt2, uint32_t ks2);
// The same with a choice of second nonces (nt2[j], ks2[j]): the first candidate consistent with any.
uint64_t crapto1_nested_any(uint32_t uid, uint32_t nt1, uint32_t ks1, const uint32_t *nt2, const uint32_t *ks2, int n2);

// FM11RF08S static encrypted nonce (NOTES.md): candidates from the clear static nonce nt, its
// encryption ntEnc under the unknown key, and the 4 raw encrypted parity bits (bit 0 = last byte,
// the only one that filters). Returns the count written to out (capped at max).
int crapto1_static(uint32_t uid, uint32_t nt, uint32_t ntEnc, int parEnc, uint64_t *out, int max);

// Clear nonce of a nested auth under a known key: ntEnc ^ the keystream with ntEnc fed back.
uint32_t crapto1_nt_decrypt(uint64_t key, uint32_t uid, uint32_t ntEnc);

// Forward keystream word: Crypto1(key) fed `in` (= uid ^ nt), as crypto1.py's word(). For checking
// a candidate against another nonce, or verifying a recovered key.
uint32_t crapto1_ks32(uint64_t key, uint32_t in);

// Darkside / common-prefix recovery, always-leak (par == 0) path (NOTES.md, tools/darkside.py): for a
// fixed tag nonce nt and the fixed on-wire reader nonce nrWire (last 3 bits cleared), ks3x[c] is the
// 4-bit NACK keystream observed with nt_diff = c (top 3 bits of nrWire's last byte = c). Returns a
// malloc'd, ascending, de-duplicated array of candidate 48-bit keys (caller frees) with the count in
// *n, or NULL on OOM or when stopped. The key is the one common to several runs with different nt: with in (an
// ascending list of nin keys, an earlier run's), only the candidates also in it are returned.
uint64_t *crapto1_darkside(uint32_t uid, uint32_t nt, uint32_t nrWire, const uint8_t ks3x[8], const uint64_t *in,
	int nin, int *n);
