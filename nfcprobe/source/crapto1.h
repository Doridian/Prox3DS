#pragma once
#include <stdint.h>

// Crypto1 key recovery (crapto1 port), running on the ARM11. See tools/crapto1.py for the reference
// and NOTES.md for the nested attack. ks = enc_nt ^ nt_T (32 target-cipher keystream bits).

// Progress hook for the long recoveries (all but crapto1_nt_decrypt / crapto1_ks32), may be NULL:
// called with 0..1000 as the work goes (about a quarter is the table setup); returning nonzero stops
// the recovery early (no candidates then).
extern int (*crapto1_tick)(int permille);

// Candidate 48-bit keys from one nested nonce; returns the count written to out (capped at max).
int crapto1_recover(uint32_t uid, uint32_t nt, uint32_t ks, uint64_t *out, int max);

// Recover the key from two nested nonces of the same target sector: recovers candidates from the
// first and keeps the one consistent with the second. Returns the 48-bit key, or 0 if none.
uint64_t crapto1_nested(uint32_t uid, uint32_t nt1, uint32_t ks1, uint32_t nt2, uint32_t ks2);

// FM11RF08S static encrypted nonce (NOTES.md): candidates from the clear static nonce nt, its
// encryption ntEnc under the unknown key, and the 4 raw encrypted parity bits (bit 0 = last byte,
// the only one that filters). Returns the count written to out (capped at max).
int crapto1_static(uint32_t uid, uint32_t nt, uint32_t ntEnc, int parEnc, uint64_t *out, int max);

// Clear nonce of a nested auth under a known key: ntEnc ^ the keystream with ntEnc fed back.
uint32_t crapto1_nt_decrypt(uint64_t key, uint32_t uid, uint32_t ntEnc);

// Forward keystream word: Crypto1(key) fed `in` (= uid ^ nt), as crypto1.py's word(). For checking
// a candidate against another nonce, or verifying a recovered key.
uint32_t crapto1_ks32(uint64_t key, uint32_t in);
