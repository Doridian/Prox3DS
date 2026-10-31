#pragma once
#include <stdint.h>

// Crypto1 key recovery (crapto1 port), running on the ARM11. See tools/crapto1.py for the reference
// and NOTES.md for the nested attack. ks = enc_nt ^ nt_T (32 target-cipher keystream bits).

// Candidate 48-bit keys from one nested nonce; returns the count written to out (capped at max).
int crapto1_recover(uint32_t uid, uint32_t nt, uint32_t ks, uint64_t *out, int max);

// Recover the key from two nested nonces of the same target sector: recovers candidates from the
// first and keeps the one consistent with the second. Returns the 48-bit key, or 0 if none.
uint64_t crapto1_nested(uint32_t uid, uint32_t nt1, uint32_t ks1, uint32_t nt2, uint32_t ks2);

// Forward keystream word: Crypto1(key) fed `in` (= uid ^ nt), as crypto1.py's word(). For checking
// a candidate against another nonce, or verifying a recovered key.
uint32_t crapto1_ks32(uint64_t key, uint32_t in);
