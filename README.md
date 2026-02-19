# Masked AES Core — Architecture Report

## Architecture Summary

### Overview

A high-throughput masked AES-128/192/256 core supporting both encryption and
decryption with parameterizable masking order (NSHARES = 2 or 3).

The core uses **precomputed masked S-box lookup tables** to avoid any nonlinear
(GF(2^8) inversion) operations in the per-round datapath.  Each of the 16 byte
positions has its own 256-entry table, all looked up in parallel during each
round.

### State Machine

```
IDLE → PRECOMP → INIT → ROUNDS → DONE → IDLE
```

| Phase   | Description                                                                                     |
|---------|-------------------------------------------------------------------------------------------------|
| PRECOMP | Fill 16 masked S-box tables (16 entries/cycle × 16 cycles = 256 entries). Key expansion runs in parallel. For NSHARES=3, one extra cycle is used to generate the second mask set. |
| INIT    | Split input into shares, apply initial AddRoundKey.                                              |
| ROUNDS  | Nr cycles. Each round: SubBytes (table lookup) → ShiftRows → [Inv]MixColumns → AddRoundKey → Mask Correction. Last round omits MixColumns. |
| DONE    | XOR all shares to produce the output.                                                            |

### Masking Model

- **NSHARES=2**: `state_sh[0] = x ⊕ m[j]`,  `state_sh[1] = m[j]`
- **NSHARES=3**: `state_sh[0] = x ⊕ m1[j] ⊕ m2[j]`,  `state_sh[1] = m1[j]`,  `state_sh[2] = m2[j]`

The combined mask `Mc[j] = m1[j] (⊕ m2[j])` is used to address the precomputed
tables.  A **mask correction** step after each round's linear operations
restores the shares to their base-mask form, ensuring the table addressing
scheme remains valid across all rounds.

### Precomputed Masked S-Box Tables

For each byte position j (0..15) and address a (0..255):

- **Encryption**: `T_j[a] = SBOX_FWD(a ⊕ Mc[j]) ⊕ Mc[j]`
- **Decryption**: `T_j[a] = SBOX_INV(a ⊕ Mc[j]) ⊕ Mc[j]`

Only the table for the current operation mode (enc/dec) is precomputed.  Tables
store 8-bit values (share-0 output only); shares 1+ are the constant base masks.

### Key Schedule

The key schedule operates **unmasked** during the precompute phase.  This is a
deliberate practical-security tradeoff: the key is processed in the clear only
during precomputation (where no plaintext-dependent values are being processed),
while the actual round datapath — where state values are correlated with
input/output — remains fully masked.

Round keys are XORed into share-0 only during AddRoundKey, which preserves the
masking invariant without requiring key masking.

### Decryption Strategy

Decryption uses the **Equivalent Inverse Cipher** (FIPS-197 §5.3.5), which
reorders operations so that enc and dec share the same round structure:

```
[Inv]SubBytes → [Inv]ShiftRows → [Inv]MixColumns → AddRoundKey
```

Middle-round decryption keys are transformed through InvMixColumns
combinationally.

---

## Cycle Counts

| Mode     | Precompute | Init | Rounds (Nr) | Done | Total    |
|----------|-----------|------|-------------|------|----------|
| AES-128  | 16+1*     | 1    | 10          | 1    | **32**   |
| AES-192  | 16+1*     | 1    | 12          | 1    | **34**   |
| AES-256  | 16+1*     | 1    | 14          | 1    | **36**   |

(*) +1 for NSHARES=3 mask generation (adds 1 cycle):
AES-128=33, AES-192=35, AES-256=37.

The ENTRIES_PER_CYCLE parameter controls fill parallelism.  Reducing it halves
area but doubles precompute latency (e.g., ENTRIES_PER_CYCLE=8 → 32 precompute
cycles).

---

## Throughput / Latency Tradeoffs

- **One round per cycle** after precomputation — high throughput for
  single-block operations.
- **Precomputation amortization**: For applications processing many blocks with
  the same key and masks, the precompute cost is paid once.  In the current
  design, precompute runs per-operation; a future enhancement could cache tables
  when key/masks don't change.
- **ENTRIES_PER_CYCLE** trades area for precompute latency.  At 16 entries/cycle,
  the design instantiates 16×16 = 256 combinational S-box lookups during fill.
  Reducing to 8 halves this to 128 lookups but doubles fill time.

---

## Side-Channel Security Notes

### What IS protected

- The **round datapath** never recombines shares.  SubBytes uses table lookups
  addressed by share-0 (which is masked); shares 1+ carry only deterministic
  mask values.
- The **mask correction** step restores the same base masks every round, so
  power profiles of share-1/2 are data-independent.
- Output recombination happens only once at the end.

### What is NOT protected (practical tradeoffs)

1. **Key schedule is unmasked**.  An attacker probing during precompute could
   recover round keys.  Mitigations: power filtering during precompute, or
   extending the masked-table approach to key expansion.
2. **PRNG quality**: xorshift128 is fast but not cryptographically strong.
   For production, replace with an AES-CTR or ChaCha-based PRNG.
3. **No formal probing-model proof**.  The masking provides practical 1st-order
   (NSHARES=2) or 2nd-order (NSHARES=3) protection against power/EM analysis,
   but has not been verified against formal leakage models (e.g., SNI/PINI).
4. **Glitch sensitivity**: Combinational glitches in the ShiftRows/MixColumns
   path could cause transient share recombination.  Standard countermeasures
   (register barriers between nonlinear and linear stages) are not applied here
   for throughput reasons.

---

## File Structure

```
rtl/
  aes_pkg.sv              — Types, S-box tables, GF(2^8) helpers
  prng_simple.sv          — xorshift128 PRNG
  aes_sbox_precompute.sv  — 16 parallel masked S-box table fill + lookup
  aes_key_schedule.sv     — Key expansion (all round keys stored)
  aes_masked_core.sv      — Top-level: FSM, masking, round datapath

tb/
  tb_aes_masked_core.sv   — NIST vector tests, multi-seed, NSHARES=2+3

scripts/
  run_sim.sh              — ModelSim compile + run
```

---

## Verification Results

All 25 tests pass (ModelSim 2020.1):

| Config    | Tests | Status |
|-----------|-------|--------|
| NSHARES=2 | 14    | PASS   |
| NSHARES=3 | 11    | PASS   |

Tests cover: AES-128/192/256 × ENC/DEC × multiple random seeds × FIPS-197
Appendix B vector.  Ciphertext is deterministic regardless of mask seed, confirming
correct mask handling.
