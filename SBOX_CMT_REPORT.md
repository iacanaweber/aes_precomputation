# S-Box CMT Gate-Level Implementation Report

## Summary

The AES forward S-Box (SubBytes for encryption) has been replaced with the
Boyar-Matthews-Peralta combinational gate-level circuit (CMT, 113 gates).
The inverse S-Box (decryption path) continues to use the ROM lookup table
unchanged.

---

## Bit-Mapping Determination

The circuit reference lists inputs U0..U7 and outputs S3 S7 S0 S6 S4 S1 S2 S5
without explicitly stating the bit ordering relative to the AES byte convention.
Four candidate mappings were tested programmatically against all 256 FIPS-197
forward S-box values:

| Input mapping    | Output mapping    | Correct |
|------------------|-------------------|---------|
| Ui = in[i]       | out[i]   = Si     |   0/256 |
| Ui = in[i]       | out[7-i] = Si     |  16/256 |
| Ui = in[7-i]     | out[i]   = Si     |  16/256 |
| **Ui = in[7-i]** | **out[7-i] = Si** | **256/256** |

**Correct mapping:**

- Input:  `{U0,U1,U2,U3,U4,U5,U6,U7} = in[7:0]` — U0 is the MSB (`in[7]`),
  U7 is the LSB (`in[0]`).
- Output: `out = {S0,S1,S2,S3,S4,S5,S6,S7}` — S0 is the MSB (`out[7]`),
  S7 is the LSB (`out[0]`).

This reflects the CMT paper's convention where bit index increases from MSB to
LSB, consistent with the AES polynomial basis written as
`b7·x^7 + b6·x^6 + … + b0` where b7 is the leftmost (most significant) bit.

---

## Files Changed

| File | Change |
|------|--------|
| `rtl/aes_sbox_cmt.sv` | **New.** Standalone `aes_sbox_cmt` module: pure combinational, 113 gates (32 AND, 81 XOR/XNOR). |
| `rtl/aes_pkg.sv` | Added `sbox_fwd_cmt_fn()` function (same network, callable from procedural code). Updated `sub_word()` to call `sbox_fwd_cmt_fn()` instead of `SBOX_FWD[]`. |
| `rtl/aes_sbox_precompute.sv` | Encryption fill path: `SBOX_FWD[x]` → `sbox_fwd_cmt_fn(x)`. Decryption fill path unchanged (`SBOX_INV[x]`). |
| `tb/tb_aes_sbox_cmt.sv` | **New.** Unit test: checks all 256 inputs against `SBOX_FWD` table from `aes_pkg`. |
| `scripts/run_sim.sh` | Updated to compile `aes_sbox_cmt.sv` and run S-box unit test before the full core test. |

---

## Test Results

### Unit test (`tb_aes_sbox_cmt`)

```
ALL 256 ENTRIES CORRECT — PASS
Bit mapping verified: U0=in[7] (MSB), out={S0..S7} (S0=MSB)
```

### Integration test (`tb_aes_masked_core`)

```
TOTAL: 25 passed, 0 failed  *** ALL TESTS PASSED ***
```

Covers NSHARES=2 and NSHARES=3, AES-128/192/256, encryption and decryption,
multiple random mask seeds, and FIPS-197 Appendix B reference vectors. Cycle
counts are identical to the pre-CMT baseline.

---

## Timing / Area Notes

### Logic depth

- ROM lookup: 1–2 logic levels (address decode + output mux).
- CMT network: ~16–20 logic levels (inherent depth of the 113-gate Boolean
  network).

### Impact by path

| Path | Impact |
|------|--------|
| **Round datapath** | **None.** Rounds use the precomputed tables; CMT is not in the round critical path. |
| **Precompute fill** | CMT replaces the S-box ROM in the table-fill combinational logic. Fill is register-bounded (writes to SRAM/flop array) so the added depth extends the clock-to-Q settle window during fill cycles, not the overall throughput. If synthesising for high Fmax, retiming or a pipeline register after CMT but before the table write could be inserted. |
| **Key schedule `sub_word()`** | CMT is in the KS_EXPAND cycle critical path. For AES-256 this path appears at most once per expansion step. If KS timing is critical, a single register stage after `sub_word()` (shifting expansion by one cycle) resolves it without changing latency significantly. |

### Area

The 113-gate CMT network eliminates the 256×8-bit ROM for the forward S-box
(2048 bits of storage per S-box instance), trading area for a small increase
in combinational logic. For ASIC targets this is a net area win. For FPGA
targets the tradeoff depends on available block-RAM versus LUT resources.

---

## What Was NOT Changed

- The **inverse S-box** (`SBOX_INV` ROM lookup) is untouched.
- The `SBOX_FWD` localparam array remains in `aes_pkg.sv` for reference and
  for use by the unit test as the golden truth table.
- The masked round datapath (table lookup during rounds) is unchanged.
- External interface, latency, and cycle counts are identical to the baseline.
