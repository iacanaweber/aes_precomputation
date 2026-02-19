# Inverse S-Box CMT Gate-Level Implementation Report

## Summary

The AES inverse S-Box (InvSubBytes for decryption) has been replaced with the
Boyar-Matthews-Peralta combinational gate-level circuit. The forward S-Box
(encryption) is unchanged.

---

## Bit-Mapping Determination

Four candidate mappings were tested against all 256 FIPS-197 inverse S-box
values:

| Input mapping    | Output mapping    | Correct |
|------------------|-------------------|---------|
| Ui = in[i]       | out[i]   = Wi     |   0/256 |
| Ui = in[i]       | out[7-i] = Wi     |  16/256 |
| Ui = in[7-i]     | out[i]   = Wi     |  16/256 |
| **Ui = in[7-i]** | **out[7-i] = Wi** | **256/256** |

**Correct mapping — identical to the forward S-Box:**

- Input:  `{U0,U1,U2,U3,U4,U5,U6,U7} = in[7:0]` — U0 is MSB (`in[7]`).
- Output: `out = {W0,W1,W2,W3,W4,W5,W6,W7}` — W0 is MSB (`out[7]`).

The inverse and forward S-Box circuits share the same bit convention, which is
consistent and expected: both implement functions over the same GF(2^8) element
representation.

---

## Files Changed

| File | Change |
|------|--------|
| `rtl/aes_inv_sbox_cmt.sv` | **New.** Standalone `aes_inv_sbox_cmt` module. |
| `rtl/aes_pkg.sv` | Added `sbox_inv_cmt_fn()` function (callable from procedural code). |
| `rtl/aes_sbox_precompute.sv` | Decryption fill path: `SBOX_INV[x]` → `sbox_inv_cmt_fn(x)`. |
| `tb/tb_aes_inv_sbox_cmt.sv` | **New.** Unit test: 256 entries vs table + 256 round-trip checks. |
| `scripts/run_sim.sh` | Added inverse S-box unit test as step 2 of 3. |

The `SBOX_INV` localparam array is retained in `aes_pkg.sv` for reference and
use as the unit-test golden truth table.

---

## Test Results

### Unit test (`tb_aes_inv_sbox_cmt`)

```
[1] All 256 entries vs SBOX_INV table:   256/256 correct
[2] Round-trip InvSBox(SBox(x)) == x:    256/256 round-trips correct
ALL TESTS PASSED (512 checks)
```

### Integration test (`tb_aes_masked_core`)

```
TOTAL: 25 passed, 0 failed  *** ALL TESTS PASSED ***
```

AES-128/192/256 × enc/dec × NSHARES=2 and 3 × multiple mask seeds.
Cycle counts unchanged from baseline.

---

## Timing / Area Notes

### Gate count

The inverse S-Box CMT network is larger than the forward:

| Circuit    | AND gates | XOR/XNOR gates | Total |
|------------|-----------|----------------|-------|
| Forward    | 32        | 81             | 113   |
| Inverse    | ~38       | ~102           | ~140  |

### Logic depth

Both circuits have similar depth (~16–20 levels), inherent to the
tower-field decomposition. Neither is materially different from the other.

### Impact by path

| Path | Impact |
|------|--------|
| **Round datapath** | **None.** Rounds use precomputed tables; neither CMT circuit is in the round critical path. |
| **Precompute fill (dec)** | Inverse CMT replaces the `SBOX_INV` ROM in the decryption table-fill path. Same register-bounded constraint as for the forward S-Box: the additional depth sits between combinational logic and a sequential write, and does not affect throughput. |
| **Key schedule** | Key expansion uses only the forward S-Box (`sub_word`). No change. |

### Area

Both S-Box ROM tables (2 × 256 × 8 = 4096 bits of storage) are now fully
eliminated and replaced with combinational logic. This is a net area win on
most ASIC targets and ROM-constrained FPGAs.

---

## What Was NOT Changed

- Forward S-Box (`aes_sbox_cmt`, `sbox_fwd_cmt_fn`) is unchanged.
- External AES core interface, latency, and cycle counts are identical.
- `SBOX_FWD` and `SBOX_INV` localparam arrays kept in `aes_pkg.sv` for
  reference and unit-test golden truth.
