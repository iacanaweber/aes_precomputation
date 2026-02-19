// =============================================================================
// Unit test for aes_inv_sbox_cmt
//   1. All 256 entries vs SBOX_INV golden table from aes_pkg.
//   2. Round-trip: InvSBox(SBox(x)) == x  for all x (uses aes_sbox_cmt).
// =============================================================================
`timescale 1ns/1ps

module tb_aes_inv_sbox_cmt;

  import aes_pkg::*;

  // Forward S-Box DUT (already verified)
  logic [7:0] fwd_in,  fwd_out;
  aes_sbox_cmt u_fwd (.in(fwd_in), .out(fwd_out));

  // Inverse S-Box DUT under test
  logic [7:0] inv_in,  inv_out;
  aes_inv_sbox_cmt u_inv (.in(inv_in), .out(inv_out));

  int pass_cnt, fail_cnt;

  initial begin
    pass_cnt = 0; fail_cnt = 0;

    $display("=====================================================");
    $display("  aes_inv_sbox_cmt — Full unit test");
    $display("=====================================================");

    // ------------------------------------------------------------------
    // Test 1: all 256 entries vs golden SBOX_INV table
    // ------------------------------------------------------------------
    $display("\n[1] All 256 entries vs SBOX_INV table:");
    for (int v = 0; v < 256; v++) begin
      inv_in = v[7:0];
      #1;
      if (inv_out === SBOX_INV[v]) begin
        pass_cnt++;
      end else begin
        $display("  FAIL: in=0x%02h  got=0x%02h  expected=0x%02h",
                 inv_in, inv_out, SBOX_INV[v]);
        fail_cnt++;
      end
    end
    $display("  Result: %0d/256 correct", 256 - fail_cnt);

    // ------------------------------------------------------------------
    // Test 2: round-trip InvSBox(SBox(x)) == x  for all x
    // ------------------------------------------------------------------
    begin
      int rt_fail;
      rt_fail = 0;
      $display("\n[2] Round-trip InvSBox(SBox(x)) == x:");
      for (int v = 0; v < 256; v++) begin
        fwd_in = v[7:0];
        #1;
        inv_in = fwd_out;
        #1;
        if (inv_out !== v[7:0]) begin
          $display("  FAIL round-trip: x=0x%02h  SBox=0x%02h  InvSBox=0x%02h",
                   v[7:0], fwd_out, inv_out);
          rt_fail++;
          fail_cnt++;
        end else begin
          pass_cnt++;
        end
      end
      $display("  Result: %0d/256 round-trips correct", 256 - rt_fail);
    end

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------
    $display("\n=====================================================");
    if (fail_cnt == 0) begin
      $display("ALL TESTS PASSED (%0d checks)", pass_cnt);
      $display("  Bit mapping: U0=in[7] (MSB), out={W0..W7} (W0=MSB)");
    end else begin
      $display("FAILURES: %0d", fail_cnt);
    end
    $display("=====================================================");
    $finish;
  end

endmodule
