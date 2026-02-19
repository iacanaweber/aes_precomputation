// =============================================================================
// Unit test for aes_sbox_cmt — checks all 256 input values against the
// golden AES forward S-box table from aes_pkg (FIPS-197).
// =============================================================================
`timescale 1ns/1ps

module tb_aes_sbox_cmt;

  import aes_pkg::*;

  logic [7:0] sbox_in, sbox_out;

  aes_sbox_cmt dut (
    .in  (sbox_in),
    .out (sbox_out)
  );

  int pass_cnt, fail_cnt;

  initial begin
    pass_cnt = 0;
    fail_cnt = 0;

    $display("=========================================");
    $display("  aes_sbox_cmt — Full 256-entry unit test");
    $display("=========================================");

    for (int v = 0; v < 256; v++) begin
      sbox_in = v[7:0];
      #1;  // allow combinational settle
      if (sbox_out === SBOX_FWD[v]) begin
        pass_cnt++;
      end else begin
        $display("FAIL: in=0x%02h  got=0x%02h  expected=0x%02h",
                 sbox_in, sbox_out, SBOX_FWD[v]);
        fail_cnt++;
      end
    end

    $display("-----------------------------------------");
    if (fail_cnt == 0) begin
      $display("ALL 256 ENTRIES CORRECT — PASS");
      $display("  Bit mapping verified: U0=in[7] (MSB), out={S0..S7} (S0=MSB)");
    end else begin
      $display("FAILURES: %0d / 256", fail_cnt);
    end
    $display("=========================================");
    $finish;
  end

endmodule
