// =============================================================================
// Unit test for sbox_inv_cmt_fn — calls the aes_pkg function directly.
//   1. All 256 entries vs FIPS-197 inverse S-box golden table embedded here.
//   2. Round-trip: sbox_inv_cmt_fn(sbox_fwd_cmt_fn(x)) == x  for all x.
// No module instantiation needed.
// =============================================================================
`timescale 1ns/1ps

module tb_aes_inv_sbox_cmt;

  import aes_pkg::*;

  // FIPS-197 inverse S-box golden reference
  localparam logic [7:0] GOLDEN_INV [0:255] = '{
    8'h52, 8'h09, 8'h6a, 8'hd5, 8'h30, 8'h36, 8'ha5, 8'h38,
    8'hbf, 8'h40, 8'ha3, 8'h9e, 8'h81, 8'hf3, 8'hd7, 8'hfb,
    8'h7c, 8'he3, 8'h39, 8'h82, 8'h9b, 8'h2f, 8'hff, 8'h87,
    8'h34, 8'h8e, 8'h43, 8'h44, 8'hc4, 8'hde, 8'he9, 8'hcb,
    8'h54, 8'h7b, 8'h94, 8'h32, 8'ha6, 8'hc2, 8'h23, 8'h3d,
    8'hee, 8'h4c, 8'h95, 8'h0b, 8'h42, 8'hfa, 8'hc3, 8'h4e,
    8'h08, 8'h2e, 8'ha1, 8'h66, 8'h28, 8'hd9, 8'h24, 8'hb2,
    8'h76, 8'h5b, 8'ha2, 8'h49, 8'h6d, 8'h8b, 8'hd1, 8'h25,
    8'h72, 8'hf8, 8'hf6, 8'h64, 8'h86, 8'h68, 8'h98, 8'h16,
    8'hd4, 8'ha4, 8'h5c, 8'hcc, 8'h5d, 8'h65, 8'hb6, 8'h92,
    8'h6c, 8'h70, 8'h48, 8'h50, 8'hfd, 8'hed, 8'hb9, 8'hda,
    8'h5e, 8'h15, 8'h46, 8'h57, 8'ha7, 8'h8d, 8'h9d, 8'h84,
    8'h90, 8'hd8, 8'hab, 8'h00, 8'h8c, 8'hbc, 8'hd3, 8'h0a,
    8'hf7, 8'he4, 8'h58, 8'h05, 8'hb8, 8'hb3, 8'h45, 8'h06,
    8'hd0, 8'h2c, 8'h1e, 8'h8f, 8'hca, 8'h3f, 8'h0f, 8'h02,
    8'hc1, 8'haf, 8'hbd, 8'h03, 8'h01, 8'h13, 8'h8a, 8'h6b,
    8'h3a, 8'h91, 8'h11, 8'h41, 8'h4f, 8'h67, 8'hdc, 8'hea,
    8'h97, 8'hf2, 8'hcf, 8'hce, 8'hf0, 8'hb4, 8'he6, 8'h73,
    8'h96, 8'hac, 8'h74, 8'h22, 8'he7, 8'had, 8'h35, 8'h85,
    8'he2, 8'hf9, 8'h37, 8'he8, 8'h1c, 8'h75, 8'hdf, 8'h6e,
    8'h47, 8'hf1, 8'h1a, 8'h71, 8'h1d, 8'h29, 8'hc5, 8'h89,
    8'h6f, 8'hb7, 8'h62, 8'h0e, 8'haa, 8'h18, 8'hbe, 8'h1b,
    8'hfc, 8'h56, 8'h3e, 8'h4b, 8'hc6, 8'hd2, 8'h79, 8'h20,
    8'h9a, 8'hdb, 8'hc0, 8'hfe, 8'h78, 8'hcd, 8'h5a, 8'hf4,
    8'h1f, 8'hdd, 8'ha8, 8'h33, 8'h88, 8'h07, 8'hc7, 8'h31,
    8'hb1, 8'h12, 8'h10, 8'h59, 8'h27, 8'h80, 8'hec, 8'h5f,
    8'h60, 8'h51, 8'h7f, 8'ha9, 8'h19, 8'hb5, 8'h4a, 8'h0d,
    8'h2d, 8'he5, 8'h7a, 8'h9f, 8'h93, 8'hc9, 8'h9c, 8'hef,
    8'ha0, 8'he0, 8'h3b, 8'h4d, 8'hae, 8'h2a, 8'hf5, 8'hb0,
    8'hc8, 8'heb, 8'hbb, 8'h3c, 8'h83, 8'h53, 8'h99, 8'h61,
    8'h17, 8'h2b, 8'h04, 8'h7e, 8'hba, 8'h77, 8'hd6, 8'h26,
    8'he1, 8'h69, 8'h14, 8'h63, 8'h55, 8'h21, 8'h0c, 8'h7d
  };

  int pass_cnt, fail_cnt;
  logic [7:0] result;

  initial begin
    pass_cnt = 0; fail_cnt = 0;

    $display("=====================================================");
    $display("  sbox_inv_cmt_fn — Full unit test");
    $display("=====================================================");

    // ------------------------------------------------------------------
    // Test 1: all 256 entries vs golden GOLDEN_INV table
    // ------------------------------------------------------------------
    $display("\n[1] All 256 entries vs GOLDEN_INV table:");
    begin
      int local_fail;
      local_fail = 0;
      for (int v = 0; v < 256; v++) begin
        result = sbox_inv_cmt_fn(v[7:0]);
        if (result === GOLDEN_INV[v]) begin
          pass_cnt++;
        end else begin
          $display("  FAIL: in=0x%02h  got=0x%02h  expected=0x%02h",
                   v[7:0], result, GOLDEN_INV[v]);
          fail_cnt++;
          local_fail++;
        end
      end
      $display("  Result: %0d/256 correct", 256 - local_fail);
    end

    // ------------------------------------------------------------------
    // Test 2: round-trip sbox_inv_cmt_fn(sbox_fwd_cmt_fn(x)) == x
    // ------------------------------------------------------------------
    $display("\n[2] Round-trip InvSBox(SBox(x)) == x:");
    begin
      int rt_fail;
      logic [7:0] fwd_result;
      rt_fail = 0;
      for (int v = 0; v < 256; v++) begin
        fwd_result = sbox_fwd_cmt_fn(v[7:0]);
        result     = sbox_inv_cmt_fn(fwd_result);
        if (result !== v[7:0]) begin
          $display("  FAIL round-trip: x=0x%02h  SBox=0x%02h  InvSBox=0x%02h",
                   v[7:0], fwd_result, result);
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
