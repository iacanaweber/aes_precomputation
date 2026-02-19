// =============================================================================
// Testbench for aes_masked_core
//   — NIST FIPS-197 test vectors
//   — Encryption + Decryption for AES-128/192/256
//   — Multiple random seeds to verify mask independence
//   — Tests both NSHARES=2 and NSHARES=3
// =============================================================================
`timescale 1ns/1ps

module tb_aes_masked_core;

  import aes_pkg::*;

  // -----------------------------------------------------------------------
  // DUT signals — NSHARES=2
  // -----------------------------------------------------------------------
  logic          clk, rst_n;
  logic          start2;
  logic          enc_dec2;
  key_size_e     key_size2;
  logic [127:0]  pt2, pt_rand2;
  logic [255:0]  key2, key_rand2;
  logic          busy2, done2, valid2;
  logic [127:0]  ct2;

  aes_masked_core #(.NSHARES(2), .ENTRIES_PER_CYCLE(16)) dut2 (
    .clk(clk), .rst_n(rst_n),
    .start_i(start2), .enc_dec_i(enc_dec2), .key_size_i(key_size2),
    .pt_i(pt2), .pt_rand_i(pt_rand2), .key_i(key2), .key_rand_i(key_rand2),
    .busy_o(busy2), .done_o(done2), .valid_o(valid2), .ct_o(ct2)
  );

  // -----------------------------------------------------------------------
  // DUT signals — NSHARES=3
  // -----------------------------------------------------------------------
  logic          start3;
  logic          enc_dec3;
  key_size_e     key_size3;
  logic [127:0]  pt3, pt_rand3;
  logic [255:0]  key3, key_rand3;
  logic          busy3, done3, valid3;
  logic [127:0]  ct3;

  aes_masked_core #(.NSHARES(3), .ENTRIES_PER_CYCLE(16)) dut3 (
    .clk(clk), .rst_n(rst_n),
    .start_i(start3), .enc_dec_i(enc_dec3), .key_size_i(key_size3),
    .pt_i(pt3), .pt_rand_i(pt_rand3), .key_i(key3), .key_rand_i(key_rand3),
    .busy_o(busy3), .done_o(done3), .valid_o(valid3), .ct_o(ct3)
  );

  // -----------------------------------------------------------------------
  // Clock
  // -----------------------------------------------------------------------
  initial clk = 0;
  always #5 clk = ~clk;

  // -----------------------------------------------------------------------
  // Test infrastructure
  // -----------------------------------------------------------------------
  int total_pass = 0;
  int total_fail = 0;

  task automatic run_test_n2(
    input string       label,
    input logic        do_enc_dec,
    input key_size_e   do_key_size,
    input logic [255:0] do_key,
    input logic [127:0] do_pt,
    input logic [127:0] expected,
    input logic [127:0] rand_seed,
    input logic [255:0] krand_seed
  );
    int cycle_cnt;
    @(posedge clk);
    enc_dec2  = do_enc_dec;
    key_size2 = do_key_size;
    key2      = do_key;
    pt2       = do_pt;
    pt_rand2  = rand_seed;
    key_rand2 = krand_seed;
    start2    = 1'b1;
    @(posedge clk);
    start2    = 1'b0;
    cycle_cnt = 0;
    while (!done2) begin
      @(posedge clk);
      cycle_cnt++;
      if (cycle_cnt > 500) begin
        $display("TIMEOUT: %s", label);
        total_fail++;
        return;
      end
    end
    if (ct2 === expected) begin
      $display("PASS: %-50s cycles=%0d", label, cycle_cnt);
      total_pass++;
    end else begin
      $display("FAIL: %-50s", label);
      $display("  Expected: %h", expected);
      $display("  Got:      %h", ct2);
      total_fail++;
    end
  endtask

  task automatic run_test_n3(
    input string       label,
    input logic        do_enc_dec,
    input key_size_e   do_key_size,
    input logic [255:0] do_key,
    input logic [127:0] do_pt,
    input logic [127:0] expected,
    input logic [127:0] rand_seed,
    input logic [255:0] krand_seed
  );
    int cycle_cnt;
    @(posedge clk);
    enc_dec3  = do_enc_dec;
    key_size3 = do_key_size;
    key3      = do_key;
    pt3       = do_pt;
    pt_rand3  = rand_seed;
    key_rand3 = krand_seed;
    start3    = 1'b1;
    @(posedge clk);
    start3    = 1'b0;
    cycle_cnt = 0;
    while (!done3) begin
      @(posedge clk);
      cycle_cnt++;
      if (cycle_cnt > 500) begin
        $display("TIMEOUT: %s", label);
        total_fail++;
        return;
      end
    end
    if (ct3 === expected) begin
      $display("PASS: %-50s cycles=%0d", label, cycle_cnt);
      total_pass++;
    end else begin
      $display("FAIL: %-50s", label);
      $display("  Expected: %h", expected);
      $display("  Got:      %h", ct3);
      total_fail++;
    end
  endtask

  // -----------------------------------------------------------------------
  // NIST Test Vectors
  // -----------------------------------------------------------------------
  localparam logic [255:0] KEY_128 = {128'h2b7e1516_28aed2a6_abf71588_09cf4f3c, 128'h0};
  localparam logic [127:0] PT_NIST = 128'h6bc1bee2_2e409f96_e93d7e11_7393172a;
  localparam logic [127:0] CT_128  = 128'h3ad77bb4_0d7a3660_a89ecaf3_2466ef97;

  localparam logic [255:0] KEY_192 = {192'h8e73b0f7_da0e6452_c810f32b_809079e5_62f8ead2_522c6b7b, 64'h0};
  localparam logic [127:0] CT_192  = 128'hbd334f1d_6e45f25f_f712a214_571fa5cc;

  localparam logic [255:0] KEY_256 = 256'h603deb10_15ca71be_2b73aef0_857d7781_1f352c07_3b6108d7_2d9810a3_0914dff4;
  localparam logic [127:0] CT_256  = 128'hf3eed1bd_b5d2a03c_064b5a7e_3db181f8;

  // FIPS-197 Appendix B
  localparam logic [255:0] KEY_APP_B = {128'h0001_0203_0405_0607_0809_0a0b_0c0d_0e0f, 128'h0};
  localparam logic [127:0] PT_APP_B  = 128'h0011_2233_4455_6677_8899_aabb_ccdd_eeff;
  localparam logic [127:0] CT_APP_B  = 128'h69c4_e0d8_6a7b_0430_d8cd_b780_70b4_c55a;

  localparam logic [127:0] SEED_CAFE = 128'hCAFEBABE_DEADBEEF_12345678_AABBCCDD;
  localparam logic [127:0] SEED_R1   = 128'h11223344_55667788_99AABBCC_DDEEFF00;

  // -----------------------------------------------------------------------
  // Main
  // -----------------------------------------------------------------------
  initial begin
    rst_n = 0;
    start2 = 0; enc_dec2 = 0; key_size2 = AES_128;
    pt2 = '0; key2 = '0; pt_rand2 = '0; key_rand2 = '0;
    start3 = 0; enc_dec3 = 0; key_size3 = AES_128;
    pt3 = '0; key3 = '0; pt_rand3 = '0; key_rand3 = '0;
    repeat (5) @(posedge clk);
    rst_n = 1;
    repeat (2) @(posedge clk);

    // ===== NSHARES = 2 =====
    $display("==========================================================");
    $display("  NSHARES = 2");
    $display("==========================================================");

    $display("\n--- AES-128 Encryption ---");
    run_test_n2("N2 AES-128 ENC seed=0",     0, AES_128, KEY_128, PT_NIST, CT_128, '0, '0);
    run_test_n2("N2 AES-128 ENC seed=CAFE",  0, AES_128, KEY_128, PT_NIST, CT_128, SEED_CAFE, 256'hFF);
    run_test_n2("N2 AES-128 ENC seed=R1",    0, AES_128, KEY_128, PT_NIST, CT_128, SEED_R1, 256'hAA);

    $display("\n--- AES-128 Decryption ---");
    run_test_n2("N2 AES-128 DEC seed=0",     1, AES_128, KEY_128, CT_128, PT_NIST, '0, '0);
    run_test_n2("N2 AES-128 DEC seed=CAFE",  1, AES_128, KEY_128, CT_128, PT_NIST, SEED_CAFE, 256'hFF);

    $display("\n--- AES-192 ---");
    run_test_n2("N2 AES-192 ENC seed=0",     0, AES_192, KEY_192, PT_NIST, CT_192, '0, '0);
    run_test_n2("N2 AES-192 ENC seed=CAFE",  0, AES_192, KEY_192, PT_NIST, CT_192, SEED_CAFE, 256'hFF);
    run_test_n2("N2 AES-192 DEC seed=0",     1, AES_192, KEY_192, CT_192, PT_NIST, '0, '0);

    $display("\n--- AES-256 ---");
    run_test_n2("N2 AES-256 ENC seed=0",     0, AES_256, KEY_256, PT_NIST, CT_256, '0, '0);
    run_test_n2("N2 AES-256 ENC seed=CAFE",  0, AES_256, KEY_256, PT_NIST, CT_256, SEED_CAFE, 256'hFF);
    run_test_n2("N2 AES-256 DEC seed=0",     1, AES_256, KEY_256, CT_256, PT_NIST, '0, '0);
    run_test_n2("N2 AES-256 DEC seed=CAFE",  1, AES_256, KEY_256, CT_256, PT_NIST, SEED_CAFE, 256'hFF);

    $display("\n--- FIPS-197 Appendix B ---");
    run_test_n2("N2 FIPS197-B ENC",           0, AES_128, KEY_APP_B, PT_APP_B, CT_APP_B, '0, '0);
    run_test_n2("N2 FIPS197-B DEC",           1, AES_128, KEY_APP_B, CT_APP_B, PT_APP_B, '0, '0);

    // ===== NSHARES = 3 =====
    $display("\n==========================================================");
    $display("  NSHARES = 3");
    $display("==========================================================");

    $display("\n--- AES-128 ---");
    run_test_n3("N3 AES-128 ENC seed=0",     0, AES_128, KEY_128, PT_NIST, CT_128, '0, '0);
    run_test_n3("N3 AES-128 ENC seed=CAFE",  0, AES_128, KEY_128, PT_NIST, CT_128, SEED_CAFE, 256'hFF);
    run_test_n3("N3 AES-128 DEC seed=0",     1, AES_128, KEY_128, CT_128, PT_NIST, '0, '0);
    run_test_n3("N3 AES-128 DEC seed=CAFE",  1, AES_128, KEY_128, CT_128, PT_NIST, SEED_CAFE, 256'hFF);

    $display("\n--- AES-192 ---");
    run_test_n3("N3 AES-192 ENC seed=0",     0, AES_192, KEY_192, PT_NIST, CT_192, '0, '0);
    run_test_n3("N3 AES-192 DEC seed=0",     1, AES_192, KEY_192, CT_192, PT_NIST, '0, '0);

    $display("\n--- AES-256 ---");
    run_test_n3("N3 AES-256 ENC seed=0",     0, AES_256, KEY_256, PT_NIST, CT_256, '0, '0);
    run_test_n3("N3 AES-256 ENC seed=CAFE",  0, AES_256, KEY_256, PT_NIST, CT_256, SEED_CAFE, 256'hFF);
    run_test_n3("N3 AES-256 DEC seed=0",     1, AES_256, KEY_256, CT_256, PT_NIST, '0, '0);

    $display("\n--- FIPS-197 Appendix B ---");
    run_test_n3("N3 FIPS197-B ENC",           0, AES_128, KEY_APP_B, PT_APP_B, CT_APP_B, '0, '0);
    run_test_n3("N3 FIPS197-B DEC",           1, AES_128, KEY_APP_B, CT_APP_B, PT_APP_B, SEED_R1, '0);

    // ===== Summary =====
    $display("\n==========================================================");
    $display("  TOTAL: %0d passed, %0d failed", total_pass, total_fail);
    $display("==========================================================");
    if (total_fail > 0) $display("*** SOME TESTS FAILED ***");
    else                $display("*** ALL TESTS PASSED ***");

    $finish;
  end

endmodule
