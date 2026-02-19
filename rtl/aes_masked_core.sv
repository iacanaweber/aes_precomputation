// =============================================================================
// Masked AES Core — top-level
//
// Architecture:
//   IDLE → PRECOMP → INIT → ROUNDS → DONE → IDLE
//
//   PRECOMP : Fill 16 masked S-box tables + expand key schedule in parallel.
//   INIT    : Split input into shares, apply initial AddRoundKey.
//   ROUNDS  : Nr cycles: SubBytes(table) → ShiftRows → [Inv]MixColumns
//             → AddRoundKey → mask correction.  Last round omits MixColumns.
//   DONE    : Recombine shares → output.
//
// Decryption uses the Equivalent Inverse Cipher so enc/dec share the same
// round structure.  Dec middle-round keys are transformed through
// InvMixColumns combinationally.
//
// Parameters:
//   NSHARES            — 2 or 3
//   ENTRIES_PER_CYCLE  — S-box table fill parallelism (default 16)
// =============================================================================
module aes_masked_core
  import aes_pkg::*;
#(
  parameter int NSHARES          = 2,
  parameter int ENTRIES_PER_CYCLE = 16
) (
  input  logic          clk,
  input  logic          rst_n,
  input  logic          start_i,
  input  logic          enc_dec_i,     // 0 = encrypt, 1 = decrypt
  input  key_size_e     key_size_i,
  input  logic [127:0]  pt_i,
  input  logic [127:0]  pt_rand_i,
  input  logic [255:0]  key_i,
  input  logic [255:0]  key_rand_i,
  output logic          busy_o,
  output logic          done_o,
  output logic          valid_o,
  output logic [127:0]  ct_o
);

  // =========================================================================
  // FSM
  // =========================================================================
  typedef enum logic [2:0] {S_IDLE, S_PRECOMP, S_INIT, S_ROUNDS, S_DONE} state_e;
  state_e        fsm_state;
  logic          enc_dec_r;
  key_size_e     key_size_r;
  int unsigned   nr_r;
  int unsigned   round_cnt;

  // =========================================================================
  // PRNG
  // =========================================================================
  logic          prng_seed_en, prng_gen_en;
  logic [127:0]  prng_data;

  prng_simple u_prng (
    .clk       (clk),
    .rst_n     (rst_n),
    .seed_en_i (prng_seed_en),
    .seed_i    (pt_rand_i ^ key_rand_i[255:128]),
    .gen_en_i  (prng_gen_en),
    .data_o    (prng_data)
  );

  // =========================================================================
  // Base masks
  // =========================================================================
  logic [7:0] mask1 [0:15];
  logic [7:0] mask2 [0:15];
  logic [7:0] mc    [0:15];   // combined mask
  logic       masks_latched;
  logic       masks_phase2_done;  // for NSHARES==3

  // =========================================================================
  // S-box precompute
  // =========================================================================
  logic        sbox_start, sbox_done;
  logic [7:0]  sbox_addr [0:15];
  logic [7:0]  sbox_data [0:15];

  aes_sbox_precompute #(.ENTRIES_PER_CYCLE(ENTRIES_PER_CYCLE)) u_sbox_pre (
    .clk(clk), .rst_n(rst_n),
    .start_i(sbox_start), .enc_dec_i(enc_dec_r), .done_o(sbox_done),
    .mc_i(mc), .addr_i(sbox_addr), .data_o(sbox_data)
  );

  // =========================================================================
  // Key schedule
  // =========================================================================
  logic        ks_start, ks_done;
  logic [3:0]  rk_idx;
  logic [127:0] rk_data;

  aes_key_schedule u_ks (
    .clk(clk), .rst_n(rst_n),
    .start_i(ks_start), .key_size_i(key_size_r), .key_i(key_i),
    .done_o(ks_done), .rk_idx_i(rk_idx), .rk_data_o(rk_data)
  );

  // =========================================================================
  // State shares
  // =========================================================================
  logic [127:0] sh0, sh1, sh2;

  // =========================================================================
  // Round datapath — purely combinational
  // =========================================================================
  logic [127:0] sh0_next, sh1_next, sh2_next;
  logic [127:0] sb_sh0;

  // SubBytes lookup: drive addresses from sh0, read results
  always_comb begin
    integer j;
    sb_sh0 = '0;
    for (j = 0; j < 16; j++) begin
      sbox_addr[j] = get_byte(sh0, j);
      sb_sh0[127 - j*8 -: 8] = sbox_data[j];
    end
  end

  // Linear ops + AddRoundKey + mask correction
  always_comb begin
    integer j;
    logic [127:0] s0_sb, s1_sb, s2_sb;
    logic [127:0] s0_sr, s1_sr, s2_sr;
    logic [127:0] s0_mc, s1_mc, s2_mc;
    logic [127:0] round_key;
    logic [127:0] s0_ark;
    logic         last_round;
    logic [7:0]   d1, d2;

    sh0_next = sh0;
    sh1_next = sh1;
    sh2_next = sh2;

    if (fsm_state == S_ROUNDS) begin
      // 1) SubBytes results
      s0_sb = sb_sh0;
      s1_sb = '0;
      s2_sb = '0;
      for (j = 0; j < 16; j++) begin
        s1_sb[127 - j*8 -: 8] = mask1[j];
        if (NSHARES == 3)
          s2_sb[127 - j*8 -: 8] = mask2[j];
      end

      // 2) ShiftRows / InvShiftRows
      if (!enc_dec_r) begin
        s0_sr = shift_rows(s0_sb);
        s1_sr = shift_rows(s1_sb);
        s2_sr = (NSHARES == 3) ? shift_rows(s2_sb) : '0;
      end else begin
        s0_sr = inv_shift_rows(s0_sb);
        s1_sr = inv_shift_rows(s1_sb);
        s2_sr = (NSHARES == 3) ? inv_shift_rows(s2_sb) : '0;
      end

      // 3) MixColumns (skip on last round)
      last_round = (round_cnt == nr_r);
      if (!last_round) begin
        if (!enc_dec_r) begin
          s0_mc = mix_columns_128(s0_sr);
          s1_mc = mix_columns_128(s1_sr);
          s2_mc = (NSHARES == 3) ? mix_columns_128(s2_sr) : '0;
        end else begin
          s0_mc = inv_mix_columns_128(s0_sr);
          s1_mc = inv_mix_columns_128(s1_sr);
          s2_mc = (NSHARES == 3) ? inv_mix_columns_128(s2_sr) : '0;
        end
      end else begin
        s0_mc = s0_sr;
        s1_mc = s1_sr;
        s2_mc = s2_sr;
      end

      // 4) AddRoundKey (share 0 only)
      round_key = rk_data;
      if (enc_dec_r && !last_round)
        round_key = inv_mix_columns_128(round_key);
      s0_ark = s0_mc ^ round_key;

      // 5) Mask correction
      sh0_next = '0;
      sh1_next = '0;
      sh2_next = '0;
      for (j = 0; j < 16; j++) begin
        d1 = s1_mc[127 - j*8 -: 8] ^ mask1[j];
        d2 = (NSHARES == 3) ? (s2_mc[127 - j*8 -: 8] ^ mask2[j]) : 8'h0;
        sh0_next[127 - j*8 -: 8] = s0_ark[127 - j*8 -: 8] ^ d1 ^ d2;
        sh1_next[127 - j*8 -: 8] = mask1[j];
        if (NSHARES == 3)
          sh2_next[127 - j*8 -: 8] = mask2[j];
      end
    end
  end

  // Round-key index mux
  always_comb begin
    if (fsm_state == S_INIT)
      rk_idx = enc_dec_r ? nr_r[3:0] : 4'd0;
    else if (!enc_dec_r)
      rk_idx = round_cnt[3:0];
    else
      rk_idx = 4'(nr_r - round_cnt);
  end

  // =========================================================================
  // Main FSM
  // =========================================================================
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      fsm_state       <= S_IDLE;
      done_o          <= 1'b0;
      valid_o         <= 1'b0;
      ct_o            <= '0;
      prng_seed_en    <= 1'b0;
      prng_gen_en     <= 1'b0;
      sbox_start      <= 1'b0;
      ks_start        <= 1'b0;
      masks_latched   <= 1'b0;
      masks_phase2_done <= 1'b0;
    end else begin
      // Defaults
      prng_seed_en <= 1'b0;
      prng_gen_en  <= 1'b0;
      sbox_start   <= 1'b0;
      ks_start     <= 1'b0;
      done_o       <= 1'b0;
      valid_o      <= 1'b0;

      case (fsm_state)
        // ---------------------------------------------------------------
        S_IDLE: begin
          if (start_i) begin
            enc_dec_r       <= enc_dec_i;
            key_size_r      <= key_size_i;
            nr_r            <= get_nr(key_size_i);
            prng_seed_en    <= 1'b1;
            masks_latched   <= 1'b0;
            masks_phase2_done <= 1'b0;
            fsm_state       <= S_PRECOMP;
          end
        end

        // ---------------------------------------------------------------
        S_PRECOMP: begin
          if (!masks_latched) begin
            // First PRECOMP cycle: PRNG seeded, read mask1
            begin
              integer jj;
              for (jj = 0; jj < 16; jj++) begin
                mask1[jj] <= prng_data[127 - jj*8 -: 8];
              end
            end
            masks_latched <= 1'b1;

            if (NSHARES == 2) begin
              begin
                integer jj;
                for (jj = 0; jj < 16; jj++) begin
                  mc[jj]    <= prng_data[127 - jj*8 -: 8];
                  mask2[jj] <= 8'h00;
                end
              end
              sbox_start <= 1'b1;
              ks_start   <= 1'b1;
            end else begin
              // Need one more cycle for mask2
              prng_gen_en <= 1'b1;
            end

          end else if (NSHARES == 3 && !masks_phase2_done) begin
            begin
              integer jj;
              for (jj = 0; jj < 16; jj++) begin
                mask2[jj] <= prng_data[127 - jj*8 -: 8];
                mc[jj]    <= mask1[jj] ^ prng_data[127 - jj*8 -: 8];
              end
            end
            masks_phase2_done <= 1'b1;
            sbox_start <= 1'b1;
            ks_start   <= 1'b1;

          end else if (sbox_done && ks_done) begin
            fsm_state <= S_INIT;
          end
        end

        // ---------------------------------------------------------------
        S_INIT: begin
          begin
            integer jj;
            logic [127:0] mc_128;
            logic [127:0] m1_128;
            logic [127:0] m2_128;
            mc_128 = '0;
            m1_128 = '0;
            m2_128 = '0;
            for (jj = 0; jj < 16; jj++) begin
              mc_128[127 - jj*8 -: 8] = mc[jj];
              m1_128[127 - jj*8 -: 8] = mask1[jj];
              if (NSHARES == 3)
                m2_128[127 - jj*8 -: 8] = mask2[jj];
            end
            sh0 <= pt_i ^ mc_128 ^ rk_data;
            sh1 <= m1_128;
            sh2 <= (NSHARES == 3) ? m2_128 : '0;
          end
          round_cnt <= 1;
          fsm_state <= S_ROUNDS;
        end

        // ---------------------------------------------------------------
        S_ROUNDS: begin
          sh0 <= sh0_next;
          sh1 <= sh1_next;
          sh2 <= sh2_next;

          if (round_cnt == nr_r)
            fsm_state <= S_DONE;
          else
            round_cnt <= round_cnt + 1;
        end

        // ---------------------------------------------------------------
        S_DONE: begin
          if (NSHARES == 2)
            ct_o <= sh0 ^ sh1;
          else
            ct_o <= sh0 ^ sh1 ^ sh2;
          done_o  <= 1'b1;
          valid_o <= 1'b1;
          fsm_state <= S_IDLE;
        end
      endcase
    end
  end

  assign busy_o = (fsm_state != S_IDLE);

endmodule
