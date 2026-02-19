// =============================================================================
// AES Key Schedule — expands cipher key into all round keys.
// Supports AES-128 / AES-192 / AES-256.
// Computes 4 new key-words per cycle (serial chain within cycle).
// Runs during the precompute phase.
//
// Security note: operates UNMASKED. The key is processed in the clear during
// precompute. The round datapath (state correlated with pt/ct) is fully masked.
// =============================================================================
module aes_key_schedule
  import aes_pkg::*;
(
  input  logic          clk,
  input  logic          rst_n,
  input  logic          start_i,
  input  key_size_e     key_size_i,
  input  logic [255:0]  key_i,
  output logic          done_o,
  input  logic [3:0]    rk_idx_i,
  output logic [127:0]  rk_data_o
);

  // Storage for expanded key words (max 60 for AES-256)
  logic [31:0] w [0:59];

  // FSM
  typedef enum logic [1:0] {KS_IDLE, KS_LOAD, KS_EXPAND, KS_DONE} ks_state_e;
  ks_state_e ks_state;

  int unsigned nk_r, nr_r, total_words;
  int unsigned word_idx;
  int unsigned rcon_idx;

  // Combinational signals for the 4-word expansion chain
  logic [31:0] new_w [0:3];
  logic [31:0] prev_for_chain;
  int unsigned next_word_idx;
  int unsigned next_rcon_idx;

  always_comb begin
    integer k, wi, ri;
    logic [31:0] prev;
    logic [31:0] temp;
    logic [31:0] result;

    next_word_idx = word_idx;
    next_rcon_idx = rcon_idx;

    for (k = 0; k < 4; k++)
      new_w[k] = 32'h0;

    wi   = word_idx;
    ri   = rcon_idx;
    prev = (wi > 0) ? w[wi - 1] : 32'h0;

    for (k = 0; k < 4; k++) begin
      if (wi < total_words) begin
        if ((wi % nk_r) == 0) begin
          temp = sub_word(rot_word(prev)) ^ {RCON[ri], 24'h0};
          ri   = ri + 1;
        end else if (nk_r == 8 && (wi % nk_r) == 4) begin
          temp = sub_word(prev);
        end else begin
          temp = prev;
        end

        result   = w[wi - nk_r] ^ temp;
        new_w[k] = result;
        prev     = result;
        wi       = wi + 1;
      end
    end

    next_word_idx = wi;
    next_rcon_idx = ri;
  end

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      ks_state <= KS_IDLE;
    end else begin
      case (ks_state)
        KS_IDLE: begin
          if (start_i) begin
            nk_r        <= get_nk(key_size_i);
            nr_r        <= get_nr(key_size_i);
            total_words <= 4 * (get_nr(key_size_i) + 1);
            ks_state    <= KS_LOAD;
          end
        end

        KS_LOAD: begin
          case (nk_r)
            4: begin
              w[0] <= key_i[255:224]; w[1] <= key_i[223:192];
              w[2] <= key_i[191:160]; w[3] <= key_i[159:128];
            end
            6: begin
              w[0] <= key_i[255:224]; w[1] <= key_i[223:192];
              w[2] <= key_i[191:160]; w[3] <= key_i[159:128];
              w[4] <= key_i[127:96];  w[5] <= key_i[95:64];
            end
            8: begin
              w[0] <= key_i[255:224]; w[1] <= key_i[223:192];
              w[2] <= key_i[191:160]; w[3] <= key_i[159:128];
              w[4] <= key_i[127:96];  w[5] <= key_i[95:64];
              w[6] <= key_i[63:32];   w[7] <= key_i[31:0];
            end
            default: ;
          endcase
          word_idx <= nk_r;
          rcon_idx <= 1;
          ks_state <= KS_EXPAND;
        end

        KS_EXPAND: begin
          begin
            integer k2;
            for (k2 = 0; k2 < 4; k2++) begin
              if ((word_idx + k2) < total_words)
                w[word_idx + k2] <= new_w[k2];
            end
          end
          word_idx <= next_word_idx;
          rcon_idx <= next_rcon_idx;

          if (next_word_idx >= total_words)
            ks_state <= KS_DONE;
        end

        KS_DONE: begin
          if (start_i) begin
            // Restart directly into KS_LOAD (don't lose the pulse)
            nk_r        <= get_nk(key_size_i);
            nr_r        <= get_nr(key_size_i);
            total_words <= 4 * (get_nr(key_size_i) + 1);
            ks_state    <= KS_LOAD;
          end
        end
      endcase
    end
  end

  assign done_o = (ks_state == KS_DONE);

  // Round-key read
  always_comb begin
    integer base_idx;
    base_idx  = int'(rk_idx_i) * 4;
    rk_data_o = {w[base_idx], w[base_idx+1], w[base_idx+2], w[base_idx+3]};
  end

endmodule
