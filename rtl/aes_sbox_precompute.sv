// =============================================================================
// Masked S-box table precomputation and lookup for 16 byte positions.
//
// During PRECOMP phase:
//   For each byte position j (0..15) and each address a (0..255):
//     x  = a ^ Mc[j]           (Mc = combined mask)
//     ENC: T_j[a] = SBOX_FWD(x) ^ Mc[j]
//     DEC: T_j[a] = SBOX_INV(x) ^ Mc[j]
//
// During ROUNDS phase:
//   Lookup: out_byte = T_j[ state_sh0.byte[j] ]
//
// ENTRIES_PER_CYCLE controls fill parallelism (default 16 → 16 cycles).
// =============================================================================
module aes_sbox_precompute
  import aes_pkg::*;
#(
  parameter int ENTRIES_PER_CYCLE = 16  // 256 / this = precomp cycles
) (
  input  logic         clk,
  input  logic         rst_n,

  // Control
  input  logic         start_i,      // begin precomputation
  input  logic         enc_dec_i,    // 0=ENC, 1=DEC
  output logic         done_o,       // precomputation finished

  // Masks: combined mask Mc per byte position (16 bytes)
  input  logic [7:0]   mc_i [0:15],

  // Round lookup interface (active after done_o)
  input  logic [7:0]   addr_i [0:15],   // 16 lookup addresses
  output logic [7:0]   data_o [0:15]    // 16 lookup results
);

  // -----------------------------------------------------------------------
  // Table storage: 16 tables × 256 entries × 8 bits
  // -----------------------------------------------------------------------
  logic [7:0] table_mem [0:15][0:255];

  // -----------------------------------------------------------------------
  // Precompute FSM
  // -----------------------------------------------------------------------
  localparam int PRECOMP_CYCLES = 256 / ENTRIES_PER_CYCLE;
  localparam int CTR_W = $clog2(PRECOMP_CYCLES + 1);

  logic [CTR_W-1:0] fill_ctr;
  logic              filling;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      filling  <= 1'b0;
      fill_ctr <= '0;
    end else if (start_i) begin
      filling  <= 1'b1;
      fill_ctr <= '0;
    end else if (filling) begin
      if (fill_ctr == CTR_W'(PRECOMP_CYCLES - 1))
        filling <= 1'b0;
      else
        fill_ctr <= fill_ctr + 1'b1;
    end
  end

  assign done_o = ~filling & ~start_i;

  // -----------------------------------------------------------------------
  // Table fill logic — runs during 'filling' phase
  // For each cycle, fill ENTRIES_PER_CYCLE entries in all 16 tables.
  // -----------------------------------------------------------------------
  always_ff @(posedge clk) begin
    if (filling) begin
      for (int j = 0; j < 16; j++) begin
        for (int e = 0; e < ENTRIES_PER_CYCLE; e++) begin
          automatic int addr_idx = int'(fill_ctr) * ENTRIES_PER_CYCLE + e;
          automatic logic [7:0] a  = addr_idx[7:0];
          automatic logic [7:0] x  = a ^ mc_i[j];
          automatic logic [7:0] sx;
          if (!enc_dec_i)
            sx = sbox_fwd_cmt_fn(x);  // CMT gate-level forward S-box
          else
            sx = SBOX_INV[x];         // inverse S-box table (unchanged)
          table_mem[j][a] <= sx ^ mc_i[j];
        end
      end
    end
  end

  // -----------------------------------------------------------------------
  // Lookup — combinational read (valid after done_o)
  // -----------------------------------------------------------------------
  always_comb begin
    for (int j = 0; j < 16; j++) begin
      data_o[j] = table_mem[j][addr_i[j]];
    end
  end

endmodule
