// =============================================================================
// Simple PRNG — xorshift128 for mask generation
// Produces 128 bits per cycle when enabled.
// =============================================================================
module prng_simple (
  input  logic         clk,
  input  logic         rst_n,
  input  logic         seed_en_i,   // pulse: load seed
  input  logic [127:0] seed_i,
  input  logic         gen_en_i,    // advance PRNG
  output logic [127:0] data_o
);

  logic [127:0] state_q;

  // xorshift128 step (Marsaglia)
  function automatic logic [127:0] xorshift128(input logic [127:0] s);
    logic [31:0] t, w;
    logic [31:0] x, y, z;
    x = s[127:96];
    y = s[95:64];
    z = s[63:32];
    w = s[31:0];
    t = x ^ (x << 11);
    x = y;
    y = z;
    z = w;
    w = w ^ (w >> 19) ^ t ^ (t >> 8);
    return {x, y, z, w};
  endfunction

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_q <= 128'hdeadbeef_cafebabe_12345678_87654321;
    end else if (seed_en_i) begin
      // Avoid all-zero state (xorshift period degenerates)
      state_q <= (seed_i == '0) ? 128'h1 : seed_i;
    end else if (gen_en_i) begin
      state_q <= xorshift128(state_q);
    end
  end

  assign data_o = state_q;

endmodule
