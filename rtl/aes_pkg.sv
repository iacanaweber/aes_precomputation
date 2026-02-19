// =============================================================================
// AES Package — types, S-box tables, GF(2^8) helpers, Rcon
// =============================================================================
package aes_pkg;

  // -------------------------------------------------------------------------
  // Key-size enumeration
  // -------------------------------------------------------------------------
  typedef enum logic [1:0] {
    AES_128 = 2'b00,
    AES_192 = 2'b01,
    AES_256 = 2'b10
  } key_size_e;

  // -------------------------------------------------------------------------
  // Number of rounds for each key size
  // -------------------------------------------------------------------------
  function automatic int unsigned get_nr(key_size_e ks);
    case (ks)
      AES_128: return 10;
      AES_192: return 12;
      AES_256: return 14;
      default: return 10;
    endcase
  endfunction

  function automatic int unsigned get_nk(key_size_e ks);
    case (ks)
      AES_128: return 4;
      AES_192: return 6;
      AES_256: return 8;
      default: return 4;
    endcase
  endfunction

  // -------------------------------------------------------------------------
  // Forward S-box (FIPS-197)
  // -------------------------------------------------------------------------
  localparam logic [7:0] SBOX_FWD [0:255] = '{
    8'h63, 8'h7c, 8'h77, 8'h7b, 8'hf2, 8'h6b, 8'h6f, 8'hc5,
    8'h30, 8'h01, 8'h67, 8'h2b, 8'hfe, 8'hd7, 8'hab, 8'h76,
    8'hca, 8'h82, 8'hc9, 8'h7d, 8'hfa, 8'h59, 8'h47, 8'hf0,
    8'had, 8'hd4, 8'ha2, 8'haf, 8'h9c, 8'ha4, 8'h72, 8'hc0,
    8'hb7, 8'hfd, 8'h93, 8'h26, 8'h36, 8'h3f, 8'hf7, 8'hcc,
    8'h34, 8'ha5, 8'he5, 8'hf1, 8'h71, 8'hd8, 8'h31, 8'h15,
    8'h04, 8'hc7, 8'h23, 8'hc3, 8'h18, 8'h96, 8'h05, 8'h9a,
    8'h07, 8'h12, 8'h80, 8'he2, 8'heb, 8'h27, 8'hb2, 8'h75,
    8'h09, 8'h83, 8'h2c, 8'h1a, 8'h1b, 8'h6e, 8'h5a, 8'ha0,
    8'h52, 8'h3b, 8'hd6, 8'hb3, 8'h29, 8'he3, 8'h2f, 8'h84,
    8'h53, 8'hd1, 8'h00, 8'hed, 8'h20, 8'hfc, 8'hb1, 8'h5b,
    8'h6a, 8'hcb, 8'hbe, 8'h39, 8'h4a, 8'h4c, 8'h58, 8'hcf,
    8'hd0, 8'hef, 8'haa, 8'hfb, 8'h43, 8'h4d, 8'h33, 8'h85,
    8'h45, 8'hf9, 8'h02, 8'h7f, 8'h50, 8'h3c, 8'h9f, 8'ha8,
    8'h51, 8'ha3, 8'h40, 8'h8f, 8'h92, 8'h9d, 8'h38, 8'hf5,
    8'hbc, 8'hb6, 8'hda, 8'h21, 8'h10, 8'hff, 8'hf3, 8'hd2,
    8'hcd, 8'h0c, 8'h13, 8'hec, 8'h5f, 8'h97, 8'h44, 8'h17,
    8'hc4, 8'ha7, 8'h7e, 8'h3d, 8'h64, 8'h5d, 8'h19, 8'h73,
    8'h60, 8'h81, 8'h4f, 8'hdc, 8'h22, 8'h2a, 8'h90, 8'h88,
    8'h46, 8'hee, 8'hb8, 8'h14, 8'hde, 8'h5e, 8'h0b, 8'hdb,
    8'he0, 8'h32, 8'h3a, 8'h0a, 8'h49, 8'h06, 8'h24, 8'h5c,
    8'hc2, 8'hd3, 8'hac, 8'h62, 8'h91, 8'h95, 8'he4, 8'h79,
    8'he7, 8'hc8, 8'h37, 8'h6d, 8'h8d, 8'hd5, 8'h4e, 8'ha9,
    8'h6c, 8'h56, 8'hf4, 8'hea, 8'h65, 8'h7a, 8'hae, 8'h08,
    8'hba, 8'h78, 8'h25, 8'h2e, 8'h1c, 8'ha6, 8'hb4, 8'hc6,
    8'he8, 8'hdd, 8'h74, 8'h1f, 8'h4b, 8'hbd, 8'h8b, 8'h8a,
    8'h70, 8'h3e, 8'hb5, 8'h66, 8'h48, 8'h03, 8'hf6, 8'h0e,
    8'h61, 8'h35, 8'h57, 8'hb9, 8'h86, 8'hc1, 8'h1d, 8'h9e,
    8'he1, 8'hf8, 8'h98, 8'h11, 8'h69, 8'hd9, 8'h8e, 8'h94,
    8'h9b, 8'h1e, 8'h87, 8'he9, 8'hce, 8'h55, 8'h28, 8'hdf,
    8'h8c, 8'ha1, 8'h89, 8'h0d, 8'hbf, 8'he6, 8'h42, 8'h68,
    8'h41, 8'h99, 8'h2d, 8'h0f, 8'hb0, 8'h54, 8'hbb, 8'h16
  };

  // -------------------------------------------------------------------------
  // Inverse S-box (computed from forward)
  // -------------------------------------------------------------------------
  localparam logic [7:0] SBOX_INV [0:255] = '{
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

  // -------------------------------------------------------------------------
  // Rcon table (up to index 14 needed for AES-256)
  // Rcon[i] = {rc[i], 00, 00, 00}  where rc[1]=01, rc[i]=xtime(rc[i-1])
  // We store only the MSB byte; lower 3 bytes are zero.
  // -------------------------------------------------------------------------
  localparam logic [7:0] RCON [1:14] = '{
    8'h01, 8'h02, 8'h04, 8'h08, 8'h10,
    8'h20, 8'h40, 8'h80, 8'h1b, 8'h36,
    8'h6c, 8'hd8, 8'hab, 8'h4d
  };

  // -------------------------------------------------------------------------
  // GF(2^8) helpers
  // -------------------------------------------------------------------------
  function automatic logic [7:0] xtime(input logic [7:0] a);
    return {a[6:0], 1'b0} ^ (a[7] ? 8'h1b : 8'h00);
  endfunction

  function automatic logic [7:0] gf_mul2(input logic [7:0] a);
    return xtime(a);
  endfunction

  function automatic logic [7:0] gf_mul3(input logic [7:0] a);
    return xtime(a) ^ a;
  endfunction

  function automatic logic [7:0] gf_mul4(input logic [7:0] a);
    return xtime(xtime(a));
  endfunction

  function automatic logic [7:0] gf_mul8(input logic [7:0] a);
    return xtime(xtime(xtime(a)));
  endfunction

  function automatic logic [7:0] gf_mul9(input logic [7:0] a);
    return gf_mul8(a) ^ a;
  endfunction

  function automatic logic [7:0] gf_mul_b(input logic [7:0] a);
    return gf_mul8(a) ^ gf_mul2(a) ^ a;
  endfunction

  function automatic logic [7:0] gf_mul_d(input logic [7:0] a);
    return gf_mul8(a) ^ gf_mul4(a) ^ a;
  endfunction

  function automatic logic [7:0] gf_mul_e(input logic [7:0] a);
    return gf_mul8(a) ^ gf_mul4(a) ^ gf_mul2(a);
  endfunction

  // -------------------------------------------------------------------------
  // Byte extraction / insertion helpers
  // State is 128 bits, byte 0 is MSB [127:120], byte 15 is LSB [7:0]
  // -------------------------------------------------------------------------
  function automatic logic [7:0] get_byte(input logic [127:0] state, input int idx);
    return state[127 - idx*8 -: 8];
  endfunction

  function automatic logic [127:0] set_byte(input logic [127:0] state,
                                             input int idx,
                                             input logic [7:0] val);
    logic [127:0] result;
    result = state;
    result[127 - idx*8 -: 8] = val;
    return result;
  endfunction

  // -------------------------------------------------------------------------
  // SubWord: apply S-box to each byte of a 32-bit word
  // -------------------------------------------------------------------------
  function automatic logic [31:0] sub_word(input logic [31:0] w);
    return {SBOX_FWD[w[31:24]], SBOX_FWD[w[23:16]],
            SBOX_FWD[w[15:8]],  SBOX_FWD[w[7:0]]};
  endfunction

  // -------------------------------------------------------------------------
  // RotWord: rotate 32-bit word left by 8 bits
  // -------------------------------------------------------------------------
  function automatic logic [31:0] rot_word(input logic [31:0] w);
    return {w[23:0], w[31:24]};
  endfunction

  // -------------------------------------------------------------------------
  // MixColumns on one 4-byte column (forward)
  // -------------------------------------------------------------------------
  function automatic logic [31:0] mix_column(input logic [31:0] col);
    logic [7:0] a0, a1, a2, a3;
    logic [7:0] r0, r1, r2, r3;
    a0 = col[31:24]; a1 = col[23:16]; a2 = col[15:8]; a3 = col[7:0];
    r0 = gf_mul2(a0) ^ gf_mul3(a1) ^ a2         ^ a3;
    r1 = a0         ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
    r2 = a0         ^ a1         ^ gf_mul2(a2) ^ gf_mul3(a3);
    r3 = gf_mul3(a0) ^ a1         ^ a2         ^ gf_mul2(a3);
    return {r0, r1, r2, r3};
  endfunction

  // -------------------------------------------------------------------------
  // InvMixColumns on one 4-byte column
  // -------------------------------------------------------------------------
  function automatic logic [31:0] inv_mix_column(input logic [31:0] col);
    logic [7:0] a0, a1, a2, a3;
    logic [7:0] r0, r1, r2, r3;
    a0 = col[31:24]; a1 = col[23:16]; a2 = col[15:8]; a3 = col[7:0];
    r0 = gf_mul_e(a0) ^ gf_mul_b(a1) ^ gf_mul_d(a2) ^ gf_mul9(a3);
    r1 = gf_mul9(a0) ^ gf_mul_e(a1) ^ gf_mul_b(a2) ^ gf_mul_d(a3);
    r2 = gf_mul_d(a0) ^ gf_mul9(a1) ^ gf_mul_e(a2) ^ gf_mul_b(a3);
    r3 = gf_mul_b(a0) ^ gf_mul_d(a1) ^ gf_mul9(a2) ^ gf_mul_e(a3);
    return {r0, r1, r2, r3};
  endfunction

  // -------------------------------------------------------------------------
  // Full-state MixColumns / InvMixColumns (4 columns)
  // -------------------------------------------------------------------------
  function automatic logic [127:0] mix_columns_128(input logic [127:0] s);
    return {mix_column(s[127:96]), mix_column(s[95:64]),
            mix_column(s[63:32]),  mix_column(s[31:0])};
  endfunction

  function automatic logic [127:0] inv_mix_columns_128(input logic [127:0] s);
    return {inv_mix_column(s[127:96]), inv_mix_column(s[95:64]),
            inv_mix_column(s[63:32]),  inv_mix_column(s[31:0])};
  endfunction

  // -------------------------------------------------------------------------
  // ShiftRows / InvShiftRows
  // State byte layout (column-major, byte 0 = MSB):
  //   byte  0  4  8 12      row 0
  //   byte  1  5  9 13      row 1
  //   byte  2  6 10 14      row 2
  //   byte  3  7 11 15      row 3
  // ShiftRows: row r shifts left by r positions
  // -------------------------------------------------------------------------
  function automatic logic [127:0] shift_rows(input logic [127:0] s);
    logic [7:0] b [0:15];
    logic [7:0] o [0:15];
    for (int i = 0; i < 16; i++) b[i] = get_byte(s, i);
    // Row 0: no shift
    o[0]  = b[0];  o[4]  = b[4];  o[8]  = b[8];  o[12] = b[12];
    // Row 1: shift left 1
    o[1]  = b[5];  o[5]  = b[9];  o[9]  = b[13]; o[13] = b[1];
    // Row 2: shift left 2
    o[2]  = b[10]; o[6]  = b[14]; o[10] = b[2];  o[14] = b[6];
    // Row 3: shift left 3
    o[3]  = b[15]; o[7]  = b[3];  o[11] = b[7];  o[15] = b[11];
    begin
      logic [127:0] result;
      result = '0;
      for (int i = 0; i < 16; i++) result = set_byte(result, i, o[i]);
      return result;
    end
  endfunction

  function automatic logic [127:0] inv_shift_rows(input logic [127:0] s);
    logic [7:0] b [0:15];
    logic [7:0] o [0:15];
    for (int i = 0; i < 16; i++) b[i] = get_byte(s, i);
    // Row 0: no shift
    o[0]  = b[0];  o[4]  = b[4];  o[8]  = b[8];  o[12] = b[12];
    // Row 1: shift right 1
    o[1]  = b[13]; o[5]  = b[1];  o[9]  = b[5];  o[13] = b[9];
    // Row 2: shift right 2
    o[2]  = b[10]; o[6]  = b[14]; o[10] = b[2];  o[14] = b[6];
    // Row 3: shift right 3
    o[3]  = b[7];  o[7]  = b[11]; o[11] = b[15]; o[15] = b[3];
    begin
      logic [127:0] result;
      result = '0;
      for (int i = 0; i < 16; i++) result = set_byte(result, i, o[i]);
      return result;
    end
  endfunction

endpackage
