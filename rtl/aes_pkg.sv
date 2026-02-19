// =============================================================================
// AES Package — types, GF(2^8) helpers, Rcon, CMT S-Box functions
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
  // Forward S-Box — CMT gate-level implementation (Boyar-Matthews-Peralta)
  // Replaces the ROM lookup for enc SubBytes and key schedule SubWord.
  // Bit mapping: U0=in[7] (MSB), out={S0,S1,S2,S3,S4,S5,S6,S7} (S0=MSB).
  // -------------------------------------------------------------------------
  function automatic logic [7:0] sbox_fwd_cmt_fn(input logic [7:0] ib);
    logic U0, U1, U2, U3, U4, U5, U6, U7;
    logic y14, y13, y9, y8, t0f, y1, y4, y12;
    logic y2, y5, y3, t1f, y15, y20, y6, y10;
    logic y11, y7, y17, y19, y16, y21, y18;
    logic t2,  t3,  t4,  t5,  t6,  t7,  t8,  t9,  t10, t11;
    logic t12, t13, t14, t15, t16, t17, t18, t19, t20, t21;
    logic t22, t23, t24, t25, t26, t27, t28, t29, t30, t31;
    logic t32, t33, t34, t35, t36, t37, t38, t39, t40, t41;
    logic t42, t43, t44, t45;
    logic z0,  z1,  z2,  z3,  z4,  z5,  z6,  z7,  z8,  z9;
    logic z10, z11, z12, z13, z14, z15, z16, z17;
    logic tc1,  tc2,  tc3,  tc4,  tc5,  tc6,  tc7,  tc8,  tc9;
    logic tc10, tc11, tc12, tc13, tc14, tc16, tc17, tc18, tc20, tc21, tc26;
    logic S0, S1, S2, S3, S4, S5, S6, S7;

    {U0,U1,U2,U3,U4,U5,U6,U7} = ib;  // U0=ib[7], U7=ib[0]

    y14 = U3  ^ U5;  y13 = U0  ^ U6;  y9  = U0  ^ U3;  y8  = U0  ^ U5;
    t0f = U1  ^ U2;  y1  = t0f ^ U7;  y4  = y1  ^ U3;  y12 = y13 ^ y14;
    y2  = y1  ^ U0;  y5  = y1  ^ U6;  y3  = y5  ^ y8;
    t1f = U4  ^ y12; y15 = t1f ^ U5;  y20 = t1f ^ U1;
    y6  = y15 ^ U7;  y10 = y15 ^ t0f; y11 = y20 ^ y9;
    y7  = U7  ^ y11; y17 = y10 ^ y11; y19 = y10 ^ y8;
    y16 = t0f ^ y11; y21 = y13 ^ y16; y18 = U0  ^ y16;

    t2  = y12 & y15; t3  = y3  & y6;  t4  = t3  ^ t2;
    t5  = y4  & U7;  t6  = t5  ^ t2;  t7  = y13 & y16;
    t8  = y5  & y1;  t9  = t8  ^ t7;  t10 = y2  & y7;
    t11 = t10 ^ t7;  t12 = y9  & y11; t13 = y14 & y17;
    t14 = t13 ^ t12; t15 = y8  & y10; t16 = t15 ^ t12;
    t17 = t4  ^ y20; t18 = t6  ^ t16; t19 = t9  ^ t14;
    t20 = t11 ^ t16; t21 = t17 ^ t14; t22 = t18 ^ y19;
    t23 = t19 ^ y21; t24 = t20 ^ y18; t25 = t21 ^ t22;
    t26 = t21 & t23; t27 = t24 ^ t26; t28 = t25 & t27;
    t29 = t28 ^ t22; t30 = t23 ^ t24; t31 = t22 ^ t26;
    t32 = t31 & t30; t33 = t32 ^ t24; t34 = t23 ^ t33;
    t35 = t27 ^ t33; t36 = t24 & t35; t37 = t36 ^ t34;
    t38 = t27 ^ t36; t39 = t29 & t38; t40 = t25 ^ t39;
    t41 = t40 ^ t37; t42 = t29 ^ t33; t43 = t29 ^ t40;
    t44 = t33 ^ t37; t45 = t42 ^ t41;

    z0  = t44 & y15; z1  = t37 & y6;  z2  = t33 & U7;
    z3  = t43 & y16; z4  = t40 & y1;  z5  = t29 & y7;
    z6  = t42 & y11; z7  = t45 & y17; z8  = t41 & y10;
    z9  = t44 & y12; z10 = t37 & y3;  z11 = t33 & y4;
    z12 = t43 & y13; z13 = t40 & y5;  z14 = t29 & y2;
    z15 = t42 & y9;  z16 = t45 & y14; z17 = t41 & y8;

    tc1  = z15  ^ z16; tc2  = z10  ^ tc1;  tc3  = z9   ^ tc2;
    tc4  = z0   ^ z2;  tc5  = z1   ^ z0;   tc6  = z3   ^ z4;
    tc7  = z12  ^ tc4; tc8  = z7   ^ tc6;  tc9  = z8   ^ tc7;
    tc10 = tc8  ^ tc9; tc11 = tc6  ^ tc5;  tc12 = z3   ^ z5;
    tc13 = z13  ^ tc1; tc14 = tc4  ^ tc12;
    S3   = tc3  ^ tc11;
    tc16 = z6   ^ tc8; tc17 = z14  ^ tc10; tc18 = tc13 ^ tc14;
    S7   = ~(z12  ^ tc18);
    tc20 = z15  ^ tc16; tc21 = tc2 ^ z11;
    S0   = tc3  ^ tc16;
    S6   = ~(tc10 ^ tc18);
    S4   = tc14 ^ S3;
    S1   = ~(S3  ^ tc16);
    tc26 = tc17 ^ tc20;
    S2   = ~(tc26 ^ z17);
    S5   = tc21 ^ tc17;

    return {S0, S1, S2, S3, S4, S5, S6, S7};
  endfunction

  // -------------------------------------------------------------------------
  // Inverse S-Box — CMT gate-level implementation (Boyar-Matthews-Peralta)
  // Same bit convention as forward S-Box: U0=in[7] (MSB), W0=out[7] (MSB).
  // -------------------------------------------------------------------------
  function automatic logic [7:0] sbox_inv_cmt_fn(input logic [7:0] ib);
    logic U0, U1, U2, U3, U4, U5, U6, U7;
    logic T23, T22, T2,  T1,  T24, R5;
    logic T8,  T19, T9,  T10, T13, T3;
    logic T25, R13, T17, T20, T4;
    logic R17, R18, R19, Y5;
    logic T6,  T16, T27, T15, T14, T26;
    logic M1,  M2,  M3,  M4,  M5,  M6,  M7,  M8,  M9,  M10;
    logic M11, M12, M13, M14, M15, M16, M17, M18, M19, M20;
    logic M21, M22, M23, M24, M25, M26, M27, M28, M29, M30;
    logic M31, M32, M33, M34, M35, M36, M37, M38, M39, M40;
    logic M41, M42, M43, M44, M45;
    logic M46, M47, M48, M49, M50, M51, M52, M53, M54, M55;
    logic M56, M57, M58, M59, M60, M61, M62, M63;
    logic P0,  P1,  P2,  P3,  P4,  P5,  P6,  P7,  P8,  P9;
    logic P10, P11, P12, P13, P14, P15, P16, P17, P18, P19;
    logic P20, P22, P23, P24, P25, P26, P27, P28, P29;
    logic W0, W1, W2, W3, W4, W5, W6, W7;

    {U0,U1,U2,U3,U4,U5,U6,U7} = ib;

    T23 = U0  ^ U3;      T22 = ~(U1  ^ U3);   T2  = ~(U0  ^ U1);
    T1  = U3  ^ U4;      T24 = ~(U4  ^ U7);   R5  = U6  ^ U7;
    T8  = ~(U1  ^ T23);  T19 = T22 ^ R5;      T9  = ~(U7  ^ T1);
    T10 = T2  ^ T24;     T13 = T2  ^ R5;      T3  = T1  ^ R5;
    T25 = ~(U2  ^ T1);   R13 = U1  ^ U6;      T17 = ~(U2  ^ T19);
    T20 = T24 ^ R13;     T4  = U4  ^ T8;      R17 = ~(U2  ^ U5);
    R18 = ~(U5  ^ U6);   R19 = ~(U2  ^ U4);   Y5  = U0  ^ R17;
    T6  = T22 ^ R17;     T16 = R13 ^ R19;     T27 = T1  ^ R18;
    T15 = T10 ^ T27;     T14 = T10 ^ R18;     T26 = T3  ^ T16;

    M1  = T13 & T6;   M2  = T23 & T8;   M3  = T14 ^ M1;
    M4  = T19 & Y5;   M5  = M4  ^ M1;   M6  = T3  & T16;
    M7  = T22 & T9;   M8  = T26 ^ M6;   M9  = T20 & T17;
    M10 = M9  ^ M6;   M11 = T1  & T15;  M12 = T4  & T27;
    M13 = M12 ^ M11;  M14 = T2  & T10;  M15 = M14 ^ M11;
    M16 = M3  ^ M2;   M17 = M5  ^ T24;  M18 = M8  ^ M7;
    M19 = M10 ^ M15;  M20 = M16 ^ M13;  M21 = M17 ^ M15;
    M22 = M18 ^ M13;  M23 = M19 ^ T25;  M24 = M22 ^ M23;
    M25 = M22 & M20;  M26 = M21 ^ M25;  M27 = M20 ^ M21;
    M28 = M23 ^ M25;  M29 = M28 & M27;  M30 = M26 & M24;
    M31 = M20 & M23;  M32 = M27 & M31;  M33 = M27 ^ M25;
    M34 = M21 & M22;  M35 = M24 & M34;  M36 = M24 ^ M25;
    M37 = M21 ^ M29;  M38 = M32 ^ M33;  M39 = M23 ^ M30;
    M40 = M35 ^ M36;  M41 = M38 ^ M40;  M42 = M37 ^ M39;
    M43 = M37 ^ M38;  M44 = M39 ^ M40;  M45 = M42 ^ M41;

    M46 = M44 & T6;   M47 = M40 & T8;   M48 = M39 & Y5;
    M49 = M43 & T16;  M50 = M38 & T9;   M51 = M37 & T17;
    M52 = M42 & T15;  M53 = M45 & T27;  M54 = M41 & T10;
    M55 = M44 & T13;  M56 = M40 & T23;  M57 = M39 & T19;
    M58 = M43 & T3;   M59 = M38 & T22;  M60 = M37 & T20;
    M61 = M42 & T1;   M62 = M45 & T4;   M63 = M41 & T2;

    P0  = M52 ^ M61;  P1  = M58 ^ M59;  P2  = M54 ^ M62;
    P3  = M47 ^ M50;  P4  = M48 ^ M56;  P5  = M46 ^ M51;
    P6  = M49 ^ M60;  P7  = P0  ^ P1;   P8  = M50 ^ M53;
    P9  = M55 ^ M63;  P10 = M57 ^ P4;   P11 = P0  ^ P3;
    P12 = M46 ^ M48;  P13 = M49 ^ M51;  P14 = M49 ^ M62;
    P15 = M54 ^ M59;  P16 = M57 ^ M61;  P17 = M58 ^ P2;
    P18 = M63 ^ P5;   P19 = P2  ^ P3;   P20 = P4  ^ P6;
    P22 = P2  ^ P7;   P23 = P7  ^ P8;   P24 = P5  ^ P7;
    P25 = P6  ^ P10;  P26 = P9  ^ P11;  P27 = P10 ^ P18;
    P28 = P11 ^ P25;  P29 = P15 ^ P20;

    W0  = P13 ^ P22;  W1  = P26 ^ P29;  W2  = P17 ^ P28;
    W3  = P12 ^ P22;  W4  = P23 ^ P27;  W5  = P19 ^ P24;
    W6  = P14 ^ P23;  W7  = P9  ^ P16;

    return {W0, W1, W2, W3, W4, W5, W6, W7};
  endfunction

  // -------------------------------------------------------------------------
  // SubWord: apply forward S-box to each byte of a 32-bit word (key schedule)
  // -------------------------------------------------------------------------
  function automatic logic [31:0] sub_word(input logic [31:0] w);
    return {sbox_fwd_cmt_fn(w[31:24]), sbox_fwd_cmt_fn(w[23:16]),
            sbox_fwd_cmt_fn(w[15:8]),  sbox_fwd_cmt_fn(w[7:0])};
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
