// =============================================================================
// AES Inverse S-Box — Boyar-Matthews-Peralta gate-level circuit (CMT)
//
// Source: "A Very Compact S-Box for AES", Boyar, Matthews, Peralta (2011).
//         Inverse mapping section from:
//         https://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
//
// Bit conventions (verified against all 256 FIPS-197 inverse S-box values,
// consistent with the project's forward S-Box mapping):
//   Input : U0 = in[7] (MSB), U1 = in[6], ..., U7 = in[0] (LSB)
//   Output: out[7] = W0 (MSB), out[6] = W1, ..., out[0] = W7 (LSB)
//           i.e.  out = {W0, W1, W2, W3, W4, W5, W6, W7}
//
// Symbols:
//   +  = XOR
//   x  = AND
//   #  = XNOR  (= NOT(a XOR b))
// =============================================================================
module aes_inv_sbox_cmt (
  input  logic [7:0] in,
  output logic [7:0] out
);

  // -------------------------------------------------------------------------
  // Input mapping: U0=in[7] (MSB) ... U7=in[0] (LSB)
  // -------------------------------------------------------------------------
  logic U0, U1, U2, U3, U4, U5, U6, U7;
  assign {U0,U1,U2,U3,U4,U5,U6,U7} = in;

  // -------------------------------------------------------------------------
  // Linear pre-processing
  // -------------------------------------------------------------------------
  logic T23, T22, T2,  T1,  T24, R5;
  logic T8,  T19, T9,  T10, T13, T3;
  logic T25, R13, T17, T20, T4;
  logic R17, R18, R19, Y5;
  logic T6,  T16, T27, T15, T14, T26;

  assign T23 = U0  ^ U3;
  assign T22 = ~(U1  ^ U3);   // XNOR
  assign T2  = ~(U0  ^ U1);   // XNOR
  assign T1  = U3  ^ U4;
  assign T24 = ~(U4  ^ U7);   // XNOR
  assign R5  = U6  ^ U7;
  assign T8  = ~(U1  ^ T23);  // XNOR
  assign T19 = T22 ^ R5;
  assign T9  = ~(U7  ^ T1);   // XNOR
  assign T10 = T2  ^ T24;
  assign T13 = T2  ^ R5;
  assign T3  = T1  ^ R5;
  assign T25 = ~(U2  ^ T1);   // XNOR
  assign R13 = U1  ^ U6;
  assign T17 = ~(U2  ^ T19);  // XNOR
  assign T20 = T24 ^ R13;
  assign T4  = U4  ^ T8;
  assign R17 = ~(U2  ^ U5);   // XNOR
  assign R18 = ~(U5  ^ U6);   // XNOR
  assign R19 = ~(U2  ^ U4);   // XNOR
  assign Y5  = U0  ^ R17;
  assign T6  = T22 ^ R17;
  assign T16 = R13 ^ R19;
  assign T27 = T1  ^ R18;
  assign T15 = T10 ^ T27;
  assign T14 = T10 ^ R18;
  assign T26 = T3  ^ T16;

  // -------------------------------------------------------------------------
  // Nonlinear middle section (M1 – M45)
  // -------------------------------------------------------------------------
  logic M1,  M2,  M3,  M4,  M5,  M6,  M7,  M8,  M9,  M10;
  logic M11, M12, M13, M14, M15, M16, M17, M18, M19, M20;
  logic M21, M22, M23, M24, M25, M26, M27, M28, M29, M30;
  logic M31, M32, M33, M34, M35, M36, M37, M38, M39, M40;
  logic M41, M42, M43, M44, M45;

  assign M1  = T13 & T6;
  assign M2  = T23 & T8;
  assign M3  = T14 ^ M1;
  assign M4  = T19 & Y5;
  assign M5  = M4  ^ M1;
  assign M6  = T3  & T16;
  assign M7  = T22 & T9;
  assign M8  = T26 ^ M6;
  assign M9  = T20 & T17;
  assign M10 = M9  ^ M6;
  assign M11 = T1  & T15;
  assign M12 = T4  & T27;
  assign M13 = M12 ^ M11;
  assign M14 = T2  & T10;
  assign M15 = M14 ^ M11;
  assign M16 = M3  ^ M2;
  assign M17 = M5  ^ T24;
  assign M18 = M8  ^ M7;
  assign M19 = M10 ^ M15;
  assign M20 = M16 ^ M13;
  assign M21 = M17 ^ M15;
  assign M22 = M18 ^ M13;
  assign M23 = M19 ^ T25;
  assign M24 = M22 ^ M23;
  assign M25 = M22 & M20;
  assign M26 = M21 ^ M25;
  assign M27 = M20 ^ M21;
  assign M28 = M23 ^ M25;
  assign M29 = M28 & M27;
  assign M30 = M26 & M24;
  assign M31 = M20 & M23;
  assign M32 = M27 & M31;
  assign M33 = M27 ^ M25;
  assign M34 = M21 & M22;
  assign M35 = M24 & M34;
  assign M36 = M24 ^ M25;
  assign M37 = M21 ^ M29;
  assign M38 = M32 ^ M33;
  assign M39 = M23 ^ M30;
  assign M40 = M35 ^ M36;
  assign M41 = M38 ^ M40;
  assign M42 = M37 ^ M39;
  assign M43 = M37 ^ M38;
  assign M44 = M39 ^ M40;
  assign M45 = M42 ^ M41;

  // -------------------------------------------------------------------------
  // Output multiplications (second nonlinear layer)
  // -------------------------------------------------------------------------
  logic M46, M47, M48, M49, M50, M51, M52, M53, M54, M55;
  logic M56, M57, M58, M59, M60, M61, M62, M63;

  assign M46 = M44 & T6;
  assign M47 = M40 & T8;
  assign M48 = M39 & Y5;
  assign M49 = M43 & T16;
  assign M50 = M38 & T9;
  assign M51 = M37 & T17;
  assign M52 = M42 & T15;
  assign M53 = M45 & T27;
  assign M54 = M41 & T10;
  assign M55 = M44 & T13;
  assign M56 = M40 & T23;
  assign M57 = M39 & T19;
  assign M58 = M43 & T3;
  assign M59 = M38 & T22;
  assign M60 = M37 & T20;
  assign M61 = M42 & T1;
  assign M62 = M45 & T4;
  assign M63 = M41 & T2;

  // -------------------------------------------------------------------------
  // Linear post-processing (P / W layer)
  // -------------------------------------------------------------------------
  logic P0,  P1,  P2,  P3,  P4,  P5,  P6,  P7,  P8,  P9;
  logic P10, P11, P12, P13, P14, P15, P16, P17, P18, P19;
  logic P20, P22, P23, P24, P25, P26, P27, P28, P29;
  logic W0, W1, W2, W3, W4, W5, W6, W7;

  assign P0  = M52 ^ M61;
  assign P1  = M58 ^ M59;
  assign P2  = M54 ^ M62;
  assign P3  = M47 ^ M50;
  assign P4  = M48 ^ M56;
  assign P5  = M46 ^ M51;
  assign P6  = M49 ^ M60;
  assign P7  = P0  ^ P1;
  assign P8  = M50 ^ M53;
  assign P9  = M55 ^ M63;
  assign P10 = M57 ^ P4;
  assign P11 = P0  ^ P3;
  assign P12 = M46 ^ M48;
  assign P13 = M49 ^ M51;
  assign P14 = M49 ^ M62;
  assign P15 = M54 ^ M59;
  assign P16 = M57 ^ M61;
  assign P17 = M58 ^ P2;
  assign P18 = M63 ^ P5;
  assign P19 = P2  ^ P3;
  assign P20 = P4  ^ P6;
  assign P22 = P2  ^ P7;
  assign P23 = P7  ^ P8;
  assign P24 = P5  ^ P7;
  assign P25 = P6  ^ P10;
  assign P26 = P9  ^ P11;
  assign P27 = P10 ^ P18;
  assign P28 = P11 ^ P25;
  assign P29 = P15 ^ P20;

  assign W0  = P13 ^ P22;
  assign W1  = P26 ^ P29;
  assign W2  = P17 ^ P28;
  assign W3  = P12 ^ P22;
  assign W4  = P23 ^ P27;
  assign W5  = P19 ^ P24;
  assign W6  = P14 ^ P23;
  assign W7  = P9  ^ P16;

  // -------------------------------------------------------------------------
  // Output reassembly: out[7]=W0 (MSB) ... out[0]=W7 (LSB)
  // -------------------------------------------------------------------------
  assign out = {W0, W1, W2, W3, W4, W5, W6, W7};

endmodule
