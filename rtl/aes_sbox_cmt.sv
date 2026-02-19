// =============================================================================
// AES Forward S-Box — Boyar-Matthews-Peralta gate-level circuit (CMT)
//
// Source: "A Very Compact S-Box for AES", Boyar, Matthews, Peralta (2011).
//         Circuit listing from https://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
//         113 gates (32 AND, 81 XOR/XNOR).
//
// Bit conventions (verified against all 256 FIPS-197 S-box values):
//   Input : U0 = in[7] (MSB), U1 = in[6], ..., U7 = in[0] (LSB)
//   Output: out[7] = S0 (MSB), out[6] = S1, ..., out[0] = S7 (LSB)
//           i.e.  out = {S0, S1, S2, S3, S4, S5, S6, S7}
//
// Symbols:
//   +  = XOR
//   x  = AND
//   #  = XNOR  (= NOT(a XOR b))
// =============================================================================
module aes_sbox_cmt (
  input  logic [7:0] in,
  output logic [7:0] out
);

  // -------------------------------------------------------------------------
  // Input mapping
  // -------------------------------------------------------------------------
  logic U0, U1, U2, U3, U4, U5, U6, U7;
  assign {U0,U1,U2,U3,U4,U5,U6,U7} = in;  // U0=in[7] MSB ... U7=in[0] LSB

  // -------------------------------------------------------------------------
  // Linear pre-processing (y-layer)
  // -------------------------------------------------------------------------
  logic y14, y13, y9, y8, t0, y1, y4, y12;
  logic y2, y5, y3, t1, y15, y20, y6, y10;
  logic y11, y7, y17, y19, y16, y21, y18;

  assign y14 = U3  ^ U5;
  assign y13 = U0  ^ U6;
  assign y9  = U0  ^ U3;
  assign y8  = U0  ^ U5;
  assign t0  = U1  ^ U2;
  assign y1  = t0  ^ U7;
  assign y4  = y1  ^ U3;
  assign y12 = y13 ^ y14;
  assign y2  = y1  ^ U0;
  assign y5  = y1  ^ U6;
  assign y3  = y5  ^ y8;
  assign t1  = U4  ^ y12;
  assign y15 = t1  ^ U5;
  assign y20 = t1  ^ U1;
  assign y6  = y15 ^ U7;
  assign y10 = y15 ^ t0;
  assign y11 = y20 ^ y9;
  assign y7  = U7  ^ y11;
  assign y17 = y10 ^ y11;
  assign y19 = y10 ^ y8;
  assign y16 = t0  ^ y11;
  assign y21 = y13 ^ y16;
  assign y18 = U0  ^ y16;

  // -------------------------------------------------------------------------
  // Nonlinear GF(2^4) tower field section (t2 – t45)
  // -------------------------------------------------------------------------
  logic t2,  t3,  t4,  t5,  t6,  t7,  t8,  t9,  t10, t11;
  logic t12, t13, t14, t15, t16, t17, t18, t19, t20, t21;
  logic t22, t23, t24, t25, t26, t27, t28, t29, t30, t31;
  logic t32, t33, t34, t35, t36, t37, t38, t39, t40, t41;
  logic t42, t43, t44, t45;

  assign t2  = y12 & y15;
  assign t3  = y3  & y6;
  assign t4  = t3  ^ t2;
  assign t5  = y4  & U7;
  assign t6  = t5  ^ t2;
  assign t7  = y13 & y16;
  assign t8  = y5  & y1;
  assign t9  = t8  ^ t7;
  assign t10 = y2  & y7;
  assign t11 = t10 ^ t7;
  assign t12 = y9  & y11;
  assign t13 = y14 & y17;
  assign t14 = t13 ^ t12;
  assign t15 = y8  & y10;
  assign t16 = t15 ^ t12;
  assign t17 = t4  ^ y20;
  assign t18 = t6  ^ t16;
  assign t19 = t9  ^ t14;
  assign t20 = t11 ^ t16;
  assign t21 = t17 ^ t14;
  assign t22 = t18 ^ y19;
  assign t23 = t19 ^ y21;
  assign t24 = t20 ^ y18;
  assign t25 = t21 ^ t22;
  assign t26 = t21 & t23;
  assign t27 = t24 ^ t26;
  assign t28 = t25 & t27;
  assign t29 = t28 ^ t22;
  assign t30 = t23 ^ t24;
  assign t31 = t22 ^ t26;
  assign t32 = t31 & t30;
  assign t33 = t32 ^ t24;
  assign t34 = t23 ^ t33;
  assign t35 = t27 ^ t33;
  assign t36 = t24 & t35;
  assign t37 = t36 ^ t34;
  assign t38 = t27 ^ t36;
  assign t39 = t29 & t38;
  assign t40 = t25 ^ t39;
  assign t41 = t40 ^ t37;
  assign t42 = t29 ^ t33;
  assign t43 = t29 ^ t40;
  assign t44 = t33 ^ t37;
  assign t45 = t42 ^ t41;

  // -------------------------------------------------------------------------
  // Output multiplications (z-layer)
  // -------------------------------------------------------------------------
  logic z0,  z1,  z2,  z3,  z4,  z5,  z6,  z7,  z8,  z9;
  logic z10, z11, z12, z13, z14, z15, z16, z17;

  assign z0  = t44 & y15;
  assign z1  = t37 & y6;
  assign z2  = t33 & U7;
  assign z3  = t43 & y16;
  assign z4  = t40 & y1;
  assign z5  = t29 & y7;
  assign z6  = t42 & y11;
  assign z7  = t45 & y17;
  assign z8  = t41 & y10;
  assign z9  = t44 & y12;
  assign z10 = t37 & y3;
  assign z11 = t33 & y4;
  assign z12 = t43 & y13;
  assign z13 = t40 & y5;
  assign z14 = t29 & y2;
  assign z15 = t42 & y9;
  assign z16 = t45 & y14;
  assign z17 = t41 & y8;

  // -------------------------------------------------------------------------
  // Linear post-processing (tc / S layer)
  // -------------------------------------------------------------------------
  logic tc1,  tc2,  tc3,  tc4,  tc5,  tc6,  tc7,  tc8,  tc9;
  logic tc10, tc11, tc12, tc13, tc14, tc16, tc17, tc18, tc20, tc21, tc26;
  logic S0, S1, S2, S3, S4, S5, S6, S7;

  assign tc1  = z15  ^ z16;
  assign tc2  = z10  ^ tc1;
  assign tc3  = z9   ^ tc2;
  assign tc4  = z0   ^ z2;
  assign tc5  = z1   ^ z0;
  assign tc6  = z3   ^ z4;
  assign tc7  = z12  ^ tc4;
  assign tc8  = z7   ^ tc6;
  assign tc9  = z8   ^ tc7;
  assign tc10 = tc8  ^ tc9;
  assign tc11 = tc6  ^ tc5;
  assign tc12 = z3   ^ z5;
  assign tc13 = z13  ^ tc1;
  assign tc14 = tc4  ^ tc12;

  assign S3   = tc3  ^ tc11;

  assign tc16 = z6   ^ tc8;
  assign tc17 = z14  ^ tc10;
  assign tc18 = tc13 ^ tc14;

  assign S7   = ~(z12  ^ tc18);   // XNOR

  assign tc20 = z15  ^ tc16;
  assign tc21 = tc2  ^ z11;

  assign S0   = tc3  ^ tc16;
  assign S6   = ~(tc10 ^ tc18);   // XNOR
  assign S4   = tc14 ^ S3;
  assign S1   = ~(S3  ^ tc16);    // XNOR

  assign tc26 = tc17 ^ tc20;

  assign S2   = ~(tc26 ^ z17);    // XNOR
  assign S5   = tc21 ^ tc17;

  // -------------------------------------------------------------------------
  // Output reassembly: out[7]=S0 (MSB) ... out[0]=S7 (LSB)
  // -------------------------------------------------------------------------
  assign out = {S0, S1, S2, S3, S4, S5, S6, S7};

endmodule
