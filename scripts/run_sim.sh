#!/bin/bash
set -e

PROJ_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SIM_DIR="$PROJ_DIR/sim_work"

mkdir -p "$SIM_DIR"
cd "$SIM_DIR"

RTL=(
  "$PROJ_DIR/rtl/aes_pkg.sv"
  "$PROJ_DIR/rtl/prng_simple.sv"
  "$PROJ_DIR/rtl/aes_sbox_cmt.sv"
  "$PROJ_DIR/rtl/aes_sbox_precompute.sv"
  "$PROJ_DIR/rtl/aes_key_schedule.sv"
  "$PROJ_DIR/rtl/aes_masked_core.sv"
)

echo "=== Compiling RTL + testbenches ==="
vlog -sv "${RTL[@]}" \
  "$PROJ_DIR/tb/tb_aes_sbox_cmt.sv" \
  "$PROJ_DIR/tb/tb_aes_masked_core.sv"

echo ""
echo "=== [1/2] S-box unit test ==="
vsim -batch -do "run -all; quit -f" tb_aes_sbox_cmt

echo ""
echo "=== [2/2] AES core integration test ==="
vsim -batch -do "run -all; quit -f" tb_aes_masked_core
