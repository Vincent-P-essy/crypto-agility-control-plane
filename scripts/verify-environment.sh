#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
OQS_INSTALL_PATH="${OQS_INSTALL_PATH:-$ROOT/.local/oqs}"
export OQS_INSTALL_PATH
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

uv run --frozen python -c 'import ssl; print(ssl.OPENSSL_VERSION)'
uv run --frozen crypto-agility benchmark \
  --iterations 3 \
  --oqs-install-path "$OQS_INSTALL_PATH" \
  --out "$ROOT/reports/generated/environment-smoke.json"
