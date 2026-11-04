#!/usr/bin/env bash
# F055 timing run. Usage: run_f055.sh "<F055_CONFIGS>" [F055_N] [outfile]
set -euo pipefail
. "$HOME/.cargo/env" 2>/dev/null || true
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC=$HERE/f055_build_metrics_timing.rs
TREE="${TREE:-$HOME/hs-7eb981b}"  # path to a `git archive 7eb981b` build tree
mkdir -p "$TREE/crates/proof-of-quality/tests"
cp "$SRC" "$TREE/crates/proof-of-quality/tests/f055_build_metrics_timing.rs"
cd "$TREE"
export RUSTFLAGS="--cap-lints allow"
export F055_CONFIGS="${1:-high:10000}"
export F055_N="${2:-3357387}"
OUT="${3:-$HERE/F055-test-output.txt}"
{
  echo "# cmd: cargo test -p proof-of-quality --release --test f055_build_metrics_timing -- --nocapture --test-threads=1"
  echo "# F055_CONFIGS=$F055_CONFIGS F055_N=$F055_N"
  echo "# host: $(nproc) cores, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
  echo "# rustc: $(rustc --version)"
  date -u +"# date: %Y-%m-%dT%H:%M:%SZ"
  time cargo test -p proof-of-quality --release --test f055_build_metrics_timing -- --nocapture --test-threads=1
} >"$OUT" 2>&1
tail -n 25 "$OUT"
