#!/usr/bin/env bash
# Record the README demo into doc/demo/: r2s-demo.cast and r2s-demo.gif.
# Needs python3 and agg 1.9 (brew install agg); R2S=path skips the cargo build.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/doc/demo
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# doc/demo/wc is gcc 13.3 -O1 -g of wc.c on x86-64 Linux; `ao @ 0x1226` names its loop head.
cp "$out/wc" "$work/wc"
if [ -z "${R2S:-}" ]; then
  cargo build --release -p r2s --features sleigh
  R2S=$root/target/release/r2s
fi
python3 -m venv "$work/venv"
"$work/venv/bin/pip" -q --disable-pip-version-check install pyte==0.8.2
"$work/venv/bin/python" "$root/scripts/record_demo.py" "$R2S" "$work/wc" "$out/r2s-demo.cast"
agg --font-size 14 --line-height 1.25 --theme github-dark --idle-time-limit 5 --fps-cap 15 --speed 1.05 \
  "$out/r2s-demo.cast" "$out/r2s-demo.gif"
if grep -E '/Users|/home/|/private|/var/folders|/root' "$out/r2s-demo.cast"; then
  echo "record_demo.sh: a host path reached the cast" >&2
  exit 1
fi
