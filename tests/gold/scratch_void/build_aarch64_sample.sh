#!/usr/bin/env bash
# The arm64 DecBench sample (ROADMAP D247): `build_aarch64_sample.sh [WORK]` cross-builds the x86 sample's projects,
# versions and flags (DecBench projects/sailr) into aarch64/ and writes decbench_aarch64.manifest; D247 names the grade.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/aarch64"
WORK=${1:-$(mktemp -d)}
HOST=aarch64-linux-gnu
CC="$HOST-gcc"
STRIP="$HOST-strip"
JOBS=${JOBS:-3}
BASE="-g -fno-builtin"

command -v "$CC" >/dev/null || { echo "no $CC (Ubuntu: gcc-aarch64-linux-gnu)" >&2; exit 2; }
mkdir -p "$OUT" "$WORK/src"

# project version url binaries (paths inside the build tree)
PROJECTS=(
  "bzip2|1.0.8|https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz|bzip2 bzip2recover"
  "diffutils|3.8|https://mirrors.kernel.org/gnu/diffutils/diffutils-3.8.tar.xz|src/cmp src/diff src/diff3 src/sdiff"
  "findutils|4.9.0|https://mirrors.kernel.org/gnu/findutils/findutils-4.9.0.tar.xz|find/find"
  "grep|3.8|https://mirrors.kernel.org/gnu/grep/grep-3.8.tar.xz|src/grep"
  "gzip|1.12|https://mirrors.kernel.org/gnu/gzip/gzip-1.12.tar.gz|gzip"
  "libexpat|2.5.0|https://github.com/libexpat/libexpat/releases/download/R_2_5_0/expat-2.5.0.tar.gz|xmlwf/.libs/xmlwf"
  "zlib|1.2.13|https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.gz|example example64 examplesh libz.so.1.2.13 minigzip minigzip64 minigzipsh"
)

fetch() {  # project url: the unpacked source tree, fetched once
  local tarball="$WORK/src/${2##*/}"
  [ -f "$tarball" ] || curl -sSfL --retry 4 -o "$tarball" "$2"
  local tree="$WORK/src/$1"
  if [ ! -d "$tree" ]; then
    mkdir -p "$tree"
    tar xf "$tarball" -C "$tree" --strip-components=1
  fi
  echo "$tree"
}

build() {  # project tree opt cflags: configure and make in a fresh copy
  local project=$1 tree=$2 opt=$3 cflags=$4 dir="$WORK/build/$opt/$1"
  rm -rf "$dir"
  mkdir -p "$dir"
  cp -a "$tree/." "$dir"
  (
    cd "$dir"
    case $project in
      bzip2) make -j"$JOBS" CC="$CC" CFLAGS="$cflags" AR="$HOST-ar" RANLIB="$HOST-ranlib" bzip2 bzip2recover ;;
      zlib) CC="$CC" CFLAGS="$cflags" CHOST=$HOST ./configure >/dev/null && make -j"$JOBS" all ;;
      libexpat) CC="$CC" CFLAGS="$cflags" ./configure --host=$HOST --without-docbook --quiet && make -j"$JOBS" ;;
      diffutils|grep) CC="$CC" CFLAGS="$cflags" ./configure --host=$HOST --quiet --disable-gcc-warnings && make -j"$JOBS" ;;
      *) CC="$CC" CFLAGS="$cflags" ./configure --host=$HOST --quiet && make -j"$JOBS" ;;
    esac
  ) > "$dir.log" 2>&1 || { echo "FAILED $opt $project (log $dir.log)" >&2; return 1; }
}

MANIFEST="$HERE/decbench_aarch64.manifest"
{
  echo "# The arm64 scratch-void sample (ROADMAP D247), built by build_aarch64_sample.sh into aarch64/ (not committed)."
  echo "# $($CC --version | head -n 1); flags $BASE plus -O2, -O2 -fno-inline (O2-noinline) or -O0 (bzip2 only)."
} > "$MANIFEST.tmp"
failed=0
for row in "${PROJECTS[@]}"; do
  IFS='|' read -r project version url binaries <<< "$row"
  tree=$(fetch "$project" "$url")
  for opt in O2 O2-noinline O0; do
    [ "$opt" = O0 ] && [ "$project" != bzip2 ] && continue
    case $opt in O2) flags="-O2" ;; O2-noinline) flags="-O2 -fno-inline" ;; O0) flags="-O0" ;; esac
    build "$project" "$tree" "$opt" "$BASE $flags" || { failed=$((failed + 1)); continue; }
    for binary in $binaries; do
      name="aarch64-$opt-$project-${binary##*/}"
      cp "$WORK/build/$opt/$project/$binary" "$OUT/$name.debug"
      "$STRIP" -o "$OUT/$name.stripped" "$OUT/$name.debug"
      echo "$name aarch64/$name.debug aarch64/$name.stripped" >> "$MANIFEST.tmp"
    done
  done
done
mv "$MANIFEST.tmp" "$MANIFEST"
echo "$(grep -vc '^#' "$MANIFEST") builds in $MANIFEST; $failed project builds failed" >&2
[ "$failed" = 0 ]
