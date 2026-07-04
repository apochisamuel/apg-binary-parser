#!/bin/bash -eu
cd "$SRC"
mkdir -p "$OUT"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${CFLAGS:=}"
: "${CXXFLAGS:=}"
objs=()
for src in src/*.c; do
  obj="$OUT/$(basename "$src" .c).o"
  "$CC" $CFLAGS -std=c99 -I src -c "$src" -o "$obj"
  objs+=("$obj")
done
for fuzzer in parse_fuzzer entry_fuzzer resolve_fuzzer; do
  "$CXX" $CXXFLAGS -std=c++11 -I src "fuzz/${fuzzer}.cc" "${objs[@]}" "$LIB_FUZZING_ENGINE" -o "$OUT/${fuzzer}"
  if [ -d "fuzz/corpus/${fuzzer}" ]; then
    zip -j "$OUT/${fuzzer}_seed_corpus.zip" fuzz/corpus/${fuzzer}/* >/dev/null
  fi
done