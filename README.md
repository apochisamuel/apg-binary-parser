# APG Container Library

APG is a compact C library for reading binary asset-profile graph containers used by media indexing and telemetry pipelines. The format combines a directory, string pools, attribute tables, symbol records, frame payloads, relocation records, keyframes, streams, and alias blobs into one mmap-friendly file.

The library exposes a small memory-based API in `src/lib.h`. It parses each container in phases, builds derived indexes, resolves cross references, computes integrity summaries, and releases all resources through `apg_close`.

## Build

```bash
make test
```

Fenrir-compatible builds use `build.sh`, which relies on `$SRC`, `$OUT`, `$CC`, `$CXX`, `$CFLAGS`, and `$LIB_FUZZING_ENGINE`.

## Format overview

An APG file starts with a 32-byte header, followed by a table of 24-byte directory entries. Each directory entry names a section type and points to section payload bytes. Section parsers are intentionally separated so that callers can inspect header, entry, and resolve behavior through independent fuzzing harnesses.
