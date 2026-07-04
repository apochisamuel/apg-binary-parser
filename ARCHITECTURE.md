# Architecture

APG parsing is split into layered passes.

1. `header.c` reads the fixed container header and establishes options.
2. `directory.c` reads the table of contents and captures raw section payloads.
3. `strings.c` loads string pools used by symbols, keyframes, and cache indexes.
4. `attrs.c` loads metadata attributes referenced by symbol records.
5. `entries.c` loads symbols and frame payloads.
6. `reloc.c` loads relocation records and applies section-based symbol lookups.
7. `streams.c` loads keyframes and streams, then materializes stream summaries.
8. `alias.c` loads alias blobs shared between the document and cache layers.
9. `validate.c` performs recoverable integrity passes and can unwind partial state.
10. `resolve.c` resolves names, attributes, relocations, and stream references.
11. `cache.c` builds derived lookup tables and analysis summaries.

The library keeps raw sections and typed sections separately. Later phases rely on pointers cached during earlier phases, so lifecycle handling is centralized around `apg_close` plus targeted recovery passes for damaged containers.
