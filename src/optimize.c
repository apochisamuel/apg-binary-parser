
#include "internal.h"

/*
 * optimize.c — multi-pass document optimization.
 *
 * Runs a series of optimization passes over a parsed document to
 * reduce size and improve access patterns:
 *
 *   1. Dead symbol elimination — remove symbols with zero references
 *   2. String pool compaction — remove unreferenced strings
 *   3. Attribute coalescing — merge identical attribute entries
 *   4. Relocation folding — collapse chains of single-target relocs
 *   5. Frame defragmentation — merge adjacent small frames
 */

/* ---- dead symbol elimination ---- */

static uint32_t apg_opt_dead_symbol_elim(APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->relocs.items) return 0;
    uint32_t n = doc->symbols.count;
    uint8_t *referenced = (uint8_t *)calloc(n, 1);
    if (!referenced) return 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].symbol_index;
        if (si < n) referenced[si] = 1;
    }
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        uint32_t ki = doc->streams.items[i].key_index;
        if (ki < doc->keyframes.count) {
            uint32_t ni = doc->keyframes.items[ki].name_index;
            if (ni < doc->strings.count) {
                for (uint32_t j = 0; j < n; j++) {
                    if (doc->symbols.items[j].name_index == ni) referenced[j] = 1;
                }
            }
        }
    }
    uint32_t dst = 0, removed = 0;
    for (uint32_t src = 0; src < n; src++) {
        if (!referenced[src]) { removed++; continue; }
        if (dst != src) doc->symbols.items[dst] = doc->symbols.items[src];
        dst++;
    }
    doc->symbols.count = dst;
    free(referenced);
    return removed;
}

/* ---- string pool compaction ---- */

static uint32_t apg_opt_compact_strings(APG_Document *doc) {
    if (!doc || !doc->strings.items) return 0;
    uint32_t n = doc->strings.count;
    uint8_t *used = (uint8_t *)calloc(n, 1);
    if (!used) return 0;
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            uint32_t ni = doc->symbols.items[i].name_index;
            if (ni < n) used[ni] = 1;
        }
    }
    if (doc->attrs.items) {
        for (uint32_t i = 0; i < doc->attrs.count; i++) {
            uint32_t ni = doc->attrs.items[i].name_index;
            if (ni < n) used[ni] = 1;
        }
    }
    if (doc->keyframes.items) {
        for (uint32_t i = 0; i < doc->keyframes.count; i++) {
            uint32_t ni = doc->keyframes.items[i].name_index;
            if (ni < n) used[ni] = 1;
        }
    }
    uint32_t freed = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (!used[i] && doc->strings.items[i].data) {
            free(doc->strings.items[i].data);
            doc->strings.items[i].data = NULL;
            doc->strings.items[i].length = 0;
            doc->strings.items[i].hash = 0;
            freed++;
        }
    }
    free(used);
    return freed;
}

/* ---- attribute coalescing ---- */

static uint32_t apg_opt_coalesce_attrs(APG_Document *doc) {
    if (!doc || !doc->attrs.items || doc->attrs.count < 2) return 0;
    uint32_t n = doc->attrs.count;
    uint32_t *remap = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!remap) return 0;
    for (uint32_t i = 0; i < n; i++) remap[i] = i;
    uint32_t merged = 0;
    for (uint32_t i = 0; i < n; i++) {
        if (remap[i] != i) continue;
        APG_Attr *a = &doc->attrs.items[i];
        for (uint32_t j = i + 1; j < n; j++) {
            if (remap[j] != j) continue;
            APG_Attr *b = &doc->attrs.items[j];
            if (a->name_index == b->name_index &&
                a->value == b->value &&
                a->flags == b->flags) {
                remap[j] = i;
                merged++;
            }
        }
    }
    if (merged && doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            uint32_t ai = doc->symbols.items[i].attr_index;
            if (ai < n) doc->symbols.items[i].attr_index = remap[ai];
        }
    }
    free(remap);
    return merged;
}

/* ---- relocation chain folding ---- */

static uint32_t apg_opt_fold_relocs(APG_Document *doc) {
    if (!doc || !doc->relocs.items || doc->relocs.count < 2) return 0;
    uint32_t folded = 0;
    uint32_t n = doc->relocs.count;
    for (uint32_t i = 0; i < n; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        if (r->resolved_hash != 0) continue;
        uint32_t chain_len = 0;
        uint32_t cur = i;
        uint8_t *visited = (uint8_t *)calloc(n, 1);
        if (!visited) continue;
        while (cur < n && !visited[cur] && chain_len < 16) {
            visited[cur] = 1;
            uint32_t next = doc->relocs.items[cur].target % n;
            if (next == cur) break;
            if (doc->relocs.items[next].resolved_hash != 0) {
                r->resolved_hash = doc->relocs.items[next].resolved_hash;
                r->target = doc->relocs.items[next].target;
                folded++;
                break;
            }
            cur = next;
            chain_len++;
        }
        free(visited);
    }
    return folded;
}

/* ---- frame defragmentation ---- */

static uint32_t apg_opt_defrag_frames(APG_Document *doc) {
    if (!doc || !doc->frames.items || doc->frames.count < 2) return 0;
    uint32_t merged = 0;
    uint32_t dst = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        APG_Frame *f = &doc->frames.items[i];
        if (f->payload_len == 0) { merged++; continue; }
        if (dst > 0 && doc->frames.items[dst-1].mode == f->mode &&
            doc->frames.items[dst-1].payload_len + f->payload_len <= 4096) {
            APG_Frame *prev = &doc->frames.items[dst-1];
            uint32_t new_len = prev->payload_len + f->payload_len;
            uint8_t *combined = (uint8_t *)malloc(new_len);
            if (combined) {
                if (prev->payload) memcpy(combined, prev->payload, prev->payload_len);
                if (f->payload) memcpy(combined + prev->payload_len, f->payload, f->payload_len);
                free(prev->payload);
                prev->payload = combined;
                prev->payload_len = new_len;
                prev->storage_len = new_len;
                merged++;
                continue;
            }
        }
        if (dst != i) doc->frames.items[dst] = doc->frames.items[i];
        dst++;
    }
    doc->frames.count = dst;
    return merged;
}

/* ---- full optimization pipeline ---- */

typedef struct APG_OptResult {
    uint32_t dead_symbols_removed;
    uint32_t unused_strings_freed;
    uint32_t attrs_coalesced;
    uint32_t relocs_folded;
    uint32_t frames_merged;
    uint32_t total_savings;
} APG_OptResult;

APG_OptResult apg_optimize(APG_Document *doc) {
    APG_OptResult r = {0};
    if (!doc) return r;
    r.dead_symbols_removed = apg_opt_dead_symbol_elim(doc);
    r.unused_strings_freed = apg_opt_compact_strings(doc);
    r.attrs_coalesced = apg_opt_coalesce_attrs(doc);
    r.relocs_folded = apg_opt_fold_relocs(doc);
    r.frames_merged = apg_opt_defrag_frames(doc);
    r.total_savings = r.dead_symbols_removed + r.unused_strings_freed +
                      r.attrs_coalesced + r.relocs_folded + r.frames_merged;
    return r;
}

int apg_optimize_needed(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t indicators = 0;
    if (doc->symbols.items && doc->relocs.items) {
        uint8_t *ref = (uint8_t *)calloc(doc->symbols.count, 1);
        if (ref) {
            for (uint32_t i = 0; i < doc->relocs.count; i++) {
                uint32_t si = doc->relocs.items[i].symbol_index;
                if (si < doc->symbols.count) ref[si] = 1;
            }
            for (uint32_t i = 0; i < doc->symbols.count; i++)
                if (!ref[i]) indicators++;
            free(ref);
        }
    }
    for (uint32_t i = 0; i < doc->frames.count; i++)
        if (doc->frames.items[i].payload_len == 0) indicators++;
    return indicators > 0;
}


/* ---- optimization cost estimation ---- */

typedef struct APG_OptCost {
    uint32_t bytes_before;
    uint32_t bytes_after_est;
    uint32_t elements_before;
    uint32_t elements_after_est;
    double   reduction_pct;
} APG_OptCost;

APG_OptCost apg_optimize_estimate(const APG_Document *doc) {
    APG_OptCost c = {0};
    if (!doc) return c;
    c.elements_before = doc->symbols.count + doc->strings.count + doc->attrs.count +
                        doc->relocs.count + doc->frames.count;
    for (uint32_t i = 0; i < doc->raw_count; i++)
        c.bytes_before += doc->raw_sections[i].size;
    uint32_t removable = 0;
    if (doc->symbols.items && doc->relocs.items) {
        uint8_t *ref = (uint8_t *)calloc(doc->symbols.count, 1);
        if (ref) {
            for (uint32_t i = 0; i < doc->relocs.count; i++) {
                uint32_t si = doc->relocs.items[i].symbol_index;
                if (si < doc->symbols.count) ref[si] = 1;
            }
            for (uint32_t i = 0; i < doc->symbols.count; i++)
                if (!ref[i]) removable++;
            free(ref);
        }
    }
    for (uint32_t i = 0; i < doc->frames.count; i++)
        if (doc->frames.items[i].payload_len == 0) removable++;
    c.elements_after_est = c.elements_before - removable;
    c.bytes_after_est = c.bytes_before;
    c.reduction_pct = c.elements_before ? (double)removable * 100.0 / (double)c.elements_before : 0.0;
    return c;
}
