
#include "internal.h"

/*
 * relocator.c — multi-pass relocation engine with cycle-safe resolution,
 * depth-limited chaining, and relocation statistics.
 *
 * The standard apg_apply_relocations does a single pass.  This module
 * provides iterative resolution: each pass propagates resolved hashes
 * through dependent relocations until a fixed point or depth limit.
 */

typedef struct APG_RelocStats {
    uint32_t total;
    uint32_t resolved_pass1;
    uint32_t resolved_multi;
    uint32_t unresolvable;
    uint32_t circular;
    uint32_t max_chain_depth;
    uint32_t passes_needed;
} APG_RelocStats;

/* ---- single-pass resolve count ---- */

static uint32_t apg_reloc_resolve_pass(APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t newly = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        if (r->resolved_hash != 0) continue;
        /* try to resolve via the symbol table */
        if (r->symbol_index < doc->symbols.count) {
            uint32_t sh = doc->symbols.items[r->symbol_index].derived_score;
            if (sh != 0) {
                r->resolved_hash = apg_mix_u32(sh, r->target);
                newly++;
            }
        }
    }
    return newly;
}

/* ---- chain depth computation ---- */

static uint32_t apg_reloc_chain_depth(const APG_Document *doc, uint32_t idx,
                                       uint8_t *visited, uint32_t limit) {
    if (idx >= doc->relocs.count || visited[idx] || limit == 0) return 0;
    visited[idx] = 1;
    APG_Reloc *r = &doc->relocs.items[idx];
    /* follow the target as a reloc index if it points to another reloc */
    uint32_t next = r->target % doc->relocs.count;
    if (next == idx) return 1;
    uint32_t depth = 1 + apg_reloc_chain_depth(doc, next, visited, limit - 1);
    visited[idx] = 0;
    return depth;
}

/* ---- multi-pass resolve ---- */

APG_RelocStats apg_relocator_resolve(APG_Document *doc, uint32_t max_passes) {
    APG_RelocStats stats = {0};
    if (!doc || !doc->relocs.items) return stats;
    stats.total = doc->relocs.count;
    if (max_passes == 0) max_passes = 16;
    /* pass 1: standard resolution */
    uint32_t resolved = apg_reloc_resolve_pass(doc);
    stats.resolved_pass1 = resolved;
    stats.passes_needed = 1;
    /* iterative passes */
    for (uint32_t pass = 1; pass < max_passes; pass++) {
        uint32_t newly = 0;
        for (uint32_t i = 0; i < doc->relocs.count; i++) {
            APG_Reloc *r = &doc->relocs.items[i];
            if (r->resolved_hash != 0) continue;
            /* try to resolve through other resolved relocs */
            uint32_t dep = r->target % doc->relocs.count;
            if (dep < doc->relocs.count && doc->relocs.items[dep].resolved_hash != 0) {
                r->resolved_hash = apg_mix_u32(doc->relocs.items[dep].resolved_hash, r->flags);
                newly++;
            }
        }
        if (newly == 0) break;
        stats.resolved_multi += newly;
        stats.passes_needed = pass + 1;
    }
    /* count unresolvable and circular */
    uint8_t *visited = (uint8_t *)calloc(doc->relocs.count, 1);
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        if (doc->relocs.items[i].resolved_hash == 0) stats.unresolvable++;
        if (visited) {
            memset(visited, 0, doc->relocs.count);
            uint32_t depth = apg_reloc_chain_depth(doc, i, visited, 64);
            if (depth > stats.max_chain_depth) stats.max_chain_depth = depth;
        }
    }
    free(visited);
    /* detect cycles: any reloc that chains back to itself */
    if (visited) {
        visited = (uint8_t *)calloc(doc->relocs.count, 1);
        for (uint32_t i = 0; i < doc->relocs.count; i++) {
            uint32_t slow = i, fast = i;
            int cycle = 0;
            for (uint32_t step = 0; step < doc->relocs.count; step++) {
                slow = doc->relocs.items[slow].target % doc->relocs.count;
                fast = doc->relocs.items[fast].target % doc->relocs.count;
                if (fast < doc->relocs.count)
                    fast = doc->relocs.items[fast].target % doc->relocs.count;
                if (slow == fast) { cycle = 1; break; }
            }
            if (cycle) stats.circular++;
        }
        free(visited);
    }
    return stats;
}

/* ---- relocation dependency list ---- */

uint32_t apg_reloc_dependents(const APG_Document *doc, uint32_t reloc_idx,
                               uint32_t *out, uint32_t cap) {
    if (!doc || !doc->relocs.items || reloc_idx >= doc->relocs.count || !out) return 0;
    uint32_t target_sym = doc->relocs.items[reloc_idx].symbol_index;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count && n < cap; i++) {
        if (i == reloc_idx) continue;
        if (doc->relocs.items[i].target % doc->relocs.count == reloc_idx) out[n++] = i;
    }
    return n;
}

/* ---- relocation clustering ---- */

typedef struct APG_RelocCluster {
    uint32_t section_index;
    uint32_t count;
    uint32_t resolved;
} APG_RelocCluster;

uint32_t apg_reloc_cluster_by_section(const APG_Document *doc,
                                       APG_RelocCluster *out, uint32_t cap) {
    if (!doc || !doc->relocs.items || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].section_index;
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n; j++) {
            if (out[j].section_index == si) { found = j; break; }
        }
        if (found != UINT32_MAX) {
            out[found].count++;
            if (doc->relocs.items[i].resolved_hash) out[found].resolved++;
        } else if (n < cap) {
            out[n].section_index = si;
            out[n].count = 1;
            out[n].resolved = doc->relocs.items[i].resolved_hash ? 1 : 0;
            n++;
        }
    }
    return n;
}


/* ---- relocation priority queue ---- */

static void apg_reloc_swap_u32(uint32_t *a, uint32_t *b) {
    uint32_t t = *a; *a = *b; *b = t;
}

/*
 * Priority-based resolution: resolve relocations in order of
 * dependency count.  Relocations with fewer dependencies should
 * be resolved first to maximise single-pass resolution.
 */
uint32_t *apg_reloc_priority_order(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return NULL;
    uint32_t n = doc->relocs.count;
    /* compute dependency count for each reloc */
    uint32_t *deps = (uint32_t *)calloc(n, sizeof(uint32_t));
    uint32_t *order = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!deps || !order) { free(deps); free(order); return NULL; }
    for (uint32_t i = 0; i < n; i++) {
        order[i] = i;
        uint32_t target = doc->relocs.items[i].target % n;
        if (target < n) deps[target]++;
    }
    /* sort by dependency count ascending (insertion sort) */
    for (uint32_t i = 1; i < n; i++) {
        uint32_t j = i;
        while (j > 0 && deps[order[j]] < deps[order[j-1]]) {
            apg_reloc_swap_u32(&order[j], &order[j-1]);
            j--;
        }
    }
    free(deps);
    return order;
}

/* ---- prioritised resolution ---- */

uint32_t apg_reloc_resolve_prioritised(APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t *order = apg_reloc_priority_order(doc);
    if (!order) return 0;
    uint32_t resolved = 0;
    for (uint32_t pass = 0; pass < 8; pass++) {
        uint32_t newly = 0;
        for (uint32_t k = 0; k < doc->relocs.count; k++) {
            uint32_t i = order[k];
            APG_Reloc *r = &doc->relocs.items[i];
            if (r->resolved_hash != 0) continue;
            if (r->symbol_index < doc->symbols.count) {
                uint32_t sh = doc->symbols.items[r->symbol_index].derived_score;
                if (sh != 0) {
                    r->resolved_hash = apg_mix_u32(sh, r->target);
                    newly++;
                }
            }
            /* try chain resolution */
            if (r->resolved_hash == 0) {
                uint32_t dep = r->target % doc->relocs.count;
                if (dep < doc->relocs.count && doc->relocs.items[dep].resolved_hash != 0) {
                    r->resolved_hash = apg_mix_u32(doc->relocs.items[dep].resolved_hash, r->flags);
                    newly++;
                }
            }
        }
        resolved += newly;
        if (newly == 0) break;
    }
    free(order);
    return resolved;
}

/* ---- relocation weight metric ---- */

double apg_reloc_weight(const APG_Document *doc, uint32_t reloc_idx) {
    if (!doc || !doc->relocs.items || reloc_idx >= doc->relocs.count) return 0.0;
    APG_Reloc *r = &doc->relocs.items[reloc_idx];
    double weight = 1.0;
    /* weight increases with chain depth */
    uint32_t depth = 0;
    uint32_t cur = reloc_idx;
    uint8_t *visited = (uint8_t *)calloc(doc->relocs.count, 1);
    if (visited) {
        while (cur < doc->relocs.count && !visited[cur] && depth < 32) {
            visited[cur] = 1;
            cur = doc->relocs.items[cur].target % doc->relocs.count;
            depth++;
        }
        free(visited);
    }
    weight += depth * 0.5;
    /* weight by number of dependents */
    uint32_t dep_count = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        if (doc->relocs.items[i].target % doc->relocs.count == reloc_idx) dep_count++;
    }
    weight += dep_count * 0.3;
    (void)r;
    return weight;
}
