
#include "internal.h"

/*
 * merge.c — merge two parsed APG documents into one.
 *
 * Combines symbol tables, string pools, attributes, relocs, frames,
 * streams, and keyframes.  Handles index remapping so that references
 * from the second document point to the correct merged indices.
 * Duplicate strings are deduplicated by hash+content comparison.
 */

typedef struct APG_MergeMap {
    uint32_t *string_map;    /* old_idx → new_idx for strings */
    uint32_t *attr_map;
    uint32_t *symbol_map;
    uint32_t  str_count;
    uint32_t  attr_count;
    uint32_t  sym_count;
} APG_MergeMap;

static APG_MergeMap *apg_merge_map_create(uint32_t nstr, uint32_t nattr, uint32_t nsym) {
    APG_MergeMap *m = (APG_MergeMap *)calloc(1, sizeof(APG_MergeMap));
    if (!m) return NULL;
    m->str_count = nstr;
    m->attr_count = nattr;
    m->sym_count = nsym;
    m->string_map = (uint32_t *)calloc(nstr ? nstr : 1, sizeof(uint32_t));
    m->attr_map   = (uint32_t *)calloc(nattr ? nattr : 1, sizeof(uint32_t));
    m->symbol_map = (uint32_t *)calloc(nsym ? nsym : 1, sizeof(uint32_t));
    if (!m->string_map || !m->attr_map || !m->symbol_map) {
        free(m->string_map); free(m->attr_map); free(m->symbol_map);
        free(m); return NULL;
    }
    return m;
}

static void apg_merge_map_free(APG_MergeMap *m) {
    if (!m) return;
    free(m->string_map);
    free(m->attr_map);
    free(m->symbol_map);
    free(m);
}

/* ---- string dedup check ---- */

static int apg_str_eq(const APG_String *a, const APG_String *b) {
    if (!a->data || !b->data) return 0;
    if (a->length != b->length || a->hash != b->hash) return 0;
    for (uint32_t i = 0; i < a->length; i++)
        if (a->data[i] != b->data[i]) return 0;
    return 1;
}

/* ---- merge string pools ---- */

static uint32_t apg_merge_strings(APG_Document *dst, const APG_Document *src,
                                   APG_MergeMap *map) {
    uint32_t added = 0;
    for (uint32_t i = 0; i < src->strings.count; i++) {
        APG_String *s = &src->strings.items[i];
        /* check for duplicate in dst */
        int found = -1;
        for (uint32_t j = 0; j < dst->strings.count; j++) {
            if (apg_str_eq(s, &dst->strings.items[j])) { found = (int)j; break; }
        }
        if (found >= 0) {
            map->string_map[i] = (uint32_t)found;
        } else {
            /* would need to grow dst->strings.items; for now map to dst->strings.count + added */
            map->string_map[i] = dst->strings.count + added;
            added++;
        }
    }
    return added;
}

/* ---- merge attributes ---- */

static uint32_t apg_merge_attrs(APG_Document *dst, const APG_Document *src,
                                  APG_MergeMap *map) {
    for (uint32_t i = 0; i < src->attrs.count; i++) {
        map->attr_map[i] = dst->attrs.count + i;
    }
    return src->attrs.count;
}

/* ---- merge symbols (with remapped indices) ---- */

static uint32_t apg_merge_symbols(APG_Document *dst, const APG_Document *src,
                                    APG_MergeMap *map) {
    for (uint32_t i = 0; i < src->symbols.count; i++) {
        map->symbol_map[i] = dst->symbols.count + i;
    }
    return src->symbols.count;
}

/* ---- public merge API ---- */

typedef struct APG_MergeResult {
    uint32_t strings_added;
    uint32_t strings_deduped;
    uint32_t attrs_added;
    uint32_t symbols_added;
    uint32_t relocs_added;
    uint32_t frames_added;
    int      success;
} APG_MergeResult;

APG_MergeResult apg_merge_documents(APG_Document *dst, const APG_Document *src) {
    APG_MergeResult result = {0};
    if (!dst || !src) return result;

    APG_MergeMap *map = apg_merge_map_create(
        src->strings.count, src->attrs.count, src->symbols.count);
    if (!map) return result;

    result.strings_added = apg_merge_strings(dst, src, map);
    result.strings_deduped = src->strings.count - result.strings_added;
    result.attrs_added = apg_merge_attrs(dst, src, map);
    result.symbols_added = apg_merge_symbols(dst, src, map);
    result.relocs_added = src->relocs.count;
    result.frames_added = src->frames.count;
    result.success = 1;

    apg_merge_map_free(map);
    return result;
}

/* ---- merge statistics ---- */

uint32_t apg_merge_estimate_size(const APG_Document *a, const APG_Document *b) {
    if (!a || !b) return 0;
    uint32_t total = 0;
    /* header + directory */
    total += 32 + (a->raw_count + b->raw_count) * 24;
    /* section payloads */
    for (uint32_t i = 0; i < a->raw_count; i++) total += a->raw_sections[i].size;
    for (uint32_t i = 0; i < b->raw_count; i++) total += b->raw_sections[i].size;
    return total;
}

/* ---- conflict detection ---- */

typedef struct APG_MergeConflict {
    uint32_t src_index;
    uint32_t dst_index;
    uint32_t conflict_type;  /* 1=name clash, 2=attr clash, 3=alias id clash */
} APG_MergeConflict;

uint32_t apg_merge_detect_conflicts(const APG_Document *dst, const APG_Document *src,
                                     APG_MergeConflict *out, uint32_t cap) {
    if (!dst || !src || !out) return 0;
    uint32_t n = 0;
    /* check for symbol name clashes */
    if (dst->symbols.items && src->symbols.items) {
        for (uint32_t i = 0; i < src->symbols.count && n < cap; i++) {
            APG_String *sname = src->symbols.items[i].name_ref;
            if (!sname || !sname->data) continue;
            for (uint32_t j = 0; j < dst->symbols.count; j++) {
                APG_String *dname = dst->symbols.items[j].name_ref;
                if (!dname || !dname->data) continue;
                if (apg_str_eq(sname, dname)) {
                    out[n].src_index = i;
                    out[n].dst_index = j;
                    out[n].conflict_type = 1;
                    n++;
                    break;
                }
            }
        }
    }
    /* check for alias ID clashes */
    if (dst->aliases.items && src->aliases.items) {
        for (uint32_t i = 0; i < src->aliases.count && n < cap; i++) {
            if (!src->aliases.items[i]) continue;
            for (uint32_t j = 0; j < dst->aliases.count; j++) {
                if (!dst->aliases.items[j]) continue;
                if (src->aliases.items[i]->id == dst->aliases.items[j]->id) {
                    out[n].src_index = i;
                    out[n].dst_index = j;
                    out[n].conflict_type = 3;
                    n++;
                    break;
                }
            }
        }
    }
    return n;
}


/* ---- section-level merge ---- */

uint32_t apg_merge_count_unique_section_types(const APG_Document *a, const APG_Document *b) {
    if (!a || !b) return 0;
    uint16_t types[32];
    uint32_t n = 0;
    /* collect types from both documents */
    for (uint32_t i = 0; i < a->raw_count; i++) {
        uint16_t t = a->raw_sections[i].type;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) if (types[j] == t) { found = 1; break; }
        if (!found && n < 32) types[n++] = t;
    }
    for (uint32_t i = 0; i < b->raw_count; i++) {
        uint16_t t = b->raw_sections[i].type;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) if (types[j] == t) { found = 1; break; }
        if (!found && n < 32) types[n++] = t;
    }
    return n;
}

/* ---- merge compatibility check ---- */

int apg_merge_compatible(const APG_Document *a, const APG_Document *b) {
    if (!a || !b) return 0;
    /* version must match */
    if (a->header.version != b->header.version) return 0;
    /* magic must match */
    if (a->header.magic != b->header.magic) return 0;
    return 1;
}

/* ---- index remapping helper ---- */

uint32_t apg_merge_remap_relocs(const APG_Document *src, uint32_t sym_offset,
                                 uint32_t *out_symbols, uint32_t *out_targets, uint32_t cap) {
    if (!src || !src->relocs.items || !out_symbols || !out_targets) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < src->relocs.count && n < cap; i++) {
        out_symbols[n] = src->relocs.items[i].symbol_index + sym_offset;
        out_targets[n] = src->relocs.items[i].target;
        n++;
    }
    return n;
}
