
#include "internal.h"

/*
 * transform.c — in-place document transformations.
 *
 * apg_transform_dedup_strings — merge duplicate string pool entries and
 *     rewrite all symbol name_index fields that referenced the removed
 *     duplicates.
 *
 * apg_transform_sort_symbols — sort symbols by derived_score (ascending)
 *     so that later query passes can use early-exit optimisations.
 *
 * apg_transform_compact_frames — remove zero-length frames and shift
 *     remaining frames down.
 *
 * apg_transform_strip_empty_relocs — remove relocations whose
 *     resolved_hash is still zero after resolution.
 */

/* ---------- string deduplication ---------- */

uint32_t apg_transform_dedup_strings(APG_Document *doc) {
    if (!doc || !doc->strings.items || doc->strings.count < 2) return 0;
    uint32_t removed = 0;
    uint32_t n = doc->strings.count;

    /* build a mapping: for each string, the canonical index */
    uint32_t *canon = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!canon) return 0;
    for (uint32_t i = 0; i < n; i++) canon[i] = i;

    for (uint32_t i = 0; i < n; i++) {
        if (canon[i] != i) continue;  /* already mapped elsewhere */
        APG_String *a = &doc->strings.items[i];
        if (!a->data) continue;
        for (uint32_t j = i + 1; j < n; j++) {
            if (canon[j] != j) continue;
            APG_String *b = &doc->strings.items[j];
            if (!b->data || b->length != a->length || b->hash != a->hash) continue;
            /* compare content */
            int eq = 1;
            for (uint32_t k = 0; k < a->length; k++) {
                if (a->data[k] != b->data[k]) { eq = 0; break; }
            }
            if (eq) { canon[j] = i; removed++; }
        }
    }
    /* rewrite symbol name_index references */
    if (removed && doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            uint32_t idx = doc->symbols.items[i].name_index;
            if (idx < n) {
                doc->symbols.items[i].name_index = canon[idx];
                doc->symbols.items[i].name_ref = &doc->strings.items[canon[idx]];
            }
        }
    }
    /* free duplicate string data */
    for (uint32_t i = 0; i < n; i++) {
        if (canon[i] != i && doc->strings.items[i].data) {
            free(doc->strings.items[i].data);
            doc->strings.items[i].data = NULL;
            doc->strings.items[i].length = 0;
        }
    }
    free(canon);
    return removed;
}

/* ---------- symbol sort ---------- */

static void apg_sym_swap(APG_Symbol *a, APG_Symbol *b) {
    APG_Symbol tmp = *a; *a = *b; *b = tmp;
}

void apg_transform_sort_symbols(APG_Document *doc) {
    if (!doc || !doc->symbols.items || doc->symbols.count < 2) return;
    /* insertion sort — stable, fine for typical sizes */
    uint32_t n = doc->symbols.count;
    for (uint32_t i = 1; i < n; i++) {
        uint32_t j = i;
        while (j > 0 && doc->symbols.items[j].derived_score <
                         doc->symbols.items[j-1].derived_score) {
            apg_sym_swap(&doc->symbols.items[j], &doc->symbols.items[j-1]);
            j--;
        }
    }
}

/* ---------- frame compaction ---------- */

uint32_t apg_transform_compact_frames(APG_Document *doc) {
    if (!doc || !doc->frames.items) return 0;
    uint32_t dst = 0, removed = 0;
    for (uint32_t src = 0; src < doc->frames.count; src++) {
        APG_Frame *f = &doc->frames.items[src];
        if (f->payload_len == 0 && !f->payload) {
            removed++;
            continue;
        }
        if (dst != src) doc->frames.items[dst] = doc->frames.items[src];
        dst++;
    }
    doc->frames.count = dst;
    return removed;
}

/* ---------- relocation stripping ---------- */

uint32_t apg_transform_strip_empty_relocs(APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t dst = 0, removed = 0;
    for (uint32_t src = 0; src < doc->relocs.count; src++) {
        if (doc->relocs.items[src].resolved_hash == 0) { removed++; continue; }
        if (dst != src) doc->relocs.items[dst] = doc->relocs.items[src];
        dst++;
    }
    doc->relocs.count = dst;
    return removed;
}

/* ---------- normalise string hashes ---------- */

void apg_transform_rehash_strings(APG_Document *doc) {
    if (!doc || !doc->strings.items) return;
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (s->data && s->length)
            s->hash = apg_hash_bytes((const uint8_t *)s->data, s->length);
    }
}


/* ---- symbol renaming ---- */

uint32_t apg_transform_rename_symbol(APG_Document *doc, uint32_t sym_idx,
                                      const char *new_name, uint32_t name_len) {
    if (!doc || !doc->symbols.items || sym_idx >= doc->symbols.count) return 0;
    if (!doc->strings.items) return 0;
    APG_Symbol *s = &doc->symbols.items[sym_idx];
    uint32_t si = s->name_index;
    if (si >= doc->strings.count) return 0;
    APG_String *str = &doc->strings.items[si];
    free(str->data);
    str->data = (char *)malloc(name_len + 1);
    if (!str->data) { str->length = 0; return 0; }
    memcpy(str->data, new_name, name_len);
    str->data[name_len] = '\0';
    str->length = name_len;
    str->hash = apg_hash_bytes((const uint8_t *)new_name, name_len);
    return 1;
}

/* ---- attribute remapping ---- */

uint32_t apg_transform_remap_attrs(APG_Document *doc,
                                    uint32_t old_val, uint32_t new_val) {
    if (!doc || !doc->attrs.items) return 0;
    uint32_t changed = 0;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].value == old_val) {
            doc->attrs.items[i].value = new_val;
            changed++;
        }
    }
    return changed;
}

/* ---- frame reorder by checksum ---- */

void apg_transform_sort_frames_by_checksum(APG_Document *doc) {
    if (!doc || !doc->frames.items || doc->frames.count < 2) return;
    uint32_t n = doc->frames.count;
    for (uint32_t i = 1; i < n; i++) {
        APG_Frame key = doc->frames.items[i];
        uint32_t j = i;
        while (j > 0 && doc->frames.items[j-1].checksum > key.checksum) {
            doc->frames.items[j] = doc->frames.items[j-1];
            j--;
        }
        doc->frames.items[j] = key;
    }
}

/* ---- merge string tables ---- */

uint32_t apg_transform_merge_string_tables(APG_Document *dst,
                                            const APG_Document *src) {
    if (!dst || !src || !src->strings.items) return 0;
    uint32_t added = 0;
    for (uint32_t i = 0; i < src->strings.count; i++) {
        APG_String *s = &src->strings.items[i];
        if (!s->data) continue;
        /* check if already exists */
        int found = 0;
        for (uint32_t j = 0; j < dst->strings.count; j++) {
            APG_String *d = &dst->strings.items[j];
            if (d->data && d->length == s->length && d->hash == s->hash) {
                int eq = 1;
                for (uint32_t k = 0; k < s->length; k++) {
                    if (d->data[k] != s->data[k]) { eq = 0; break; }
                }
                if (eq) { found = 1; break; }
            }
        }
        if (!found) added++;
    }
    return added;
}
