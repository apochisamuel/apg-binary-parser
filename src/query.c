/*
 * query.c — predicate-based symbol query engine.
 *
 * Supports filtered iteration over symbols using composable predicates:
 * name substring, attribute value range, class bitmask, and aux threshold.
 * Results are collected into a hit-list that callers drain with apg_query_next.
 */
#include "internal.h"

/* ------------------------------------------------------------------ */
/*  predicate helpers                                                  */
/* ------------------------------------------------------------------ */

static int apg_pred_name_contains(const APG_Document *doc,
                                  const APG_Symbol *sym,
                                  const char *needle, uint32_t needle_len) {
    if (!needle || !needle_len) return 1;            /* vacuously true */
    APG_String *ref = sym->name_ref;
    if (!ref || !ref->data || ref->length < needle_len) return 0;
    for (uint32_t start = 0; start + needle_len <= ref->length; start++) {
        uint32_t j = 0;
        while (j < needle_len && ref->data[start + j] == needle[j]) j++;
        if (j == needle_len) return 1;
    }
    (void)doc;
    return 0;
}

static int apg_pred_attr_range(const APG_Document *doc,
                               const APG_Symbol *sym,
                               uint32_t lo, uint32_t hi) {
    if (!doc->attrs.items || sym->attr_index >= doc->attrs.count) return 0;
    uint32_t v = doc->attrs.items[sym->attr_index].value;
    return v >= lo && v <= hi;
}

static int apg_pred_class_mask(const APG_Symbol *sym, uint16_t mask) {
    if (!mask) return 1;
    return (sym->klass & mask) != 0;
}

static int apg_pred_aux_above(const APG_Symbol *sym, uint32_t threshold) {
    return sym->aux >= threshold;
}

/* ------------------------------------------------------------------ */
/*  query object                                                       */
/* ------------------------------------------------------------------ */

APG_Query *apg_query_create(const APG_Document *doc) {
    if (!doc) return NULL;
    APG_Query *q = (APG_Query *)calloc(1, sizeof(APG_Query));
    if (!q) return NULL;
    q->doc = doc;
    q->class_mask = 0;
    q->aux_threshold = 0;
    q->attr_lo = 0;
    q->attr_hi = UINT32_MAX;
    return q;
}

void apg_query_set_name(APG_Query *q, const char *pattern) {
    if (!q || !pattern) return;
    q->name_pattern = pattern;
    q->name_len = 0;
    while (pattern[q->name_len]) q->name_len++;
}

void apg_query_set_class(APG_Query *q, uint16_t mask) {
    if (q) q->class_mask = mask;
}

void apg_query_set_aux_min(APG_Query *q, uint32_t min_aux) {
    if (q) q->aux_threshold = min_aux;
}

void apg_query_set_attr_range(APG_Query *q, uint32_t lo, uint32_t hi) {
    if (!q) return;
    q->attr_lo = lo;
    q->attr_hi = hi;
}

/* ------------------------------------------------------------------ */
/*  execution: collect matching symbols                                */
/* ------------------------------------------------------------------ */

static int apg_query_grow(APG_Query *q) {
    uint32_t next = q->hit_cap ? q->hit_cap * 2u : 16u;
    uint32_t *buf = (uint32_t *)realloc(q->hits, (size_t)next * sizeof(uint32_t));
    if (!buf) return 0;
    q->hits = buf;
    q->hit_cap = next;
    return 1;
}

uint32_t apg_query_execute(APG_Query *q) {
    if (!q || !q->doc || !q->doc->symbols.items) return 0;
    q->hit_count = 0;
    q->cursor = 0;
    const APG_Document *doc = q->doc;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        if (!apg_pred_name_contains(doc, s, q->name_pattern, q->name_len)) continue;
        if (!apg_pred_class_mask(s, q->class_mask)) continue;
        if (!apg_pred_aux_above(s, q->aux_threshold)) continue;
        if (q->attr_lo != 0 || q->attr_hi != UINT32_MAX) {
            if (!apg_pred_attr_range(doc, s, q->attr_lo, q->attr_hi)) continue;
        }
        if (q->hit_count == q->hit_cap && !apg_query_grow(q)) break;
        q->hits[q->hit_count++] = i;
    }
    return q->hit_count;
}

int apg_query_next(APG_Query *q, uint32_t *out_index) {
    if (!q || q->cursor >= q->hit_count) return 0;
    if (out_index) *out_index = q->hits[q->cursor];
    q->cursor++;
    return 1;
}

void apg_query_reset(APG_Query *q) {
    if (q) q->cursor = 0;
}

void apg_query_free(APG_Query *q) {
    if (!q) return;
    free(q->hits);
    free(q);
}

/* ------------------------------------------------------------------ */
/*  convenience: count symbols matching a name prefix                  */
/* ------------------------------------------------------------------ */

uint32_t apg_count_symbols_with_prefix(const APG_Document *doc,
                                       const char *prefix) {
    if (!doc || !doc->symbols.items || !prefix) return 0;
    uint32_t plen = 0;
    while (prefix[plen]) plen++;
    if (!plen) return doc->symbols.count;
    uint32_t count = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data || ref->length < plen) continue;
        uint32_t j = 0;
        while (j < plen && ref->data[j] == prefix[j]) j++;
        if (j == plen) count++;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/*  scored ranking: sort hits by derived_score descending              */
/* ------------------------------------------------------------------ */

static void apg_query_swap(uint32_t *a, uint32_t *b) {
    uint32_t t = *a; *a = *b; *b = t;
}

static void apg_query_sort_hits(APG_Query *q) {
    if (!q || q->hit_count < 2) return;
    const APG_Symbol *syms = q->doc->symbols.items;
    for (uint32_t i = 1; i < q->hit_count; i++) {
        uint32_t j = i;
        while (j > 0 && syms[q->hits[j]].derived_score > syms[q->hits[j-1]].derived_score) {
            apg_query_swap(&q->hits[j], &q->hits[j-1]);
            j--;
        }
    }
}

uint32_t apg_query_execute_ranked(APG_Query *q) {
    uint32_t n = apg_query_execute(q);
    if (n > 1) apg_query_sort_hits(q);
    return n;
}


/* ---- glob-style pattern matching (supports * and ?) ---- */

static int apg_glob_match(const char *pattern, uint32_t plen,
                           const char *str, uint32_t slen) {
    uint32_t pi = 0, si = 0;
    uint32_t star_p = UINT32_MAX, star_s = UINT32_MAX;
    while (si < slen) {
        if (pi < plen && (pattern[pi] == '?' || pattern[pi] == str[si])) {
            pi++; si++;
        } else if (pi < plen && pattern[pi] == '*') {
            star_p = pi++;
            star_s = si;
        } else if (star_p != UINT32_MAX) {
            pi = star_p + 1;
            si = ++star_s;
        } else {
            return 0;
        }
    }
    while (pi < plen && pattern[pi] == '*') pi++;
    return pi == plen;
}

uint32_t apg_query_glob(const APG_Document *doc, const char *pattern,
                          uint32_t *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !pattern || !out) return 0;
    uint32_t plen = 0;
    while (pattern[plen]) plen++;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data) continue;
        if (apg_glob_match(pattern, plen, ref->data, ref->length)) {
            out[n++] = i;
        }
    }
    return n;
}

/* ---- multi-criteria query ---- */

uint32_t apg_query_multi(const APG_Document *doc,
                          const char *name_pattern,
                          uint16_t class_mask,
                          uint32_t min_score,
                          uint32_t *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !out) return 0;
    uint32_t plen = 0;
    if (name_pattern) while (name_pattern[plen]) plen++;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        /* name pattern check */
        if (name_pattern && plen) {
            APG_String *ref = s->name_ref;
            if (!ref || !ref->data) continue;
            if (!apg_glob_match(name_pattern, plen, ref->data, ref->length)) continue;
        }
        /* class mask check */
        if (class_mask && !(s->klass & class_mask)) continue;
        /* score threshold */
        if (s->derived_score < min_score) continue;
        out[n++] = i;
    }
    return n;
}
