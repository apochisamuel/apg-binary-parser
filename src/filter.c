
#include "internal.h"

/*
 * filter.c — composable predicate filters for document elements.
 *
 * Filters are small predicate objects that can be AND/OR composed.
 * Apply them to symbols, frames, or relocs to produce a filtered view.
 */

typedef enum {
    APG_FILT_TRUE,
    APG_FILT_FALSE,
    APG_FILT_KLASS_EQ,
    APG_FILT_AUX_GE,
    APG_FILT_AUX_LE,
    APG_FILT_SCORE_ABOVE,
    APG_FILT_HAS_NAME,
    APG_FILT_AND,
    APG_FILT_OR,
    APG_FILT_NOT
} APG_FilterOp;

struct APG_Filter {
    APG_FilterOp   op;
    uint32_t       operand;
    struct APG_Filter *left;
    struct APG_Filter *right;
};

static APG_Filter *apg_filter_alloc(APG_FilterOp op, uint32_t operand) {
    APG_Filter *f = (APG_Filter *)calloc(1, sizeof(APG_Filter));
    if (f) { f->op = op; f->operand = operand; }
    return f;
}

APG_Filter *apg_filter_true(void)              { return apg_filter_alloc(APG_FILT_TRUE, 0); }
APG_Filter *apg_filter_false(void)             { return apg_filter_alloc(APG_FILT_FALSE, 0); }
APG_Filter *apg_filter_klass_eq(uint16_t k)    { return apg_filter_alloc(APG_FILT_KLASS_EQ, k); }
APG_Filter *apg_filter_aux_ge(uint32_t v)      { return apg_filter_alloc(APG_FILT_AUX_GE, v); }
APG_Filter *apg_filter_aux_le(uint32_t v)      { return apg_filter_alloc(APG_FILT_AUX_LE, v); }
APG_Filter *apg_filter_score_above(uint32_t v) { return apg_filter_alloc(APG_FILT_SCORE_ABOVE, v); }
APG_Filter *apg_filter_has_name(void)          { return apg_filter_alloc(APG_FILT_HAS_NAME, 0); }

APG_Filter *apg_filter_and(APG_Filter *a, APG_Filter *b) {
    APG_Filter *f = apg_filter_alloc(APG_FILT_AND, 0);
    if (f) { f->left = a; f->right = b; }
    return f;
}

APG_Filter *apg_filter_or(APG_Filter *a, APG_Filter *b) {
    APG_Filter *f = apg_filter_alloc(APG_FILT_OR, 0);
    if (f) { f->left = a; f->right = b; }
    return f;
}

APG_Filter *apg_filter_not(APG_Filter *inner) {
    APG_Filter *f = apg_filter_alloc(APG_FILT_NOT, 0);
    if (f) f->left = inner;
    return f;
}

static int apg_filter_eval(const APG_Filter *f, const APG_Symbol *s) {
    if (!f) return 1;
    switch (f->op) {
        case APG_FILT_TRUE:        return 1;
        case APG_FILT_FALSE:       return 0;
        case APG_FILT_KLASS_EQ:    return s->klass == (uint16_t)f->operand;
        case APG_FILT_AUX_GE:     return s->aux >= f->operand;
        case APG_FILT_AUX_LE:     return s->aux <= f->operand;
        case APG_FILT_SCORE_ABOVE: return s->derived_score > f->operand;
        case APG_FILT_HAS_NAME:   return s->name_ref && s->name_ref->data;
        case APG_FILT_AND:        return apg_filter_eval(f->left, s) && apg_filter_eval(f->right, s);
        case APG_FILT_OR:         return apg_filter_eval(f->left, s) || apg_filter_eval(f->right, s);
        case APG_FILT_NOT:        return !apg_filter_eval(f->left, s);
    }
    return 0;
}

uint32_t apg_filter_count(const APG_Document *doc, const APG_Filter *filt) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        if (apg_filter_eval(filt, &doc->symbols.items[i])) count++;
    return count;
}

uint32_t apg_filter_collect(const APG_Document *doc, const APG_Filter *filt,
                            uint32_t *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++)
        if (apg_filter_eval(filt, &doc->symbols.items[i])) out[n++] = i;
    return n;
}

void apg_filter_free(APG_Filter *f) {
    if (!f) return;
    apg_filter_free(f->left);
    apg_filter_free(f->right);
    free(f);
}


/* ---- range predicate ---- */

APG_Filter *apg_filter_aux_between(uint32_t lo, uint32_t hi) {
    return apg_filter_and(apg_filter_aux_ge(lo), apg_filter_aux_le(hi));
}

/* ---- named class filter ---- */

APG_Filter *apg_filter_klass_not(uint16_t k) {
    return apg_filter_not(apg_filter_klass_eq(k));
}

/* ---- depth measurement ---- */

static uint32_t apg_filter_depth_inner(const APG_Filter *f) {
    if (!f) return 0;
    uint32_t l = apg_filter_depth_inner(f->left);
    uint32_t r = apg_filter_depth_inner(f->right);
    return 1 + (l > r ? l : r);
}

uint32_t apg_filter_depth(const APG_Filter *f) {
    return apg_filter_depth_inner(f);
}

/* ---- filter statistics: count nodes ---- */

static uint32_t apg_filter_node_count_inner(const APG_Filter *f) {
    if (!f) return 0;
    return 1 + apg_filter_node_count_inner(f->left) + apg_filter_node_count_inner(f->right);
}

uint32_t apg_filter_node_count(const APG_Filter *f) {
    return apg_filter_node_count_inner(f);
}

/* ---- apply to frames ---- */

uint32_t apg_filter_frames_by_size(const APG_Document *doc,
                                    uint32_t min_size, uint32_t max_size,
                                    uint32_t *out, uint32_t cap) {
    if (!doc || !doc->frames.items || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->frames.count && n < cap; i++) {
        uint32_t pl = doc->frames.items[i].payload_len;
        if (pl >= min_size && pl <= max_size) out[n++] = i;
    }
    return n;
}

/* ---- apply to relocs ---- */

uint32_t apg_filter_resolved_relocs(const APG_Document *doc,
                                     uint32_t *out, uint32_t cap) {
    if (!doc || !doc->relocs.items || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count && n < cap; i++) {
        if (doc->relocs.items[i].resolved_hash != 0) out[n++] = i;
    }
    return n;
}
