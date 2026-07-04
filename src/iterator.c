
#include "internal.h"

/*
 * iterator.c — unified iteration over document elements.
 *
 * Provides cursor-based iterators for symbols, strings, frames,
 * keyframes, streams, relocs, and raw sections.  Each iterator
 * supports forward traversal, peek, skip, and count-remaining.
 * A "zip" iterator pairs elements from two iterators for
 * parallel traversal (useful for diff and comparison).
 */

typedef enum {
    APG_ITER_SYMBOLS,
    APG_ITER_STRINGS,
    APG_ITER_FRAMES,
    APG_ITER_KEYFRAMES,
    APG_ITER_STREAMS,
    APG_ITER_RELOCS,
    APG_ITER_RAW_SECTIONS
} APG_IterKind;

typedef struct APG_Iterator {
    const APG_Document *doc;
    APG_IterKind        kind;
    uint32_t            cursor;
    uint32_t            limit;
} APG_Iterator;

static uint32_t apg_iter_total(const APG_Document *doc, APG_IterKind kind) {
    switch (kind) {
        case APG_ITER_SYMBOLS:      return doc->symbols.count;
        case APG_ITER_STRINGS:      return doc->strings.count;
        case APG_ITER_FRAMES:       return doc->frames.count;
        case APG_ITER_KEYFRAMES:    return doc->keyframes.count;
        case APG_ITER_STREAMS:      return doc->streams.count;
        case APG_ITER_RELOCS:       return doc->relocs.count;
        case APG_ITER_RAW_SECTIONS: return doc->raw_count;
    }
    return 0;
}

APG_Iterator *apg_iter_create(const APG_Document *doc, APG_IterKind kind) {
    if (!doc) return NULL;
    APG_Iterator *it = (APG_Iterator *)calloc(1, sizeof(APG_Iterator));
    if (!it) return NULL;
    it->doc = doc;
    it->kind = kind;
    it->cursor = 0;
    it->limit = apg_iter_total(doc, kind);
    return it;
}

int apg_iter_has_next(const APG_Iterator *it) {
    return it && it->cursor < it->limit;
}

uint32_t apg_iter_next(APG_Iterator *it) {
    if (!it || it->cursor >= it->limit) return UINT32_MAX;
    return it->cursor++;
}

uint32_t apg_iter_peek(const APG_Iterator *it) {
    if (!it || it->cursor >= it->limit) return UINT32_MAX;
    return it->cursor;
}

void apg_iter_skip(APG_Iterator *it, uint32_t n) {
    if (!it) return;
    it->cursor += n;
    if (it->cursor > it->limit) it->cursor = it->limit;
}

uint32_t apg_iter_remaining(const APG_Iterator *it) {
    if (!it || it->cursor >= it->limit) return 0;
    return it->limit - it->cursor;
}

void apg_iter_reset(APG_Iterator *it) {
    if (it) it->cursor = 0;
}

void apg_iter_free(APG_Iterator *it) { free(it); }

/* ---- element access by iterator ---- */

const APG_Symbol *apg_iter_symbol(const APG_Iterator *it) {
    if (!it || it->kind != APG_ITER_SYMBOLS || it->cursor >= it->limit) return NULL;
    return &it->doc->symbols.items[it->cursor];
}

const APG_String *apg_iter_string(const APG_Iterator *it) {
    if (!it || it->kind != APG_ITER_STRINGS || it->cursor >= it->limit) return NULL;
    return &it->doc->strings.items[it->cursor];
}

const APG_Frame *apg_iter_frame(const APG_Iterator *it) {
    if (!it || it->kind != APG_ITER_FRAMES || it->cursor >= it->limit) return NULL;
    return &it->doc->frames.items[it->cursor];
}

const APG_Stream *apg_iter_stream(const APG_Iterator *it) {
    if (!it || it->kind != APG_ITER_STREAMS || it->cursor >= it->limit) return NULL;
    return &it->doc->streams.items[it->cursor];
}

const APG_Reloc *apg_iter_reloc(const APG_Iterator *it) {
    if (!it || it->kind != APG_ITER_RELOCS || it->cursor >= it->limit) return NULL;
    return &it->doc->relocs.items[it->cursor];
}

/* ---- zip iterator ---- */

typedef struct APG_ZipIter {
    APG_Iterator *left;
    APG_Iterator *right;
} APG_ZipIter;

APG_ZipIter *apg_zip_create(APG_Iterator *a, APG_Iterator *b) {
    if (!a || !b) return NULL;
    APG_ZipIter *z = (APG_ZipIter *)calloc(1, sizeof(APG_ZipIter));
    if (!z) return NULL;
    z->left = a;
    z->right = b;
    return z;
}

int apg_zip_has_next(const APG_ZipIter *z) {
    return z && apg_iter_has_next(z->left) && apg_iter_has_next(z->right);
}

int apg_zip_advance(APG_ZipIter *z, uint32_t *out_l, uint32_t *out_r) {
    if (!apg_zip_has_next(z)) return 0;
    if (out_l) *out_l = apg_iter_next(z->left);
    if (out_r) *out_r = apg_iter_next(z->right);
    return 1;
}

void apg_zip_free(APG_ZipIter *z) {
    if (!z) return;
    apg_iter_free(z->left);
    apg_iter_free(z->right);
    free(z);
}

/* ---- filtered iteration ---- */

uint32_t apg_iter_next_matching(APG_Iterator *it,
                                 int (*pred)(const APG_Document *, uint32_t)) {
    if (!it || !pred) return UINT32_MAX;
    while (it->cursor < it->limit) {
        uint32_t idx = it->cursor++;
        if (pred(it->doc, idx)) return idx;
    }
    return UINT32_MAX;
}

/* ---- batch collect ---- */

uint32_t apg_iter_collect(APG_Iterator *it, uint32_t *buf, uint32_t cap) {
    if (!it || !buf) return 0;
    uint32_t n = 0;
    while (it->cursor < it->limit && n < cap) {
        buf[n++] = it->cursor++;
    }
    return n;
}


/* ---- reverse iterator ---- */

APG_Iterator *apg_iter_create_reverse(const APG_Document *doc, APG_IterKind kind) {
    APG_Iterator *it = apg_iter_create(doc, kind);
    if (it && it->limit > 0) it->cursor = it->limit - 1;
    return it;
}

uint32_t apg_iter_prev(APG_Iterator *it) {
    if (!it || it->cursor == 0) return UINT32_MAX;
    return --it->cursor;
}

/* ---- windowed iteration ---- */

uint32_t apg_iter_window(APG_Iterator *it, uint32_t start, uint32_t count,
                          uint32_t *buf, uint32_t cap) {
    if (!it || !buf) return 0;
    it->cursor = start;
    uint32_t n = 0;
    uint32_t limit = start + count;
    if (limit > it->limit) limit = it->limit;
    while (it->cursor < limit && n < cap) {
        buf[n++] = it->cursor++;
    }
    return n;
}

/* ---- count matching predicate ---- */

uint32_t apg_iter_count_matching(APG_Iterator *it,
                                  int (*pred)(const APG_Document *, uint32_t)) {
    if (!it || !pred) return 0;
    uint32_t saved = it->cursor;
    it->cursor = 0;
    uint32_t count = 0;
    while (it->cursor < it->limit) {
        if (pred(it->doc, it->cursor)) count++;
        it->cursor++;
    }
    it->cursor = saved;
    return count;
}

/* ---- section iterator helpers ---- */

uint32_t apg_iter_sections_of_type(const APG_Document *doc, uint16_t type,
                                    uint32_t *out, uint32_t cap) {
    if (!doc || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->raw_count && n < cap; i++) {
        if (doc->raw_sections[i].type == type) out[n++] = i;
    }
    return n;
}
