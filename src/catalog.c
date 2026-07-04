
#include "internal.h"

/*
 * catalog.c — enriched symbol catalog with grouped iteration.
 *
 * Builds a sorted copy of the symbol table enriched with resolved
 * string data and attribute summaries.  Provides grouped iteration
 * where symbols sharing the same class are returned together.
 */

typedef struct APG_CatalogEntry {
    uint32_t original_index;
    uint16_t klass;
    uint32_t name_hash;
    uint32_t score;
    uint32_t attr_value;
    const char *name;
    uint32_t    name_len;
} APG_CatalogEntry;

struct APG_Catalog {
    APG_CatalogEntry *entries;
    uint32_t count;
    uint32_t cursor;
};

APG_Catalog *apg_catalog_build(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->symbols.count) return NULL;
    APG_Catalog *c = (APG_Catalog *)calloc(1, sizeof(APG_Catalog));
    if (!c) return NULL;
    c->count = doc->symbols.count;
    c->entries = (APG_CatalogEntry *)calloc(c->count, sizeof(APG_CatalogEntry));
    if (!c->entries) { free(c); return NULL; }
    for (uint32_t i = 0; i < c->count; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        APG_CatalogEntry *e = &c->entries[i];
        e->original_index = i;
        e->klass = s->klass;
        e->score = s->derived_score;
        e->name_hash = s->name_ref ? s->name_ref->hash : 0;
        e->name = s->name_ref ? s->name_ref->data : NULL;
        e->name_len = s->name_ref ? s->name_ref->length : 0;
        if (doc->attrs.items && s->attr_index < doc->attrs.count)
            e->attr_value = doc->attrs.items[s->attr_index].value;
    }
    /* sort by (klass, score) */
    for (uint32_t i = 1; i < c->count; i++) {
        APG_CatalogEntry key = c->entries[i];
        uint32_t j = i;
        while (j > 0) {
            APG_CatalogEntry *prev = &c->entries[j-1];
            if (prev->klass < key.klass ||
                (prev->klass == key.klass && prev->score <= key.score)) break;
            c->entries[j] = *prev;
            j--;
        }
        c->entries[j] = key;
    }
    return c;
}

/* iterate: returns next entry, or NULL at end */
const APG_CatalogEntry *apg_catalog_next(APG_Catalog *c) {
    if (!c || c->cursor >= c->count) return NULL;
    return &c->entries[c->cursor++];
}

void apg_catalog_reset(APG_Catalog *c) { if (c) c->cursor = 0; }

/* grouped iteration: get all entries for one class */
uint32_t apg_catalog_group_count(const APG_Catalog *c, uint16_t klass) {
    if (!c) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->count; i++)
        if (c->entries[i].klass == klass) n++;
    return n;
}

uint32_t apg_catalog_unique_classes(const APG_Catalog *c) {
    if (!c || !c->count) return 0;
    uint32_t n = 1;
    for (uint32_t i = 1; i < c->count; i++)
        if (c->entries[i].klass != c->entries[i-1].klass) n++;
    return n;
}

void apg_catalog_free(APG_Catalog *c) {
    if (!c) return;
    free(c->entries);
    free(c);
}


/* ---- catalog search by name prefix ---- */

uint32_t apg_catalog_search_prefix(const APG_Catalog *c, const char *prefix, uint32_t plen,
                                    uint32_t *out, uint32_t cap) {
    if (!c || !prefix || !plen || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->count && n < cap; i++) {
        const APG_CatalogEntry *e = &c->entries[i];
        if (!e->name || e->name_len < plen) continue;
        int match = 1;
        for (uint32_t j = 0; j < plen; j++) {
            if (e->name[j] != prefix[j]) { match = 0; break; }
        }
        if (match) out[n++] = e->original_index;
    }
    return n;
}

/* ---- catalog score range ---- */

uint32_t apg_catalog_score_range(const APG_Catalog *c, uint32_t lo, uint32_t hi,
                                  uint32_t *out, uint32_t cap) {
    if (!c || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->count && n < cap; i++) {
        if (c->entries[i].score >= lo && c->entries[i].score <= hi)
            out[n++] = c->entries[i].original_index;
    }
    return n;
}

/* ---- catalog to sorted name list ---- */

uint32_t apg_catalog_sorted_names(const APG_Catalog *c, const char **out, uint32_t cap) {
    if (!c || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < c->count && n < cap; i++) {
        if (c->entries[i].name) out[n++] = c->entries[i].name;
    }
    return n;
}

/* ---- catalog statistics ---- */

uint32_t apg_catalog_total_score(const APG_Catalog *c) {
    if (!c) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < c->count; i++) total += c->entries[i].score;
    return total;
}

uint32_t apg_catalog_max_score(const APG_Catalog *c) {
    if (!c || !c->count) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < c->count; i++)
        if (c->entries[i].score > mx) mx = c->entries[i].score;
    return mx;
}


/* ---- catalog merge from another document ---- */

uint32_t apg_catalog_merge_count(const APG_Catalog *a, const APG_Catalog *b) {
    if (!a || !b) return 0;
    uint32_t overlap = 0;
    for (uint32_t i = 0; i < a->count; i++) {
        for (uint32_t j = 0; j < b->count; j++) {
            if (a->entries[i].name_hash == b->entries[j].name_hash &&
                a->entries[i].name_len == b->entries[j].name_len) {
                overlap++;
                break;
            }
        }
    }
    return a->count + b->count - overlap;
}

/* ---- catalog class boundaries ---- */

uint32_t apg_catalog_class_start(const APG_Catalog *c, uint16_t klass) {
    if (!c) return UINT32_MAX;
    for (uint32_t i = 0; i < c->count; i++)
        if (c->entries[i].klass == klass) return i;
    return UINT32_MAX;
}

uint32_t apg_catalog_class_end(const APG_Catalog *c, uint16_t klass) {
    if (!c) return UINT32_MAX;
    uint32_t last = UINT32_MAX;
    for (uint32_t i = 0; i < c->count; i++)
        if (c->entries[i].klass == klass) last = i;
    return last;
}
