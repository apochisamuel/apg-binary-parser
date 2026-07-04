
#include "internal.h"

int apg_parse_attributes(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_ATTRS);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "attribute table count outside limits");
        return 0;
    }
    doc->attrs.items = (APG_Attr *)calloc(count ? count : 1u, sizeof(APG_Attr));
    if (!doc->attrs.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "attribute allocation failed");
        return 0;
    }
    doc->attrs.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->attrs.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        doc->attrs.items[i].name_index = apg_read_u32(&r);
        doc->attrs.items[i].value = apg_read_u32(&r);
        doc->attrs.items[i].flags = apg_read_u32(&r);
        if (r.failed) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "attribute entry is truncated");
            return 0;
        }
    }
    doc->cache.attrs = &doc->attrs;
    return 1;
}

void apg_free_attrs(APG_AttrTable *tab) {
    if (!tab || !tab->items) return;
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}

void apg_rollback_attr_table(APG_Document *doc) {
    if (!doc || !doc->attrs.items) return;
    apg_free_attrs(&doc->attrs);
    doc->attrs.rolled_back = 1;
}


/* ---- attribute lookup and analysis ---- */

const APG_Attr *apg_attr_find_by_name(const APG_Document *doc, uint32_t name_index) {
    if (!doc || !doc->attrs.items) return NULL;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].name_index == name_index) return &doc->attrs.items[i];
    }
    return NULL;
}

uint32_t apg_attr_count_value(const APG_Document *doc, uint32_t value) {
    if (!doc || !doc->attrs.items) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].value == value) n++;
    }
    return n;
}

uint32_t apg_attr_max_value(const APG_Document *doc) {
    if (!doc || !doc->attrs.items) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].value > mx) mx = doc->attrs.items[i].value;
    }
    return mx;
}

uint32_t apg_attr_min_value(const APG_Document *doc) {
    if (!doc || !doc->attrs.items || !doc->attrs.count) return 0;
    uint32_t mn = UINT32_MAX;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].value < mn) mn = doc->attrs.items[i].value;
    }
    return mn;
}

/* ---- distinct attribute flag values ---- */

uint32_t apg_attr_distinct_flags(const APG_Document *doc) {
    if (!doc || !doc->attrs.items) return 0;
    uint32_t flags[64];
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        uint32_t f = doc->attrs.items[i].flags;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) {
            if (flags[j] == f) { found = 1; break; }
        }
        if (!found && n < 64) flags[n++] = f;
    }
    return n;
}
