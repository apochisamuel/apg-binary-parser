
#include "internal.h"

static int apg_parse_one_string_table(APG_Document *doc, APG_RawSection *rs) {
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "string table count outside limits");
        return 0;
    }
    doc->strings.items = (APG_String *)calloc(count ? count : 1u, sizeof(APG_String));
    if (!doc->strings.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "string table allocation failed");
        return 0;
    }
    doc->strings.count = count;
    doc->strings.directory_index = UINT32_MAX;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        if (&doc->raw_sections[i] == rs) doc->strings.directory_index = i;
    }
    for (uint32_t i = 0; i < count; i++) {
        uint16_t len = apg_read_u16(&r);
        if (r.failed || len > apg_reader_remaining(&r)) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "string entry is truncated");
            return 0;
        }
        doc->strings.items[i].data = (char *)malloc((size_t)len + 1u);
        if (!doc->strings.items[i].data) {
            apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "string allocation failed");
            return 0;
        }
        if (!apg_read_bytes(&r, (uint8_t *)doc->strings.items[i].data, len)) return 0;
        doc->strings.items[i].data[len] = '\0';
        doc->strings.items[i].length = len;
        doc->strings.items[i].hash = apg_hash_bytes((const uint8_t *)doc->strings.items[i].data, len);
    }
    doc->cache.primary_strings = &doc->strings;
    return 1;
}

int apg_load_string_tables(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_STRINGS);
    if (!rs) return 1;
    return apg_parse_one_string_table(doc, rs);
}

void apg_free_strings(APG_StringTable *tab) {
    if (!tab || !tab->items) return;
    for (uint32_t i = 0; i < tab->count; i++) {
        free(tab->items[i].data);
        tab->items[i].data = NULL;
    }
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}

const char *apg_document_string(const APG_Document *doc, uint32_t index) {
    if (!doc || !doc->strings.items || index >= doc->strings.count) return NULL;
    return doc->strings.items[index].data;
}

void apg_rollback_string_table(APG_Document *doc) {
    if (!doc || !doc->strings.items) return;
    APG_String *items = doc->strings.items;
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        free(items[i].data);
        items[i].data = NULL;
    }
    free(items);
    doc->strings.rolled_back = 1;
}


/* ---- string utility functions ---- */

int apg_string_starts_with(const APG_String *s, const char *prefix, uint32_t plen) {
    if (!s || !s->data || !prefix || s->length < plen) return 0;
    for (uint32_t i = 0; i < plen; i++)
        if (s->data[i] != prefix[i]) return 0;
    return 1;
}

int apg_string_ends_with(const APG_String *s, const char *suffix, uint32_t slen) {
    if (!s || !s->data || !suffix || s->length < slen) return 0;
    uint32_t offset = s->length - slen;
    for (uint32_t i = 0; i < slen; i++)
        if (s->data[offset + i] != suffix[i]) return 0;
    return 1;
}

int apg_string_contains(const APG_String *s, const char *needle, uint32_t nlen) {
    if (!s || !s->data || !needle || s->length < nlen) return 0;
    for (uint32_t i = 0; i + nlen <= s->length; i++) {
        uint32_t j = 0;
        while (j < nlen && s->data[i + j] == needle[j]) j++;
        if (j == nlen) return 1;
    }
    return 0;
}

uint32_t apg_string_find(const APG_String *s, const char *needle, uint32_t nlen) {
    if (!s || !s->data || !needle || s->length < nlen) return UINT32_MAX;
    for (uint32_t i = 0; i + nlen <= s->length; i++) {
        uint32_t j = 0;
        while (j < nlen && s->data[i + j] == needle[j]) j++;
        if (j == nlen) return i;
    }
    return UINT32_MAX;
}

/* ---- string pool analysis ---- */

uint32_t apg_strings_total_bytes(const APG_Document *doc) {
    if (!doc || !doc->strings.items) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        if (doc->strings.items[i].data) total += doc->strings.items[i].length;
    }
    return total;
}

uint32_t apg_strings_unique_hash_count(const APG_Document *doc) {
    if (!doc || !doc->strings.items || doc->strings.count == 0) return 0;
    uint32_t *hashes = (uint32_t *)calloc(doc->strings.count, sizeof(uint32_t));
    if (!hashes) return 0;
    for (uint32_t i = 0; i < doc->strings.count; i++)
        hashes[i] = doc->strings.items[i].hash;
    /* sort */
    for (uint32_t i = 1; i < doc->strings.count; i++) {
        uint32_t key = hashes[i], j = i;
        while (j > 0 && hashes[j-1] > key) { hashes[j] = hashes[j-1]; j--; }
        hashes[j] = key;
    }
    uint32_t unique = 1;
    for (uint32_t i = 1; i < doc->strings.count; i++) {
        if (hashes[i] != hashes[i-1]) unique++;
    }
    free(hashes);
    return unique;
}
