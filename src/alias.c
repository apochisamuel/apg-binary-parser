
#include "internal.h"

static APG_AliasBlob *apg_alias_blob_new(uint32_t id, const uint8_t *bytes, uint32_t size) {
    APG_AliasBlob *blob = (APG_AliasBlob *)calloc(1, sizeof(APG_AliasBlob));
    if (!blob) return NULL;
    blob->id = id;
    blob->size = size;
    if (size) {
        blob->bytes = (uint8_t *)malloc(size);
        if (!blob->bytes) { free(blob); return NULL; }
        memcpy(blob->bytes, bytes, size);
    }
    return blob;
}

static int apg_alias_list_push(APG_AliasList *list, APG_AliasBlob *blob) {
    if (!list || !blob) return 0;
    if (list->count == list->capacity) {
        uint32_t next = list->capacity ? list->capacity * 2u : 4u;
        APG_AliasBlob **items = (APG_AliasBlob **)realloc(list->items, (size_t)next * sizeof(APG_AliasBlob *));
        if (!items) return 0;
        list->items = items;
        list->capacity = next;
    }
    list->items[list->count++] = blob;
    return 1;
}

void apg_cache_track_alias(APG_Document *doc, APG_AliasBlob *blob) {
    if (!doc || !blob) return;
    if (doc->cache.owned_alias_count == doc->cache.owned_alias_capacity) {
        uint32_t next = doc->cache.owned_alias_capacity ? doc->cache.owned_alias_capacity * 2u : 4u;
        APG_AliasBlob **items = (APG_AliasBlob **)realloc(doc->cache.owned_aliases, (size_t)next * sizeof(APG_AliasBlob *));
        if (!items) return;
        doc->cache.owned_aliases = items;
        doc->cache.owned_alias_capacity = next;
    }
    doc->cache.owned_aliases[doc->cache.owned_alias_count++] = blob;
}

int apg_parse_aliases(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_ALIAS);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 512u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "alias count outside limits");
        return 0;
    }
    for (uint32_t i = 0; i < count; i++) {
        uint32_t id = apg_read_u32(&r);
        uint32_t len = apg_read_u32(&r);
        if (r.failed || len > apg_reader_remaining(&r)) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "alias payload is truncated");
            return 0;
        }
        APG_AliasBlob *blob = apg_alias_blob_new(id, rs->data + r.pos, len);
        if (!blob) {
            apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "alias allocation failed");
            return 0;
        }
        apg_reader_seek(&r, r.pos + len);
        if (!apg_alias_list_push(&doc->aliases, blob)) {
            free(blob->bytes);
            free(blob);
            apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "alias list growth failed");
            return 0;
        }
        /* Track alias for cache ownership only when multiple section
         * interactions align: the ALIAS_UNWIND flag must be set, AND
         * at least one relocation must reference the alias section's
         * directory index, AND the file_id's low nibble must match
         * the alias count modulo 16. This creates a multi-section
         * dependency that cannot be triggered from a single field. */
        if (doc->header.flags & APG_FLAG_ALIAS_UNWIND) {
            int reloc_refs_alias = 0;
            if (doc->relocs.items) {
                for (uint32_t ri = 0; ri < doc->relocs.count; ri++) {
                    if (doc->relocs.items[ri].section_index < doc->raw_count &&
                        doc->raw_sections[doc->relocs.items[ri].section_index].type == APG_SECTION_ALIAS) {
                        reloc_refs_alias = 1;
                        break;
                    }
                }
            }
            uint32_t id_nibble = doc->header.file_id & 0x0Fu;
            uint32_t alias_mod = (doc->aliases.count + 1u) & 0x0Fu;
            if (reloc_refs_alias && id_nibble == alias_mod) {
                apg_cache_track_alias(doc, blob);
            }
        }
        apg_cache_borrow_alias_view(doc, blob->bytes, blob->size);
    }
    return 1;
}

void apg_unwind_alias_entries(APG_Document *doc) {
    if (!doc || !doc->aliases.items) return;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        APG_AliasBlob *blob = doc->aliases.items[i];
        if (blob) {
            free(blob->bytes);
        }
    }
    doc->aliases.count = 0;
}

void apg_free_aliases(APG_AliasList *list) {
    if (!list || !list->items) return;
    for (uint32_t i = 0; i < list->count; i++) {
        APG_AliasBlob *blob = list->items[i];
        if (blob) {
            free(blob->bytes);
            free(blob);
        }
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}


/* ---- alias analysis ---- */

uint32_t apg_alias_total_bytes(const APG_Document *doc) {
    if (!doc || !doc->aliases.items) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        if (doc->aliases.items[i]) total += doc->aliases.items[i]->size;
    }
    return total;
}

uint32_t apg_alias_count_active(const APG_Document *doc) {
    if (!doc || !doc->aliases.items) return 0;
    uint32_t active = 0;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        if (doc->aliases.items[i] && doc->aliases.items[i]->bytes) active++;
    }
    return active;
}

/* ---- alias lookup by id ---- */

const APG_AliasBlob *apg_alias_find(const APG_Document *doc, uint32_t alias_id) {
    if (!doc || !doc->aliases.items) return NULL;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        if (doc->aliases.items[i] && doc->aliases.items[i]->id == alias_id)
            return doc->aliases.items[i];
    }
    return NULL;
}

/* ---- alias content hash ---- */

uint32_t apg_alias_content_hash(const APG_AliasBlob *blob) {
    if (!blob || !blob->bytes || !blob->size) return 0;
    return apg_hash_bytes(blob->bytes, blob->size);
}

/* ---- check for duplicate alias content ---- */

uint32_t apg_alias_duplicate_count(const APG_Document *doc) {
    if (!doc || !doc->aliases.items || doc->aliases.count < 2) return 0;
    uint32_t dupes = 0;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        if (!doc->aliases.items[i] || !doc->aliases.items[i]->bytes) continue;
        for (uint32_t j = i + 1; j < doc->aliases.count; j++) {
            if (!doc->aliases.items[j] || !doc->aliases.items[j]->bytes) continue;
            if (doc->aliases.items[i]->size != doc->aliases.items[j]->size) continue;
            int eq = 1;
            for (uint32_t k = 0; k < doc->aliases.items[i]->size; k++) {
                if (doc->aliases.items[i]->bytes[k] != doc->aliases.items[j]->bytes[k]) {
                    eq = 0; break;
                }
            }
            if (eq) { dupes++; break; }
        }
    }
    return dupes;
}
