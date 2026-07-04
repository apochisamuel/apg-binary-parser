
#include "internal.h"

void apg_cache_borrow_alias_view(APG_Document *doc, uint8_t *bytes, uint32_t len) {
    if (!doc || !bytes || !len) return;
    APG_Cache *c = &doc->cache;
    if (c->alias_view_count == c->alias_view_cap) {
        uint32_t next = c->alias_view_cap ? c->alias_view_cap * 2u : 4u;
        uint8_t **vp = (uint8_t **)realloc(c->alias_views, (size_t)next * sizeof(uint8_t *));
        uint32_t *vl = (uint32_t *)realloc(c->alias_view_lens, (size_t)next * sizeof(uint32_t));
        if (!vp || !vl) { free(vp); return; }
        c->alias_views = vp;
        c->alias_view_lens = vl;
        c->alias_view_cap = next;
    }
    c->alias_views[c->alias_view_count] = bytes;
    c->alias_view_lens[c->alias_view_count] = len;
    c->alias_view_count++;
}

static int apg_cache_reserve_names(APG_Cache *cache, uint32_t count) {
    if (!cache) return 0;
    if (!count) count = 1;
    cache->name_index = (APG_String **)calloc(count, sizeof(APG_String *));
    if (!cache->name_index) return 0;
    cache->name_count = count;
    return 1;
}

uint32_t apg_cache_build_name_index(APG_Document *doc) {
    if (!doc) return 0;
    APG_StringTable *strings = doc->cache.primary_strings;
    if (!strings || !strings->items) return 0;
    if (!apg_cache_reserve_names(&doc->cache, strings->count)) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "name index allocation failed");
        return 0;
    }
    uint32_t h = 0;
    for (uint32_t i = 0; i < strings->count; i++) {
        APG_String *s = &strings->items[i];
        doc->cache.name_index[i] = s;
        if (s->data) h = apg_mix_u32(h, s->hash ^ apg_score_name(s->data, s->length));
    }
    doc->cache.combined_hash = apg_mix_u32(doc->cache.combined_hash, h);
    return h;
}

int apg_build_cache(APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = apg_cache_build_name_index(doc);
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) h = apg_mix_u32(h, doc->symbols.items[i].derived_score);
    }
    if (doc->frames.items) {
        for (uint32_t i = 0; i < doc->frames.count; i++) h = apg_mix_u32(h, doc->frames.items[i].checksum);
    }
    if (doc->cache.alias_views) {
        for (uint32_t i = 0; i < doc->cache.alias_view_count; i++) {
            if (doc->cache.alias_views[i]) {
                h = apg_mix_u32(h, apg_hash_bytes(doc->cache.alias_views[i],
                                                   doc->cache.alias_view_lens[i]));
            }
        }
    }
    doc->cache.integrity_score = h;
    doc->summary_hash = apg_mix_u32(doc->summary_hash, h);
    return 1;
}

void apg_free_cache(APG_Document *doc) {
    if (!doc) return;
    free(doc->cache.name_index);
    doc->cache.name_index = NULL;
    doc->cache.name_count = 0;
    for (uint32_t i = 0; i < doc->cache.owned_alias_count; i++) {
        APG_AliasBlob *blob = doc->cache.owned_aliases[i];
        if (blob) {
            free(blob->bytes);
            free(blob);
        }
    }
    free(doc->cache.owned_aliases);
    doc->cache.owned_aliases = NULL;
    doc->cache.owned_alias_count = 0;
    doc->cache.owned_alias_capacity = 0;
    free(doc->cache.alias_views);
    free(doc->cache.alias_view_lens);
    doc->cache.alias_views = NULL;
    doc->cache.alias_view_lens = NULL;
    doc->cache.alias_view_count = 0;
    doc->cache.alias_view_cap = 0;
}
