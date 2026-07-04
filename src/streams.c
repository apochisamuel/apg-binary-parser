
#include "internal.h"

static APG_String *apg_stream_label(APG_Document *doc, uint32_t idx) {
    if (!doc || !doc->strings.items || idx >= doc->strings.count) return NULL;
    return &doc->strings.items[idx];
}

int apg_parse_keyframes(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_KEYFRAMES);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "keyframe count outside limits");
        return 0;
    }
    doc->keyframes.items = (APG_Keyframe *)calloc(count ? count : 1u, sizeof(APG_Keyframe));
    if (!doc->keyframes.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "keyframe allocation failed");
        return 0;
    }
    doc->keyframes.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->keyframes.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        doc->keyframes.items[i].frame_no = apg_read_u32(&r);
        doc->keyframes.items[i].name_index = apg_read_u32(&r);
        doc->keyframes.items[i].marker = apg_read_u32(&r);
        if (r.failed) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "keyframe entry is truncated");
            return 0;
        }
        doc->keyframes.items[i].label = apg_stream_label(doc, doc->keyframes.items[i].name_index);
    }
    return 1;
}

int apg_parse_streams(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_STREAMS);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "stream count outside limits");
        return 0;
    }
    doc->streams.items = (APG_Stream *)calloc(count ? count : 1u, sizeof(APG_Stream));
    if (!doc->streams.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "stream allocation failed");
        return 0;
    }
    doc->streams.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->streams.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        APG_Stream *s = &doc->streams.items[i];
        s->id = apg_read_u32(&r);
        s->key_index = apg_read_u32(&r);
        s->event_count = apg_read_u32(&r);
        s->flags = apg_read_u32(&r);
        if (r.failed) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "stream entry is truncated");
            return 0;
        }
        if (doc->keyframes.items && s->key_index < doc->keyframes.count) s->key_cache = &doc->keyframes.items[s->key_index];
    }
    return 1;
}

uint32_t apg_materialize_streams(APG_Document *doc) {
    if (!doc || !doc->streams.items) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        APG_Stream *s = &doc->streams.items[i];
        uint32_t label_hash = 0;
        if (s->key_cache && s->key_cache->label && s->key_cache->label->data) {
            label_hash = s->key_cache->label->hash;
        }
        s->materialized_score = apg_mix_u32(s->id, s->key_cache ? s->key_cache->marker : 0u) ^ label_hash;
        total = apg_mix_u32(total, s->materialized_score + s->event_count);
    }
    return total;
}

void apg_rollback_keyframes(APG_Document *doc) {
    if (!doc || !doc->keyframes.items) return;
    apg_free_keyframes(&doc->keyframes);
    doc->keyframes.rolled_back = 1;
}

void apg_free_keyframes(APG_KeyframeTable *tab) {
    if (!tab || !tab->items) return;
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}

void apg_free_streams(APG_StreamTable *tab) {
    if (!tab || !tab->items) return;
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}


/* ---- stream analysis utilities ---- */

uint32_t apg_stream_total_events(const APG_Document *doc) {
    if (!doc || !doc->streams.items) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->streams.count; i++)
        total += doc->streams.items[i].event_count;
    return total;
}

uint32_t apg_stream_max_events(const APG_Document *doc) {
    if (!doc || !doc->streams.items) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->streams.count; i++)
        if (doc->streams.items[i].event_count > mx) mx = doc->streams.items[i].event_count;
    return mx;
}

const APG_Stream *apg_stream_find_by_id(const APG_Document *doc, uint32_t id) {
    if (!doc || !doc->streams.items) return NULL;
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        if (doc->streams.items[i].id == id) return &doc->streams.items[i];
    }
    return NULL;
}

uint32_t apg_stream_distinct_ids(const APG_Document *doc) {
    if (!doc || !doc->streams.items) return 0;
    uint32_t ids[256];
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        uint32_t id = doc->streams.items[i].id;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) if (ids[j] == id) { found = 1; break; }
        if (!found && n < 256) ids[n++] = id;
    }
    return n;
}

uint32_t apg_stream_events_per_key(const APG_Document *doc) {
    if (!doc || !doc->streams.items || !doc->keyframes.count) return 0;
    uint32_t total = apg_stream_total_events(doc);
    return total / doc->keyframes.count;
}
