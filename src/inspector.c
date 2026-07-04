
#include "internal.h"

/*
 * inspector.c — high-level document inspection routines.
 *
 * Provides summary statistics, structural health checks, and a
 * compact fingerprint for quick document identification.
 * Used by CLI tools and automated validation pipelines.
 */

typedef struct APG_InspectResult {
    /* counts */
    uint32_t section_count;
    uint32_t symbol_count;
    uint32_t string_count;
    uint32_t attr_count;
    uint32_t reloc_count;
    uint32_t frame_count;
    uint32_t stream_count;
    uint32_t keyframe_count;
    uint32_t alias_count;
    /* sizes */
    uint32_t total_payload_bytes;
    uint32_t largest_section_bytes;
    uint32_t smallest_section_bytes;
    uint32_t total_string_bytes;
    uint32_t total_frame_bytes;
    /* health */
    uint32_t warning_count;
    uint32_t dangling_name_refs;
    uint32_t dangling_attr_refs;
    uint32_t zero_length_strings;
    uint32_t empty_frames;
    uint32_t unresolved_relocs;
    /* fingerprint */
    uint32_t content_hash;
    uint32_t structure_hash;
} APG_InspectResult;

APG_InspectResult *apg_inspect(const APG_Document *doc) {
    if (!doc) return NULL;
    APG_InspectResult *r = (APG_InspectResult *)calloc(1, sizeof(APG_InspectResult));
    if (!r) return NULL;

    r->section_count  = doc->raw_count;
    r->symbol_count   = doc->symbols.count;
    r->string_count   = doc->strings.count;
    r->attr_count     = doc->attrs.count;
    r->reloc_count    = doc->relocs.count;
    r->frame_count    = doc->frames.count;
    r->stream_count   = doc->streams.count;
    r->keyframe_count = doc->keyframes.count;
    r->alias_count    = doc->aliases.count;
    r->warning_count  = doc->warning_count;

    /* section sizes */
    r->smallest_section_bytes = UINT32_MAX;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        uint32_t sz = doc->raw_sections[i].size;
        r->total_payload_bytes += sz;
        if (sz > r->largest_section_bytes)  r->largest_section_bytes = sz;
        if (sz < r->smallest_section_bytes) r->smallest_section_bytes = sz;
    }
    if (!doc->raw_count) r->smallest_section_bytes = 0;

    /* string stats */
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (s->data) r->total_string_bytes += s->length;
        else r->zero_length_strings++;
        if (s->length == 0) r->zero_length_strings++;
    }

    /* frame stats */
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        r->total_frame_bytes += doc->frames.items[i].payload_len;
        if (doc->frames.items[i].payload_len == 0) r->empty_frames++;
    }

    /* dangling reference check */
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            if (doc->symbols.items[i].name_index >= doc->strings.count)
                r->dangling_name_refs++;
            if (doc->attrs.items && doc->symbols.items[i].attr_index >= doc->attrs.count)
                r->dangling_attr_refs++;
        }
    }

    /* unresolved relocs */
    if (doc->relocs.items) {
        for (uint32_t i = 0; i < doc->relocs.count; i++) {
            if (doc->relocs.items[i].resolved_hash == 0) r->unresolved_relocs++;
        }
    }

    /* fingerprint hashes */
    uint32_t ch = doc->header.magic;
    ch = apg_mix_u32(ch, doc->header.flags);
    ch = apg_mix_u32(ch, doc->summary_hash);
    for (uint32_t i = 0; i < doc->raw_count; i++)
        ch = apg_mix_u32(ch, doc->raw_sections[i].size ^ doc->raw_sections[i].type);
    r->content_hash = ch;

    uint32_t sh = doc->directory_count;
    sh = apg_mix_u32(sh, doc->symbols.count << 16 | doc->strings.count);
    sh = apg_mix_u32(sh, doc->relocs.count << 8 | doc->frames.count);
    sh = apg_mix_u32(sh, doc->streams.count << 4 | doc->keyframes.count);
    r->structure_hash = sh;

    return r;
}

int apg_inspect_is_healthy(const APG_InspectResult *r) {
    if (!r) return 0;
    return r->dangling_name_refs == 0 &&
           r->dangling_attr_refs == 0 &&
           r->unresolved_relocs == 0 &&
           r->warning_count == 0;
}

uint32_t apg_inspect_complexity_score(const APG_InspectResult *r) {
    if (!r) return 0;
    uint32_t score = 0;
    score += r->symbol_count * 3;
    score += r->reloc_count * 5;
    score += r->stream_count * 4;
    score += r->section_count * 2;
    score += r->total_payload_bytes / 256;
    return score;
}

void apg_inspect_free(APG_InspectResult *r) { free(r); }


/* ---- section balance analysis ---- */

typedef struct APG_BalanceReport {
    uint32_t total_sections;
    uint32_t data_sections;
    uint32_t metadata_sections;
    double   data_ratio;
    double   largest_to_avg;
} APG_BalanceReport;

APG_BalanceReport apg_inspect_balance(const APG_Document *doc) {
    APG_BalanceReport r = {0};
    if (!doc || !doc->raw_count) return r;
    r.total_sections = doc->raw_count;
    uint32_t total = 0, largest = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        total += rs->size;
        if (rs->size > largest) largest = rs->size;
        if (rs->type == APG_SECTION_FRAMES || rs->type == APG_SECTION_STREAMS)
            r.data_sections++;
        else
            r.metadata_sections++;
    }
    r.data_ratio = r.total_sections ? (double)r.data_sections / (double)r.total_sections : 0.0;
    double avg = (double)total / (double)doc->raw_count;
    r.largest_to_avg = avg > 0 ? (double)largest / avg : 0.0;
    return r;
}

/* ---- symbol connectivity ---- */

uint32_t apg_inspect_connected_symbols(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->relocs.items) return 0;
    uint8_t *connected = (uint8_t *)calloc(doc->symbols.count, 1);
    if (!connected) return 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].symbol_index;
        if (si < doc->symbols.count) connected[si] = 1;
    }
    uint32_t count = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        if (connected[i]) count++;
    free(connected);
    return count;
}

/* ---- duplicate symbol detection ---- */

uint32_t apg_inspect_duplicate_symbols(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || doc->symbols.count < 2) return 0;
    uint32_t dupes = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_String *a = doc->symbols.items[i].name_ref;
        if (!a || !a->data) continue;
        for (uint32_t j = i + 1; j < doc->symbols.count; j++) {
            APG_String *b = doc->symbols.items[j].name_ref;
            if (!b || !b->data || a->length != b->length || a->hash != b->hash) continue;
            int eq = 1;
            for (uint32_t k = 0; k < a->length; k++)
                if (a->data[k] != b->data[k]) { eq = 0; break; }
            if (eq) { dupes++; break; }
        }
    }
    return dupes;
}
