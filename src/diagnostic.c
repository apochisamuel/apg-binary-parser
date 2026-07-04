
#include "internal.h"

/*
 * diagnostic.c — parse diagnostics and document health reporting.
 *
 * Tracks parse progress, counts recoverable and fatal errors,
 * and computes a health metric.  Also provides section coverage
 * analysis: which bytes of the input are covered by parsed sections
 * and which are unreferenced gaps.
 */

typedef struct APG_Coverage {
    uint8_t *bitmap;    /* 1 bit per byte of input */
    uint32_t input_len;
    uint32_t covered;
    uint32_t uncovered;
} APG_Coverage;

APG_Coverage *apg_coverage_compute(const APG_Document *doc, uint32_t input_len) {
    if (!doc || !input_len) return NULL;
    APG_Coverage *cov = (APG_Coverage *)calloc(1, sizeof(APG_Coverage));
    if (!cov) return NULL;
    uint32_t bitmap_bytes = (input_len + 7) / 8;
    cov->bitmap = (uint8_t *)calloc(bitmap_bytes, 1);
    if (!cov->bitmap) { free(cov); return NULL; }
    cov->input_len = input_len;
    /* mark header (first 32 bytes) */
    for (uint32_t i = 0; i < 32 && i < input_len; i++)
        cov->bitmap[i / 8] |= (1u << (i % 8));
    /* mark directory entries */
    uint32_t dir_start = doc->header.directory_offset;
    uint32_t dir_end = dir_start + doc->directory_count * 24;
    for (uint32_t i = dir_start; i < dir_end && i < input_len; i++)
        cov->bitmap[i / 8] |= (1u << (i % 8));
    /* mark section payloads */
    for (uint32_t s = 0; s < doc->directory_count; s++) {
        uint32_t off = doc->directory[s].offset;
        uint32_t sz  = doc->directory[s].size;
        for (uint32_t i = off; i < off + sz && i < input_len; i++)
            cov->bitmap[i / 8] |= (1u << (i % 8));
    }
    /* count covered/uncovered */
    for (uint32_t i = 0; i < input_len; i++) {
        if (cov->bitmap[i / 8] & (1u << (i % 8))) cov->covered++;
        else cov->uncovered++;
    }
    return cov;
}

double apg_coverage_ratio(const APG_Coverage *cov) {
    if (!cov || !cov->input_len) return 0.0;
    return (double)cov->covered / (double)cov->input_len;
}

/* find largest uncovered gap */
uint32_t apg_coverage_largest_gap(const APG_Coverage *cov, uint32_t *gap_offset) {
    if (!cov) return 0;
    uint32_t max_gap = 0, cur_gap = 0, cur_start = 0;
    uint32_t best_start = 0;
    for (uint32_t i = 0; i < cov->input_len; i++) {
        if (!(cov->bitmap[i / 8] & (1u << (i % 8)))) {
            if (cur_gap == 0) cur_start = i;
            cur_gap++;
        } else {
            if (cur_gap > max_gap) { max_gap = cur_gap; best_start = cur_start; }
            cur_gap = 0;
        }
    }
    if (cur_gap > max_gap) { max_gap = cur_gap; best_start = cur_start; }
    if (gap_offset) *gap_offset = best_start;
    return max_gap;
}

void apg_coverage_free(APG_Coverage *cov) {
    if (!cov) return;
    free(cov->bitmap);
    free(cov);
}

/* ---- parse health score ---- */

typedef struct APG_Health {
    double score;         /* 0.0 (terrible) to 1.0 (perfect) */
    uint32_t deductions;  /* number of issues found */
    uint32_t critical;    /* number of critical issues */
} APG_Health;

APG_Health apg_health_check(const APG_Document *doc) {
    APG_Health h = {1.0, 0, 0};
    if (!doc) { h.score = 0.0; h.critical = 1; return h; }
    if (doc->ctx.error_code) { h.score -= 0.3; h.deductions++; }
    if (doc->ctx.fatal) { h.score -= 0.5; h.critical++; }
    /* check for dangling references */
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            if (doc->symbols.items[i].name_index >= doc->strings.count) {
                h.score -= 0.01;
                h.deductions++;
            }
        }
    }
    /* check for empty sections */
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        if (doc->raw_sections[i].size == 0) {
            h.score -= 0.02;
            h.deductions++;
        }
    }
    /* warnings */
    h.score -= (double)doc->warning_count * 0.01;
    h.deductions += doc->warning_count;
    if (h.score < 0.0) h.score = 0.0;
    return h;
}

/* ---- section overlap detection ---- */

uint32_t apg_detect_overlaps(const APG_Document *doc) {
    if (!doc || !doc->directory || doc->directory_count < 2) return 0;
    uint32_t n = doc->directory_count;
    uint32_t overlaps = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t a_start = doc->directory[i].offset;
        uint32_t a_end   = a_start + doc->directory[i].size;
        for (uint32_t j = i + 1; j < n; j++) {
            uint32_t b_start = doc->directory[j].offset;
            uint32_t b_end   = b_start + doc->directory[j].size;
            if (a_start < b_end && b_start < a_end) overlaps++;
        }
    }
    return overlaps;
}


/* ---- parse timing estimate ---- */

typedef struct APG_ParseProfile {
    uint32_t header_bytes;
    uint32_t directory_bytes;
    uint32_t string_bytes;
    uint32_t symbol_bytes;
    uint32_t reloc_bytes;
    uint32_t frame_bytes;
    uint32_t other_bytes;
    uint32_t total_bytes;
    double   estimated_parse_weight;
} APG_ParseProfile;

APG_ParseProfile apg_profile_document(const APG_Document *doc) {
    APG_ParseProfile p = {0};
    if (!doc) return p;
    p.header_bytes = 32;
    p.directory_bytes = doc->directory_count * 24;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        switch (rs->type) {
            case APG_SECTION_STRINGS: p.string_bytes += rs->size; break;
            case APG_SECTION_SYMBOLS: p.symbol_bytes += rs->size; break;
            case APG_SECTION_RELOCS:  p.reloc_bytes  += rs->size; break;
            case APG_SECTION_FRAMES:  p.frame_bytes  += rs->size; break;
            default:                  p.other_bytes  += rs->size; break;
        }
    }
    p.total_bytes = p.header_bytes + p.directory_bytes + p.string_bytes +
                    p.symbol_bytes + p.reloc_bytes + p.frame_bytes + p.other_bytes;
    /* weight: strings and relocs are heavier to parse than raw frames */
    p.estimated_parse_weight = (double)p.string_bytes * 2.0 +
                               (double)p.symbol_bytes * 1.5 +
                               (double)p.reloc_bytes * 3.0 +
                               (double)p.frame_bytes * 1.0 +
                               (double)p.other_bytes * 0.5;
    return p;
}

/* ---- document complexity class ---- */

const char *apg_complexity_class(const APG_Document *doc) {
    if (!doc) return "invalid";
    uint32_t score = doc->symbols.count + doc->relocs.count * 2 + doc->streams.count;
    if (score < 10) return "trivial";
    if (score < 100) return "simple";
    if (score < 1000) return "moderate";
    if (score < 10000) return "complex";
    return "very_complex";
}

/* ---- reference graph density ---- */

double apg_reference_density(const APG_Document *doc) {
    if (!doc) return 0.0;
    uint32_t refs = 0;
    uint32_t possible = doc->symbols.count + doc->strings.count + doc->attrs.count;
    if (!possible) return 0.0;
    /* count actual references */
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            if (doc->symbols.items[i].name_ref) refs++;
            if (doc->symbols.items[i].cached_attr) refs++;
        }
    }
    refs += doc->relocs.count;
    return (double)refs / (double)possible;
}
