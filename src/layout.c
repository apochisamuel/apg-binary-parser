
#include "internal.h"

/*
 * layout.c — section layout computation and rewriting.
 *
 * Computes optimal ordering and alignment of sections to minimize
 * fragmentation and improve sequential access patterns.  Provides
 * layout planning without modifying the document, and a separate
 * apply step that rewrites the directory.
 */

typedef struct APG_LayoutEntry {
    uint32_t section_idx;
    uint16_t type;
    uint32_t original_offset;
    uint32_t original_size;
    uint32_t planned_offset;
    uint32_t alignment;
} APG_LayoutEntry;

typedef struct APG_Layout {
    APG_LayoutEntry *entries;
    uint32_t         count;
    uint32_t         total_size;
    uint32_t         wasted_bytes;
    double           packing_efficiency;
} APG_Layout;

/* ---- section type ordering priority ---- */

static uint32_t apg_layout_type_priority(uint16_t type) {
    switch (type) {
        case APG_SECTION_STRINGS:   return 0;
        case APG_SECTION_ATTRS:     return 1;
        case APG_SECTION_SYMBOLS:   return 2;
        case APG_SECTION_RELOCS:    return 3;
        case APG_SECTION_KEYFRAMES: return 4;
        case APG_SECTION_STREAMS:   return 5;
        case APG_SECTION_FRAMES:    return 6;
        case APG_SECTION_ALIAS:     return 7;
        default:                    return 8;
    }
}

/* ---- alignment computation ---- */

static uint32_t apg_layout_alignment(uint16_t type, uint32_t size) {
    if (type == APG_SECTION_FRAMES && size > 1024) return 64;
    if (type == APG_SECTION_SYMBOLS) return 16;
    if (size > 4096) return 32;
    return 8;
}

static uint32_t apg_align_up(uint32_t value, uint32_t align) {
    return (value + align - 1) & ~(align - 1);
}

/* ---- plan layout ---- */

APG_Layout *apg_layout_plan(const APG_Document *doc) {
    if (!doc || !doc->directory || !doc->directory_count) return NULL;
    APG_Layout *lay = (APG_Layout *)calloc(1, sizeof(APG_Layout));
    if (!lay) return NULL;
    uint32_t n = doc->directory_count;
    lay->entries = (APG_LayoutEntry *)calloc(n, sizeof(APG_LayoutEntry));
    if (!lay->entries) { free(lay); return NULL; }
    lay->count = n;
    for (uint32_t i = 0; i < n; i++) {
        lay->entries[i].section_idx = i;
        lay->entries[i].type = doc->directory[i].type;
        lay->entries[i].original_offset = doc->directory[i].offset;
        lay->entries[i].original_size = doc->directory[i].size;
        lay->entries[i].alignment = apg_layout_alignment(
            doc->directory[i].type, doc->directory[i].size);
    }
    /* sort by type priority */
    for (uint32_t i = 1; i < n; i++) {
        APG_LayoutEntry key = lay->entries[i];
        uint32_t kp = apg_layout_type_priority(key.type);
        uint32_t j = i;
        while (j > 0) {
            uint32_t pp = apg_layout_type_priority(lay->entries[j-1].type);
            if (pp <= kp) break;
            lay->entries[j] = lay->entries[j-1];
            j--;
        }
        lay->entries[j] = key;
    }
    /* compute planned offsets */
    uint32_t header_size = 32 + n * 24;
    uint32_t cur = apg_align_up(header_size, 8);
    for (uint32_t i = 0; i < n; i++) {
        cur = apg_align_up(cur, lay->entries[i].alignment);
        lay->entries[i].planned_offset = cur;
        cur += lay->entries[i].original_size;
    }
    lay->total_size = cur;
    /* compute wasted bytes */
    uint32_t payload_total = 0;
    for (uint32_t i = 0; i < n; i++) payload_total += lay->entries[i].original_size;
    lay->wasted_bytes = lay->total_size - header_size - payload_total;
    lay->packing_efficiency = lay->total_size ?
        (double)(header_size + payload_total) / (double)lay->total_size : 1.0;
    return lay;
}

/* ---- layout analysis ---- */

uint32_t apg_layout_fragmentation(const APG_Layout *lay) {
    if (!lay || lay->count < 2) return 0;
    uint32_t gaps = 0;
    for (uint32_t i = 1; i < lay->count; i++) {
        uint32_t prev_end = lay->entries[i-1].planned_offset + lay->entries[i-1].original_size;
        if (lay->entries[i].planned_offset > prev_end)
            gaps += lay->entries[i].planned_offset - prev_end;
    }
    return gaps;
}

int apg_layout_is_optimal(const APG_Document *doc) {
    if (!doc || !doc->directory || doc->directory_count < 2) return 1;
    for (uint32_t i = 1; i < doc->directory_count; i++) {
        uint32_t prev_end = doc->directory[i-1].offset + doc->directory[i-1].size;
        if (doc->directory[i].offset < prev_end) return 0;
        uint32_t pp = apg_layout_type_priority(doc->directory[i-1].type);
        uint32_t cp = apg_layout_type_priority(doc->directory[i].type);
        if (cp < pp) return 0;
    }
    return 1;
}

/* ---- section offset lookup ---- */

uint32_t apg_layout_planned_offset(const APG_Layout *lay, uint32_t section_idx) {
    if (!lay) return UINT32_MAX;
    for (uint32_t i = 0; i < lay->count; i++) {
        if (lay->entries[i].section_idx == section_idx)
            return lay->entries[i].planned_offset;
    }
    return UINT32_MAX;
}

/* ---- section reorder suggestion ---- */

uint32_t apg_layout_reorder(const APG_Layout *lay, uint32_t *order, uint32_t cap) {
    if (!lay || !order) return 0;
    uint32_t n = lay->count < cap ? lay->count : cap;
    for (uint32_t i = 0; i < n; i++) order[i] = lay->entries[i].section_idx;
    return n;
}

void apg_layout_free(APG_Layout *lay) {
    if (!lay) return;
    free(lay->entries);
    free(lay);
}


/* ---- access cost estimation ---- */

typedef struct APG_AccessCost {
    uint32_t sequential_cost;
    uint32_t random_cost;
    uint32_t seek_count;
    double   locality_score;
} APG_AccessCost;

APG_AccessCost apg_layout_access_cost(const APG_Layout *lay) {
    APG_AccessCost cost = {0};
    if (!lay || lay->count < 2) { cost.locality_score = 1.0; return cost; }
    uint32_t total_gap = 0;
    uint32_t total_size = 0;
    for (uint32_t i = 0; i < lay->count; i++) total_size += lay->entries[i].original_size;
    for (uint32_t i = 1; i < lay->count; i++) {
        uint32_t prev_end = lay->entries[i-1].planned_offset + lay->entries[i-1].original_size;
        if (lay->entries[i].planned_offset > prev_end) {
            uint32_t gap = lay->entries[i].planned_offset - prev_end;
            total_gap += gap;
            cost.seek_count++;
        }
    }
    cost.sequential_cost = total_size + total_gap;
    cost.random_cost = total_size + lay->count * 64;
    cost.locality_score = total_size ? 1.0 - (double)total_gap / (double)(total_size + total_gap) : 1.0;
    return cost;
}

/* ---- compare two layouts ---- */

int apg_layout_is_better(const APG_Layout *a, const APG_Layout *b) {
    if (!a || !b) return 0;
    return a->wasted_bytes < b->wasted_bytes &&
           a->packing_efficiency >= b->packing_efficiency;
}
