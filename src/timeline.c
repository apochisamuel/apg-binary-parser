
#include "internal.h"

/*
 * timeline.c — keyframe timeline analysis.
 *
 * Builds a sorted timeline of keyframes ordered by frame_no.
 * Detects temporal gaps (missing frame ranges between keyframes)
 * and computes per-keyframe spacing statistics.
 */

typedef struct APG_TimelineEntry {
    uint32_t keyframe_idx;
    uint32_t frame_no;
    uint32_t marker;
    uint32_t gap_before;   /* frames between this and previous keyframe */
} APG_TimelineEntry;

typedef struct APG_Timeline {
    APG_TimelineEntry *entries;
    uint32_t count;
    uint32_t total_gap;
    uint32_t max_gap;
    uint32_t min_gap;
    double   avg_gap;
} APG_Timeline;

APG_Timeline *apg_timeline_build(const APG_Document *doc) {
    if (!doc || !doc->keyframes.items || !doc->keyframes.count) return NULL;
    uint32_t n = doc->keyframes.count;
    APG_Timeline *tl = (APG_Timeline *)calloc(1, sizeof(APG_Timeline));
    if (!tl) return NULL;
    tl->entries = (APG_TimelineEntry *)calloc(n, sizeof(APG_TimelineEntry));
    if (!tl->entries) { free(tl); return NULL; }
    tl->count = n;
    for (uint32_t i = 0; i < n; i++) {
        tl->entries[i].keyframe_idx = i;
        tl->entries[i].frame_no = doc->keyframes.items[i].frame_no;
        tl->entries[i].marker   = doc->keyframes.items[i].marker;
    }
    /* sort by frame_no */
    for (uint32_t i = 1; i < n; i++) {
        APG_TimelineEntry key = tl->entries[i];
        uint32_t j = i;
        while (j > 0 && tl->entries[j-1].frame_no > key.frame_no) {
            tl->entries[j] = tl->entries[j-1];
            j--;
        }
        tl->entries[j] = key;
    }
    /* compute gaps */
    tl->min_gap = UINT32_MAX;
    tl->max_gap = 0;
    tl->total_gap = 0;
    tl->entries[0].gap_before = 0;
    for (uint32_t i = 1; i < n; i++) {
        uint32_t gap = tl->entries[i].frame_no - tl->entries[i-1].frame_no;
        tl->entries[i].gap_before = gap;
        tl->total_gap += gap;
        if (gap > tl->max_gap) tl->max_gap = gap;
        if (gap < tl->min_gap) tl->min_gap = gap;
    }
    tl->avg_gap = (n > 1) ? (double)tl->total_gap / (double)(n - 1) : 0.0;
    return tl;
}

uint32_t apg_timeline_gap_count(const APG_Timeline *tl, uint32_t threshold) {
    if (!tl) return 0;
    uint32_t count = 0;
    for (uint32_t i = 1; i < tl->count; i++)
        if (tl->entries[i].gap_before > threshold) count++;
    return count;
}

uint32_t apg_timeline_span(const APG_Timeline *tl) {
    if (!tl || !tl->count) return 0;
    return tl->entries[tl->count - 1].frame_no - tl->entries[0].frame_no;
}

void apg_timeline_free(APG_Timeline *tl) {
    if (!tl) return;
    free(tl->entries);
    free(tl);
}


/* ---- keyframe marker histogram ---- */

typedef struct APG_MarkerHist {
    uint32_t marker;
    uint32_t count;
} APG_MarkerHist;

uint32_t apg_timeline_marker_histogram(const APG_Timeline *tl,
                                        APG_MarkerHist *out, uint32_t cap) {
    if (!tl || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < tl->count; i++) {
        uint32_t m = tl->entries[i].marker;
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n; j++) {
            if (out[j].marker == m) { found = j; break; }
        }
        if (found != UINT32_MAX) out[found].count++;
        else if (n < cap) { out[n].marker = m; out[n].count = 1; n++; }
    }
    return n;
}

/* ---- regularity score ---- */

double apg_timeline_regularity(const APG_Timeline *tl) {
    if (!tl || tl->count < 3) return 1.0;
    double mean = tl->avg_gap;
    if (mean < 1e-9) return 1.0;
    double var = 0.0;
    for (uint32_t i = 1; i < tl->count; i++) {
        double d = (double)tl->entries[i].gap_before - mean;
        var += d * d;
    }
    var /= (double)(tl->count - 1);
    double cv = sqrt(var) / mean;
    return 1.0 / (1.0 + cv);
}

/* ---- keyframe density per frame range ---- */

double apg_timeline_density(const APG_Timeline *tl) {
    if (!tl || !tl->count) return 0.0;
    uint32_t span = apg_timeline_span(tl);
    if (!span) return (double)tl->count;
    return (double)tl->count / (double)span;
}


/* ---- keyframe interpolation ---- */

uint32_t apg_timeline_interpolate_marker(const APG_Timeline *tl,
                                          uint32_t frame_no) {
    if (!tl || !tl->count) return 0;
    if (frame_no <= tl->entries[0].frame_no) return tl->entries[0].marker;
    if (frame_no >= tl->entries[tl->count-1].frame_no)
        return tl->entries[tl->count-1].marker;
    for (uint32_t i = 1; i < tl->count; i++) {
        if (tl->entries[i].frame_no >= frame_no) {
            uint32_t da = frame_no - tl->entries[i-1].frame_no;
            uint32_t db = tl->entries[i].frame_no - frame_no;
            return da <= db ? tl->entries[i-1].marker : tl->entries[i].marker;
        }
    }
    return 0;
}

/* ---- find nearest keyframe ---- */

uint32_t apg_timeline_nearest(const APG_Timeline *tl, uint32_t frame_no) {
    if (!tl || !tl->count) return UINT32_MAX;
    uint32_t best = 0, best_dist = UINT32_MAX;
    for (uint32_t i = 0; i < tl->count; i++) {
        uint32_t dist = tl->entries[i].frame_no > frame_no
            ? tl->entries[i].frame_no - frame_no
            : frame_no - tl->entries[i].frame_no;
        if (dist < best_dist) { best_dist = dist; best = i; }
    }
    return best;
}

/* ---- sub-range timeline ---- */

uint32_t apg_timeline_range_count(const APG_Timeline *tl,
                                   uint32_t from_frame, uint32_t to_frame) {
    if (!tl) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < tl->count; i++) {
        if (tl->entries[i].frame_no >= from_frame &&
            tl->entries[i].frame_no <= to_frame) n++;
    }
    return n;
}
