
#include "internal.h"
#include <math.h>

/*
 * analysis.c — statistical analysis of document content.
 *
 * apg_entropy()          — Shannon entropy of a byte buffer (bits/byte)
 * apg_section_entropy()  — entropy of a specific raw section
 * apg_class_histogram()  — distribution of symbol klass values
 * apg_fragmentation()    — measure section fragmentation
 * apg_symbol_density()   — symbols per kilobyte of section data
 */

/* ---- Shannon entropy ---- */
double apg_entropy(const uint8_t *data, uint32_t len) {
    if (!data || !len) return 0.0;
    uint32_t freq[256] = {0};
    for (uint32_t i = 0; i < len; i++) freq[data[i]]++;
    double ent = 0.0;
    double inv = 1.0 / (double)len;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] * inv;
        ent -= p * log2(p);
    }
    return ent;
}

double apg_section_entropy(const APG_Document *doc, uint32_t section_idx) {
    if (!doc || section_idx >= doc->raw_count) return 0.0;
    APG_RawSection *rs = &doc->raw_sections[section_idx];
    if (!rs->data || !rs->size) return 0.0;
    return apg_entropy(rs->data, rs->size);
}

/* ---- symbol class histogram ---- */
typedef struct APG_ClassHistEntry {
    uint16_t klass;
    uint32_t count;
} APG_ClassHistEntry;

uint32_t apg_class_histogram(const APG_Document *doc,
                             APG_ClassHistEntry *out, uint32_t out_cap) {
    if (!doc || !doc->symbols.items || !out || !out_cap) return 0;
    uint32_t n_classes = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        uint16_t k = doc->symbols.items[i].klass;
        /* find or insert */
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n_classes; j++) {
            if (out[j].klass == k) { found = j; break; }
        }
        if (found != UINT32_MAX) {
            out[found].count++;
        } else if (n_classes < out_cap) {
            out[n_classes].klass = k;
            out[n_classes].count = 1;
            n_classes++;
        }
    }
    /* sort by count descending */
    for (uint32_t i = 1; i < n_classes; i++) {
        uint32_t j = i;
        while (j > 0 && out[j].count > out[j-1].count) {
            APG_ClassHistEntry tmp = out[j]; out[j] = out[j-1]; out[j-1] = tmp;
            j--;
        }
    }
    return n_classes;
}

/* ---- fragmentation index ---- */
/*
 * Measures how fragmented sections are by computing the ratio of
 * gaps between directory entries to total address space.
 * Returns 0.0 (perfectly packed) to 1.0 (maximally fragmented).
 */
double apg_fragmentation(const APG_Document *doc) {
    if (!doc || !doc->directory || doc->directory_count < 2) return 0.0;
    uint32_t n = doc->directory_count;
    /* sort entries by offset (copy to avoid mutating) */
    uint32_t *offs = (uint32_t *)calloc(n, sizeof(uint32_t));
    uint32_t *sizes = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!offs || !sizes) { free(offs); free(sizes); return 0.0; }
    for (uint32_t i = 0; i < n; i++) {
        offs[i]  = doc->directory[i].offset;
        sizes[i] = doc->directory[i].size;
    }
    /* insertion sort by offset */
    for (uint32_t i = 1; i < n; i++) {
        uint32_t ko = offs[i], ks = sizes[i], j = i;
        while (j > 0 && offs[j-1] > ko) {
            offs[j] = offs[j-1]; sizes[j] = sizes[j-1]; j--;
        }
        offs[j] = ko; sizes[j] = ks;
    }
    uint32_t gap_total = 0;
    uint32_t span = (offs[n-1] + sizes[n-1]) - offs[0];
    for (uint32_t i = 1; i < n; i++) {
        uint32_t end_prev = offs[i-1] + sizes[i-1];
        if (offs[i] > end_prev) gap_total += offs[i] - end_prev;
    }
    free(offs);
    free(sizes);
    return span ? (double)gap_total / (double)span : 0.0;
}

/* ---- symbol density ---- */
double apg_symbol_density(const APG_Document *doc) {
    if (!doc || !doc->symbols.count) return 0.0;
    uint32_t total_bytes = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) total_bytes += doc->raw_sections[i].size;
    if (!total_bytes) return 0.0;
    return (double)doc->symbols.count * 1024.0 / (double)total_bytes;
}


/* ---- byte value anomaly detection ---- */

/*
 * Flag bytes whose frequency deviates from the expected uniform
 * distribution by more than `sigma` standard deviations.
 */
typedef struct APG_Anomaly {
    uint8_t  byte_value;
    uint32_t count;
    double   z_score;
} APG_Anomaly;

uint32_t apg_detect_anomalies(const uint8_t *data, uint32_t len,
                               double sigma, APG_Anomaly *out, uint32_t cap) {
    if (!data || !len || !out) return 0;
    uint32_t freq[256] = {0};
    for (uint32_t i = 0; i < len; i++) freq[data[i]]++;
    double mean = (double)len / 256.0;
    double variance = 0.0;
    for (int i = 0; i < 256; i++) {
        double d = (double)freq[i] - mean;
        variance += d * d;
    }
    variance /= 256.0;
    double stddev = sqrt(variance);
    if (stddev < 1e-9) return 0;
    uint32_t n = 0;
    for (int i = 0; i < 256 && n < cap; i++) {
        double z = ((double)freq[i] - mean) / stddev;
        if (z > sigma || z < -sigma) {
            out[n].byte_value = (uint8_t)i;
            out[n].count = freq[i];
            out[n].z_score = z;
            n++;
        }
    }
    return n;
}

/* ---- section type distribution ---- */

typedef struct APG_SectionStat {
    uint16_t type;
    uint32_t count;
    uint32_t total_bytes;
    double   fraction;
} APG_SectionStat;

uint32_t apg_section_type_stats(const APG_Document *doc,
                                 APG_SectionStat *out, uint32_t cap) {
    if (!doc || !out || !cap) return 0;
    uint32_t n = 0;
    uint32_t grand_total = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) grand_total += doc->raw_sections[i].size;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        uint16_t t = doc->raw_sections[i].type;
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n; j++) {
            if (out[j].type == t) { found = j; break; }
        }
        if (found != UINT32_MAX) {
            out[found].count++;
            out[found].total_bytes += doc->raw_sections[i].size;
        } else if (n < cap) {
            out[n].type = t;
            out[n].count = 1;
            out[n].total_bytes = doc->raw_sections[i].size;
            n++;
        }
    }
    if (grand_total) {
        for (uint32_t i = 0; i < n; i++)
            out[i].fraction = (double)out[i].total_bytes / (double)grand_total;
    }
    return n;
}

/* ---- string pool statistics ---- */

typedef struct APG_StringStats {
    uint32_t total_strings;
    uint32_t total_bytes;
    uint32_t min_length;
    uint32_t max_length;
    double   avg_length;
    uint32_t empty_count;
    uint32_t unique_hashes;
} APG_StringStats;

APG_StringStats apg_string_pool_stats(const APG_Document *doc) {
    APG_StringStats st = {0};
    if (!doc || !doc->strings.items) return st;
    st.total_strings = doc->strings.count;
    st.min_length = UINT32_MAX;
    /* count unique hashes */
    uint32_t *hashes = (uint32_t *)calloc(doc->strings.count, sizeof(uint32_t));
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (!s->data || s->length == 0) { st.empty_count++; continue; }
        st.total_bytes += s->length;
        if (s->length < st.min_length) st.min_length = s->length;
        if (s->length > st.max_length) st.max_length = s->length;
        if (hashes) hashes[i] = s->hash;
    }
    if (st.total_strings > st.empty_count)
        st.avg_length = (double)st.total_bytes / (double)(st.total_strings - st.empty_count);
    if (!st.total_strings) st.min_length = 0;
    /* count unique */
    if (hashes) {
        /* simple insertion sort then count distinct */
        for (uint32_t i = 1; i < doc->strings.count; i++) {
            uint32_t k = hashes[i], j = i;
            while (j > 0 && hashes[j-1] > k) { hashes[j] = hashes[j-1]; j--; }
            hashes[j] = k;
        }
        st.unique_hashes = doc->strings.count ? 1 : 0;
        for (uint32_t i = 1; i < doc->strings.count; i++) {
            if (hashes[i] != hashes[i-1]) st.unique_hashes++;
        }
        free(hashes);
    }
    return st;
}


/* ---- symbol score distribution ---- */

typedef struct APG_ScoreDistribution {
    uint32_t min_score;
    uint32_t max_score;
    double   mean_score;
    double   median_score;
    double   stddev;
    uint32_t zero_count;
} APG_ScoreDistribution;

APG_ScoreDistribution apg_score_distribution(const APG_Document *doc) {
    APG_ScoreDistribution d = {0};
    if (!doc || !doc->symbols.items || !doc->symbols.count) return d;
    uint32_t n = doc->symbols.count;
    d.min_score = UINT32_MAX;
    uint64_t sum = 0;
    /* collect scores */
    uint32_t *scores = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!scores) return d;
    for (uint32_t i = 0; i < n; i++) {
        scores[i] = doc->symbols.items[i].derived_score;
        sum += scores[i];
        if (scores[i] < d.min_score) d.min_score = scores[i];
        if (scores[i] > d.max_score) d.max_score = scores[i];
        if (scores[i] == 0) d.zero_count++;
    }
    d.mean_score = (double)sum / (double)n;
    /* sort for median */
    for (uint32_t i = 1; i < n; i++) {
        uint32_t key = scores[i], j = i;
        while (j > 0 && scores[j-1] > key) { scores[j] = scores[j-1]; j--; }
        scores[j] = key;
    }
    d.median_score = (double)scores[n / 2];
    /* stddev */
    double var = 0.0;
    for (uint32_t i = 0; i < n; i++) {
        double diff = (double)scores[i] - d.mean_score;
        var += diff * diff;
    }
    d.stddev = sqrt(var / (double)n);
    free(scores);
    return d;
}

/* ---- name length distribution ---- */

typedef struct APG_NameLengthDist {
    uint32_t bucket_0_8;     /* names 0-8 chars */
    uint32_t bucket_9_16;
    uint32_t bucket_17_32;
    uint32_t bucket_33_64;
    uint32_t bucket_65_plus;
    double   avg_length;
} APG_NameLengthDist;

APG_NameLengthDist apg_name_length_distribution(const APG_Document *doc) {
    APG_NameLengthDist d = {0};
    if (!doc || !doc->symbols.items) return d;
    uint32_t total_len = 0;
    uint32_t named = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data) continue;
        named++;
        uint32_t len = ref->length;
        total_len += len;
        if (len <= 8) d.bucket_0_8++;
        else if (len <= 16) d.bucket_9_16++;
        else if (len <= 32) d.bucket_17_32++;
        else if (len <= 64) d.bucket_33_64++;
        else d.bucket_65_plus++;
    }
    d.avg_length = named ? (double)total_len / (double)named : 0.0;
    return d;
}
