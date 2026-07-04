
#include "internal.h"

/*
 * stats.c — comprehensive document statistics module.
 *
 * Computes aggregate statistics across all document elements:
 * symbol distributions, section utilisation, reference density,
 * and cross-section relationship metrics.
 */

typedef struct APG_DocStats {
    /* element counts */
    uint32_t sections;
    uint32_t symbols;
    uint32_t strings;
    uint32_t attrs;
    uint32_t relocs;
    uint32_t frames;
    uint32_t streams;
    uint32_t keyframes;
    uint32_t aliases;

    /* size metrics */
    uint64_t total_section_bytes;
    uint32_t avg_section_size;
    uint32_t median_section_size;
    uint32_t section_size_stddev;

    /* string metrics */
    uint32_t total_string_bytes;
    uint32_t avg_string_length;
    uint32_t max_string_length;

    /* reference metrics */
    double   refs_per_symbol;
    double   relocs_per_section;
    uint32_t max_attr_value;
    uint32_t distinct_classes;

    /* quality metrics */
    uint32_t warnings;
    uint32_t empty_sections;
    uint32_t orphan_strings;  /* strings not referenced by any symbol */
} APG_DocStats;

static int cmp_u32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a;
    uint32_t vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}

APG_DocStats *apg_stats_compute(const APG_Document *doc) {
    if (!doc) return NULL;
    APG_DocStats *s = (APG_DocStats *)calloc(1, sizeof(APG_DocStats));
    if (!s) return NULL;

    s->sections  = doc->raw_count;
    s->symbols   = doc->symbols.count;
    s->strings   = doc->strings.count;
    s->attrs     = doc->attrs.count;
    s->relocs    = doc->relocs.count;
    s->frames    = doc->frames.count;
    s->streams   = doc->streams.count;
    s->keyframes = doc->keyframes.count;
    s->aliases   = doc->aliases.count;
    s->warnings  = doc->warning_count;

    /* section sizes */
    if (doc->raw_count) {
        uint32_t *sizes = (uint32_t *)calloc(doc->raw_count, sizeof(uint32_t));
        if (sizes) {
            for (uint32_t i = 0; i < doc->raw_count; i++) {
                sizes[i] = doc->raw_sections[i].size;
                s->total_section_bytes += sizes[i];
                if (sizes[i] == 0) s->empty_sections++;
            }
            s->avg_section_size = (uint32_t)(s->total_section_bytes / doc->raw_count);
            /* sort for median */
            qsort(sizes, doc->raw_count, sizeof(uint32_t), cmp_u32);
            s->median_section_size = sizes[doc->raw_count / 2];
            /* stddev */
            double var = 0.0;
            for (uint32_t i = 0; i < doc->raw_count; i++) {
                double d = (double)sizes[i] - (double)s->avg_section_size;
                var += d * d;
            }
            var /= doc->raw_count;
            s->section_size_stddev = (uint32_t)sqrt(var);
            free(sizes);
        }
    }

    /* string metrics */
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *str = &doc->strings.items[i];
        if (str->data) {
            s->total_string_bytes += str->length;
            if (str->length > s->max_string_length) s->max_string_length = str->length;
        }
    }
    if (doc->strings.count)
        s->avg_string_length = s->total_string_bytes / doc->strings.count;

    /* reference metrics */
    if (doc->symbols.count) {
        uint32_t total_refs = 0;
        uint8_t *class_seen = (uint8_t *)calloc(65536, 1);
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            APG_Symbol *sym = &doc->symbols.items[i];
            if (sym->name_ref) total_refs++;
            if (sym->cached_attr) total_refs++;
            if (class_seen) class_seen[sym->klass] = 1;
        }
        s->refs_per_symbol = (double)total_refs / (double)doc->symbols.count;
        if (class_seen) {
            for (uint32_t i = 0; i < 65536; i++) if (class_seen[i]) s->distinct_classes++;
            free(class_seen);
        }
    }
    if (doc->raw_count && doc->relocs.count)
        s->relocs_per_section = (double)doc->relocs.count / (double)doc->raw_count;

    /* max attr value */
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        if (doc->attrs.items[i].value > s->max_attr_value)
            s->max_attr_value = doc->attrs.items[i].value;
    }

    /* orphan strings */
    if (doc->strings.count && doc->symbols.items) {
        uint8_t *referenced = (uint8_t *)calloc(doc->strings.count, 1);
        if (referenced) {
            for (uint32_t i = 0; i < doc->symbols.count; i++) {
                uint32_t ni = doc->symbols.items[i].name_index;
                if (ni < doc->strings.count) referenced[ni] = 1;
            }
            for (uint32_t i = 0; i < doc->strings.count; i++) {
                if (!referenced[i]) s->orphan_strings++;
            }
            free(referenced);
        }
    }

    return s;
}

/* ---- comparison ---- */

int apg_stats_similar(const APG_DocStats *a, const APG_DocStats *b, double threshold) {
    if (!a || !b) return 0;
    uint32_t diffs = 0;
    uint32_t checks = 0;
    if (a->sections != b->sections) diffs++;   checks++;
    if (a->symbols != b->symbols)   diffs++;   checks++;
    if (a->strings != b->strings)   diffs++;   checks++;
    if (a->relocs != b->relocs)     diffs++;   checks++;
    if (a->frames != b->frames)     diffs++;   checks++;
    if (a->streams != b->streams)   diffs++;   checks++;
    if (!checks) return 1;
    double sim = 1.0 - (double)diffs / (double)checks;
    return sim >= threshold;
}

void apg_stats_free(APG_DocStats *s) { free(s); }


/* ---- attribute value histogram ---- */

typedef struct APG_AttrHistEntry {
    uint32_t value;
    uint32_t count;
} APG_AttrHistEntry;

uint32_t apg_stats_attr_histogram(const APG_Document *doc,
                                    APG_AttrHistEntry *out, uint32_t cap) {
    if (!doc || !doc->attrs.items || !out || !cap) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        uint32_t v = doc->attrs.items[i].value;
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n; j++) {
            if (out[j].value == v) { found = j; break; }
        }
        if (found != UINT32_MAX) {
            out[found].count++;
        } else if (n < cap) {
            out[n].value = v;
            out[n].count = 1;
            n++;
        }
    }
    /* sort by count descending */
    for (uint32_t i = 1; i < n; i++) {
        APG_AttrHistEntry key = out[i];
        uint32_t j = i;
        while (j > 0 && out[j-1].count < key.count) {
            out[j] = out[j-1]; j--;
        }
        out[j] = key;
    }
    return n;
}

/* ---- reloc resolution rate ---- */

double apg_stats_reloc_resolution_rate(const APG_Document *doc) {
    if (!doc || !doc->relocs.items || !doc->relocs.count) return 1.0;
    uint32_t resolved = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        if (doc->relocs.items[i].resolved_hash != 0) resolved++;
    }
    return (double)resolved / (double)doc->relocs.count;
}

/* ---- frame utilisation ---- */

double apg_stats_frame_utilisation(const APG_Document *doc) {
    if (!doc || !doc->frames.items || !doc->frames.count) return 0.0;
    uint32_t used = 0, allocated = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        used += doc->frames.items[i].payload_len;
        allocated += doc->frames.items[i].storage_len;
    }
    return allocated ? (double)used / (double)allocated : 0.0;
}

/* ---- cross-section reference matrix ---- */

uint32_t apg_stats_cross_section_refs(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t cross = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        /* a cross-section ref is one where the reloc's section differs from the
           section implied by the target */
        uint32_t src_sec = r->section_index;
        uint32_t dst_sec = r->target % (doc->raw_count ? doc->raw_count : 1);
        if (src_sec != dst_sec) cross++;
    }
    return cross;
}
