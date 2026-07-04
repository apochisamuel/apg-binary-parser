
#include "internal.h"

/*
 * diff.c — compare two parsed APG documents and produce a structured
 * change report.
 *
 * Reports additions, removals, and modifications at the symbol,
 * attribute, string, and section level.  Uses LCS (longest common
 * subsequence) on symbol names for alignment.
 */

typedef enum {
    APG_DIFF_ADD,
    APG_DIFF_DEL,
    APG_DIFF_MOD,
    APG_DIFF_EQ
} APG_DiffKind;

typedef struct APG_DiffEntry {
    APG_DiffKind kind;
    uint32_t     left_idx;   /* index in doc_a, UINT32_MAX if added */
    uint32_t     right_idx;  /* index in doc_b, UINT32_MAX if deleted */
    uint32_t     detail;     /* type-specific detail (e.g. changed field bitmask) */
} APG_DiffEntry;

typedef struct APG_DiffReport {
    APG_DiffEntry *entries;
    uint32_t count;
    uint32_t cap;
    uint32_t adds;
    uint32_t dels;
    uint32_t mods;
} APG_DiffReport;

static int apg_diff_push(APG_DiffReport *r, APG_DiffKind kind,
                          uint32_t li, uint32_t ri, uint32_t detail) {
    if (r->count == r->cap) {
        uint32_t next = r->cap ? r->cap * 2 : 32;
        APG_DiffEntry *p = (APG_DiffEntry *)realloc(r->entries,
                            (size_t)next * sizeof(APG_DiffEntry));
        if (!p) return 0;
        r->entries = p;
        r->cap = next;
    }
    APG_DiffEntry *e = &r->entries[r->count++];
    e->kind = kind;
    e->left_idx = li;
    e->right_idx = ri;
    e->detail = detail;
    if (kind == APG_DIFF_ADD) r->adds++;
    if (kind == APG_DIFF_DEL) r->dels++;
    if (kind == APG_DIFF_MOD) r->mods++;
    return 1;
}

/* ---- string comparison ---- */

static int apg_strings_equal(const APG_String *a, const APG_String *b) {
    if (!a || !b) return a == b;
    if (!a->data || !b->data) return a->data == b->data;
    if (a->length != b->length) return 0;
    for (uint32_t i = 0; i < a->length; i++)
        if (a->data[i] != b->data[i]) return 0;
    return 1;
}

/* ---- LCS-based symbol alignment ---- */

/*
 * Compute edit script between two symbol arrays using the classic
 * O(n*m) LCS DP.  For large documents this could be optimised to
 * Myers' O(ND) but the typical APG symbol counts are < 4096.
 */
static void apg_diff_symbols_lcs(const APG_Document *a, const APG_Document *b,
                                  APG_DiffReport *report) {
    uint32_t na = a->symbols.count, nb = b->symbols.count;
    if (!na && !nb) return;
    /* build match matrix: match[i][j] = names equal */
    /* We use a 1-D DP array of (na+1)*(nb+1) uint16_t */
    size_t dp_size = (size_t)(na + 1) * (nb + 1);
    uint16_t *dp = (uint16_t *)calloc(dp_size, sizeof(uint16_t));
    if (!dp) {
        /* fallback: mark everything as add/del */
        for (uint32_t i = 0; i < na; i++) apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0);
        for (uint32_t j = 0; j < nb; j++) apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, j, 0);
        return;
    }
    /* fill DP bottom-up */
    for (uint32_t i = na; i-- > 0; ) {
        for (uint32_t j = nb; j-- > 0; ) {
            int match = 0;
            APG_String *sa = a->symbols.items[i].name_ref;
            APG_String *sb = b->symbols.items[j].name_ref;
            if (apg_strings_equal(sa, sb)) match = 1;
            if (match)
                dp[i * (nb+1) + j] = dp[(i+1)*(nb+1) + j+1] + 1;
            else {
                uint16_t skip_a = dp[(i+1)*(nb+1) + j];
                uint16_t skip_b = dp[i*(nb+1) + j+1];
                dp[i*(nb+1)+j] = skip_a > skip_b ? skip_a : skip_b;
            }
        }
    }
    /* trace back */
    uint32_t i = 0, j = 0;
    while (i < na && j < nb) {
        APG_String *sa = a->symbols.items[i].name_ref;
        APG_String *sb = b->symbols.items[j].name_ref;
        if (apg_strings_equal(sa, sb)) {
            /* check if modified */
            const APG_Symbol *si = &a->symbols.items[i];
            const APG_Symbol *sj = &b->symbols.items[j];
            uint32_t detail = 0;
            if (si->klass != sj->klass)           detail |= 1;
            if (si->aux   != sj->aux)             detail |= 2;
            if (si->derived_score != sj->derived_score) detail |= 4;
            if (detail)
                apg_diff_push(report, APG_DIFF_MOD, i, j, detail);
            else
                apg_diff_push(report, APG_DIFF_EQ, i, j, 0);
            i++; j++;
        } else if (dp[(i+1)*(nb+1)+j] >= dp[i*(nb+1)+j+1]) {
            apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0);
            i++;
        } else {
            apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, j, 0);
            j++;
        }
    }
    while (i < na) { apg_diff_push(report, APG_DIFF_DEL, i++, UINT32_MAX, 0); }
    while (j < nb) { apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, j++, 0); }
    free(dp);
}

/* ---- string pool diff ---- */

static void apg_diff_strings(const APG_Document *a, const APG_Document *b,
                               APG_DiffReport *report) {
    uint32_t na = a->strings.count, nb = b->strings.count;
    uint32_t common = na < nb ? na : nb;
    for (uint32_t i = 0; i < common; i++) {
        if (!apg_strings_equal(&a->strings.items[i], &b->strings.items[i]))
            apg_diff_push(report, APG_DIFF_MOD, i, i, 0x10);
    }
    for (uint32_t i = common; i < na; i++)
        apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0x10);
    for (uint32_t i = common; i < nb; i++)
        apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, i, 0x10);
}

/* ---- section-level diff ---- */

static void apg_diff_sections(const APG_Document *a, const APG_Document *b,
                               APG_DiffReport *report) {
    uint32_t na = a->raw_count, nb = b->raw_count;
    uint32_t common = na < nb ? na : nb;
    for (uint32_t i = 0; i < common; i++) {
        APG_RawSection *sa = &a->raw_sections[i];
        APG_RawSection *sb = &b->raw_sections[i];
        if (sa->type != sb->type || sa->size != sb->size)
            apg_diff_push(report, APG_DIFF_MOD, i, i, 0x20);
        else if (sa->data && sb->data && sa->size == sb->size) {
            int same = 1;
            for (uint32_t k = 0; k < sa->size; k++)
                if (sa->data[k] != sb->data[k]) { same = 0; break; }
            if (!same) apg_diff_push(report, APG_DIFF_MOD, i, i, 0x20);
        }
    }
    for (uint32_t i = common; i < na; i++)
        apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0x20);
    for (uint32_t i = common; i < nb; i++)
        apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, i, 0x20);
}

/* ---- public API ---- */

APG_DiffReport *apg_diff(const APG_Document *a, const APG_Document *b) {
    if (!a || !b) return NULL;
    APG_DiffReport *r = (APG_DiffReport *)calloc(1, sizeof(APG_DiffReport));
    if (!r) return NULL;
    apg_diff_symbols_lcs(a, b, r);
    apg_diff_strings(a, b, r);
    apg_diff_sections(a, b, r);
    return r;
}

uint32_t apg_diff_total_changes(const APG_DiffReport *r) {
    return r ? r->adds + r->dels + r->mods : 0;
}

void apg_diff_free(APG_DiffReport *r) {
    if (!r) return;
    free(r->entries);
    free(r);
}


/* ---- attribute-level diff ---- */

static void apg_diff_attrs(const APG_Document *a, const APG_Document *b,
                            APG_DiffReport *report) {
    uint32_t na = a->attrs.count, nb = b->attrs.count;
    uint32_t common = na < nb ? na : nb;
    for (uint32_t i = 0; i < common; i++) {
        uint32_t detail = 0;
        if (a->attrs.items[i].name_index != b->attrs.items[i].name_index) detail |= 0x100;
        if (a->attrs.items[i].value != b->attrs.items[i].value) detail |= 0x200;
        if (a->attrs.items[i].flags != b->attrs.items[i].flags) detail |= 0x400;
        if (detail) apg_diff_push(report, APG_DIFF_MOD, i, i, detail);
    }
    for (uint32_t i = common; i < na; i++)
        apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0x100);
    for (uint32_t i = common; i < nb; i++)
        apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, i, 0x100);
}

/* ---- frame diff ---- */

static void apg_diff_frames(const APG_Document *a, const APG_Document *b,
                              APG_DiffReport *report) {
    uint32_t na = a->frames.count, nb = b->frames.count;
    uint32_t common = na < nb ? na : nb;
    for (uint32_t i = 0; i < common; i++) {
        if (a->frames.items[i].payload_len != b->frames.items[i].payload_len ||
            a->frames.items[i].mode != b->frames.items[i].mode ||
            a->frames.items[i].checksum != b->frames.items[i].checksum)
            apg_diff_push(report, APG_DIFF_MOD, i, i, 0x40);
    }
    for (uint32_t i = common; i < na; i++)
        apg_diff_push(report, APG_DIFF_DEL, i, UINT32_MAX, 0x40);
    for (uint32_t i = common; i < nb; i++)
        apg_diff_push(report, APG_DIFF_ADD, UINT32_MAX, i, 0x40);
}

/* ---- comprehensive diff (adds attr + frame layers) ---- */

APG_DiffReport *apg_diff_full(const APG_Document *a, const APG_Document *b) {
    APG_DiffReport *r = apg_diff(a, b);
    if (!r) return NULL;
    apg_diff_attrs(a, b, r);
    apg_diff_frames(a, b, r);
    return r;
}

/* ---- diff summary ---- */

typedef struct APG_DiffSummary {
    uint32_t total_changes;
    uint32_t symbol_changes;
    uint32_t string_changes;
    uint32_t section_changes;
    uint32_t attr_changes;
    uint32_t frame_changes;
} APG_DiffSummary;

APG_DiffSummary apg_diff_summarize(const APG_DiffReport *r) {
    APG_DiffSummary s = {0};
    if (!r) return s;
    s.total_changes = r->adds + r->dels + r->mods;
    for (uint32_t i = 0; i < r->count; i++) {
        uint32_t d = r->entries[i].detail;
        if (d == 0 || d < 0x10) s.symbol_changes++;
        else if (d == 0x10)     s.string_changes++;
        else if (d == 0x20)     s.section_changes++;
        else if (d >= 0x100)    s.attr_changes++;
        else if (d == 0x40)     s.frame_changes++;
    }
    return s;
}
