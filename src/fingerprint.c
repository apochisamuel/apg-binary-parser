
#include "internal.h"

/*
 * fingerprint.c — compact document fingerprints for fast comparison.
 *
 * Computes multiple hash-based fingerprints at different granularities:
 * structural (section types and sizes), content (payload hashes),
 * and semantic (symbol names and relationships).  Two documents with
 * identical fingerprints are very likely identical; differing
 * fingerprints guarantee differences exist at that level.
 */

typedef struct APG_Fingerprint {
    uint32_t structural;
    uint32_t content;
    uint32_t semantic;
    uint32_t combined;
} APG_Fingerprint;

static uint32_t fp_structural(const APG_Document *doc) {
    uint32_t h = doc->header.magic ^ doc->header.flags;
    h = apg_mix_u32(h, doc->header.version ^ doc->directory_count);
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        const APG_DirectoryEntry *de = &doc->directory[i];
        h = apg_mix_u32(h, ((uint32_t)de->type << 16) | de->subtype);
        h = apg_mix_u32(h, de->size);
        h = apg_mix_u32(h, de->aux ^ de->link);
    }
    return h;
}

static uint32_t fp_content(const APG_Document *doc) {
    uint32_t h = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        if (rs->data && rs->size)
            h = apg_mix_u32(h, apg_hash_bytes(rs->data, rs->size < 256 ? rs->size : 256));
        h = apg_mix_u32(h, rs->size ^ (uint32_t)rs->type);
    }
    return h;
}

static uint32_t fp_semantic(const APG_Document *doc) {
    uint32_t h = doc->symbols.count ^ doc->strings.count;
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            const APG_Symbol *s = &doc->symbols.items[i];
            h = apg_mix_u32(h, s->derived_score ^ s->klass);
            if (s->name_ref && s->name_ref->data)
                h = apg_mix_u32(h, s->name_ref->hash);
        }
    }
    if (doc->relocs.items) {
        for (uint32_t i = 0; i < doc->relocs.count; i++)
            h = apg_mix_u32(h, doc->relocs.items[i].resolved_hash);
    }
    return h;
}

APG_Fingerprint apg_fingerprint(const APG_Document *doc) {
    APG_Fingerprint fp = {0};
    if (!doc) return fp;
    fp.structural = fp_structural(doc);
    fp.content    = fp_content(doc);
    fp.semantic   = fp_semantic(doc);
    fp.combined   = apg_mix_u32(apg_mix_u32(fp.structural, fp.content), fp.semantic);
    return fp;
}

int apg_fingerprint_equal(APG_Fingerprint a, APG_Fingerprint b) {
    return a.combined == b.combined &&
           a.structural == b.structural &&
           a.content == b.content &&
           a.semantic == b.semantic;
}

int apg_fingerprint_structural_match(APG_Fingerprint a, APG_Fingerprint b) {
    return a.structural == b.structural;
}

/* ---- similarity score (0.0 = completely different, 1.0 = identical) ---- */

double apg_similarity(const APG_Document *a, const APG_Document *b) {
    if (!a || !b) return 0.0;
    APG_Fingerprint fa = apg_fingerprint(a);
    APG_Fingerprint fb = apg_fingerprint(b);
    double score = 0.0;
    if (fa.structural == fb.structural) score += 0.4;
    if (fa.content == fb.content)       score += 0.3;
    if (fa.semantic == fb.semantic)     score += 0.3;
    return score;
}

/* ---- MinHash-style similarity for large documents ---- */

uint32_t apg_minhash(const APG_Document *doc, uint32_t *hashes, uint32_t k) {
    if (!doc || !hashes || !k) return 0;
    for (uint32_t i = 0; i < k; i++) hashes[i] = UINT32_MAX;
    /* hash each symbol name with k different seeds */
    if (doc->symbols.items) {
        for (uint32_t i = 0; i < doc->symbols.count; i++) {
            APG_String *ref = doc->symbols.items[i].name_ref;
            if (!ref || !ref->data) continue;
            uint32_t base = ref->hash;
            for (uint32_t j = 0; j < k; j++) {
                uint32_t h = apg_mix_u32(base, j * 0x9e3779b9u);
                if (h < hashes[j]) hashes[j] = h;
            }
        }
    }
    return k;
}

double apg_minhash_jaccard(const uint32_t *a, const uint32_t *b, uint32_t k) {
    if (!a || !b || !k) return 0.0;
    uint32_t match = 0;
    for (uint32_t i = 0; i < k; i++) if (a[i] == b[i]) match++;
    return (double)match / (double)k;
}


/* ---- section type fingerprint ---- */

uint32_t apg_section_type_fingerprint(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        /* encode position + type + approximate size class */
        uint32_t sc = 0;
        if (doc->raw_sections[i].size > 4096) sc = 3;
        else if (doc->raw_sections[i].size > 256) sc = 2;
        else if (doc->raw_sections[i].size > 0) sc = 1;
        h = apg_mix_u32(h, ((uint32_t)doc->raw_sections[i].type << 16) | (i << 8) | sc);
    }
    return h;
}

/* ---- symbol class profile fingerprint ---- */

uint32_t apg_class_profile_fingerprint(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t class_counts[16] = {0};
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        uint32_t bucket = doc->symbols.items[i].klass % 16;
        class_counts[bucket]++;
    }
    uint32_t h = 0;
    for (int i = 0; i < 16; i++)
        h = apg_mix_u32(h, class_counts[i]);
    return h;
}

/* ---- difference metric between fingerprints ---- */

uint32_t apg_fingerprint_hamming(APG_Fingerprint a, APG_Fingerprint b) {
    uint32_t diff = 0;
    uint32_t x;
    x = a.structural ^ b.structural; while (x) { diff += x & 1; x >>= 1; }
    x = a.content ^ b.content;       while (x) { diff += x & 1; x >>= 1; }
    x = a.semantic ^ b.semantic;     while (x) { diff += x & 1; x >>= 1; }
    return diff;
}
