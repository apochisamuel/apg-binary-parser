
#include "internal.h"

/*
 * search.c — full-text search over the string pool and symbol names.
 *
 * Provides substring search, case-insensitive search, and a simple
 * inverted index for efficient multi-keyword lookups.
 */

/* ---- case-insensitive character compare ---- */

static int apg_char_lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* ---- substring search (Boyer-Moore-Horspool simplified) ---- */

static int apg_bmh_search(const char *haystack, uint32_t hlen,
                           const char *needle, uint32_t nlen) {
    if (nlen == 0) return 0;
    if (nlen > hlen) return -1;
    uint32_t skip[256];
    for (int i = 0; i < 256; i++) skip[i] = nlen;
    for (uint32_t i = 0; i < nlen - 1; i++)
        skip[(uint8_t)needle[i]] = nlen - 1 - i;
    uint32_t pos = 0;
    while (pos + nlen <= hlen) {
        uint32_t j = nlen - 1;
        while (haystack[pos + j] == needle[j]) {
            if (j == 0) return (int)pos;
            j--;
        }
        pos += skip[(uint8_t)haystack[pos + nlen - 1]];
    }
    return -1;
}

/* ---- case-insensitive substring search ---- */

static int apg_search_icase(const char *haystack, uint32_t hlen,
                             const char *needle, uint32_t nlen) {
    if (nlen == 0) return 0;
    if (nlen > hlen) return -1;
    for (uint32_t i = 0; i + nlen <= hlen; i++) {
        uint32_t j = 0;
        while (j < nlen && apg_char_lower(haystack[i + j]) == apg_char_lower(needle[j])) j++;
        if (j == nlen) return (int)i;
    }
    return -1;
}

/* ---- search string pool ---- */

uint32_t apg_search_strings(const APG_Document *doc, const char *query, uint32_t qlen,
                             uint32_t *out, uint32_t cap) {
    if (!doc || !doc->strings.items || !query || !qlen || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->strings.count && n < cap; i++) {
        APG_String *s = &doc->strings.items[i];
        if (!s->data || s->length < qlen) continue;
        if (apg_bmh_search(s->data, s->length, query, qlen) >= 0)
            out[n++] = i;
    }
    return n;
}

/* ---- case-insensitive string pool search ---- */

uint32_t apg_search_strings_icase(const APG_Document *doc, const char *query, uint32_t qlen,
                                    uint32_t *out, uint32_t cap) {
    if (!doc || !doc->strings.items || !query || !qlen || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->strings.count && n < cap; i++) {
        APG_String *s = &doc->strings.items[i];
        if (!s->data || s->length < qlen) continue;
        if (apg_search_icase(s->data, s->length, query, qlen) >= 0)
            out[n++] = i;
    }
    return n;
}

/* ---- search symbol names and return symbol indices ---- */

uint32_t apg_search_symbols(const APG_Document *doc, const char *query, uint32_t qlen,
                              uint32_t *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !query || !qlen || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data || ref->length < qlen) continue;
        if (apg_bmh_search(ref->data, ref->length, query, qlen) >= 0)
            out[n++] = i;
    }
    return n;
}

/* ---- simple inverted index for multi-keyword search ---- */

#define APG_SEARCH_MAX_TOKENS 16u

typedef struct APG_SearchIndex {
    uint32_t  *posting_lists[APG_SEARCH_MAX_TOKENS];
    uint32_t   posting_counts[APG_SEARCH_MAX_TOKENS];
    uint32_t   token_hashes[APG_SEARCH_MAX_TOKENS];
    uint32_t   num_tokens;
    const APG_Document *doc;
} APG_SearchIndex;

static uint32_t apg_token_hash(const char *s, uint32_t len) {
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < len; i++) {
        h ^= (uint8_t)apg_char_lower(s[i]);
        h *= 0x01000193u;
    }
    return h;
}

APG_SearchIndex *apg_search_index_build(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return NULL;
    APG_SearchIndex *idx = (APG_SearchIndex *)calloc(1, sizeof(APG_SearchIndex));
    if (!idx) return NULL;
    idx->doc = doc;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data || ref->length < 2) continue;
        uint32_t h = apg_token_hash(ref->data, ref->length);
        uint32_t slot = UINT32_MAX;
        for (uint32_t j = 0; j < idx->num_tokens; j++) {
            if (idx->token_hashes[j] == h) { slot = j; break; }
        }
        if (slot == UINT32_MAX) {
            if (idx->num_tokens >= APG_SEARCH_MAX_TOKENS) continue;
            slot = idx->num_tokens++;
            idx->token_hashes[slot] = h;
        }
        uint32_t *list = (uint32_t *)realloc(idx->posting_lists[slot],
                          (idx->posting_counts[slot] + 1) * sizeof(uint32_t));
        if (!list) continue;
        list[idx->posting_counts[slot]++] = i;
        idx->posting_lists[slot] = list;
    }
    return idx;
}

uint32_t apg_search_index_lookup(const APG_SearchIndex *idx, const char *token, uint32_t tlen,
                                   uint32_t *out, uint32_t cap) {
    if (!idx || !token) return 0;
    uint32_t h = apg_token_hash(token, tlen);
    for (uint32_t i = 0; i < idx->num_tokens; i++) {
        if (idx->token_hashes[i] == h) {
            uint32_t n = idx->posting_counts[i] < cap ? idx->posting_counts[i] : cap;
            if (out) memcpy(out, idx->posting_lists[i], n * sizeof(uint32_t));
            return n;
        }
    }
    return 0;
}

void apg_search_index_free(APG_SearchIndex *idx) {
    if (!idx) return;
    for (uint32_t i = 0; i < idx->num_tokens; i++) free(idx->posting_lists[i]);
    free(idx);
}


/* ---- multi-keyword AND search ---- */

uint32_t apg_search_multi_and(const APG_Document *doc,
                                const char **keywords, const uint32_t *klens,
                                uint32_t nkeywords,
                                uint32_t *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !keywords || !klens || !nkeywords || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data) continue;
        int all_match = 1;
        for (uint32_t k = 0; k < nkeywords; k++) {
            if (apg_search_icase(ref->data, ref->length, keywords[k], klens[k]) < 0) {
                all_match = 0;
                break;
            }
        }
        if (all_match) out[n++] = i;
    }
    return n;
}

/* ---- search with scoring ---- */

typedef struct APG_SearchHit {
    uint32_t symbol_idx;
    uint32_t score;
} APG_SearchHit;

uint32_t apg_search_scored(const APG_Document *doc, const char *query, uint32_t qlen,
                             APG_SearchHit *out, uint32_t cap) {
    if (!doc || !doc->symbols.items || !query || !qlen || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count && n < cap; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (!ref || !ref->data || ref->length < qlen) continue;
        int pos = apg_bmh_search(ref->data, ref->length, query, qlen);
        if (pos < 0) continue;
        out[n].symbol_idx = i;
        out[n].score = 100;
        if ((uint32_t)pos == 0) out[n].score += 50;
        if (ref->length == qlen) out[n].score += 100;
        if (ref->length < qlen * 2) out[n].score += 25;
        n++;
    }
    /* sort by score descending */
    for (uint32_t i = 1; i < n; i++) {
        APG_SearchHit key = out[i];
        uint32_t j = i;
        while (j > 0 && out[j-1].score < key.score) {
            out[j] = out[j-1]; j--;
        }
        out[j] = key;
    }
    return n;
}
