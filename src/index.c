
#include "internal.h"

/*
 * index.c — sorted symbol index with binary-search lookup.
 *
 * Builds a name-hash-sorted array of symbol indices for O(log n) lookup.
 * Also supports range iteration and a secondary hash-table for O(1)
 * expected-time lookup by exact name hash.
 */

#define APG_INDEX_BUCKET_COUNT 64u

typedef struct APG_IndexEntry {
    uint32_t name_hash;
    uint32_t symbol_idx;
} APG_IndexEntry;

typedef struct APG_IndexBucket {
    uint32_t *indices;      /* into the sorted array */
    uint32_t  count;
    uint32_t  cap;
} APG_IndexBucket;

struct APG_Index {
    APG_IndexEntry   *sorted;
    uint32_t          count;
    APG_IndexBucket   buckets[APG_INDEX_BUCKET_COUNT];
    const APG_Document *doc;
};

/* ---- insertion sort (fast for the sizes we expect) ---- */
static void apg_index_isort(APG_IndexEntry *arr, uint32_t n) {
    for (uint32_t i = 1; i < n; i++) {
        APG_IndexEntry key = arr[i];
        uint32_t j = i;
        while (j > 0 && arr[j-1].name_hash > key.name_hash) {
            arr[j] = arr[j-1];
            j--;
        }
        arr[j] = key;
    }
}

/* ---- bucket helpers ---- */
static int apg_bucket_push(APG_IndexBucket *b, uint32_t idx) {
    if (b->count == b->cap) {
        uint32_t next = b->cap ? b->cap * 2u : 4u;
        uint32_t *p = (uint32_t *)realloc(b->indices, (size_t)next * sizeof(uint32_t));
        if (!p) return 0;
        b->indices = p;
        b->cap = next;
    }
    b->indices[b->count++] = idx;
    return 1;
}

/* ---- build ---- */
APG_Index *apg_index_build(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->symbols.count) return NULL;
    APG_Index *ix = (APG_Index *)calloc(1, sizeof(APG_Index));
    if (!ix) return NULL;
    ix->doc = doc;
    ix->count = doc->symbols.count;
    ix->sorted = (APG_IndexEntry *)calloc(ix->count, sizeof(APG_IndexEntry));
    if (!ix->sorted) { free(ix); return NULL; }
    for (uint32_t i = 0; i < ix->count; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        uint32_t h = 0;
        if (s->name_ref && s->name_ref->data)
            h = apg_hash_bytes((const uint8_t *)s->name_ref->data, s->name_ref->length);
        ix->sorted[i].name_hash  = h;
        ix->sorted[i].symbol_idx = i;
    }
    apg_index_isort(ix->sorted, ix->count);
    /* populate hash buckets */
    for (uint32_t i = 0; i < ix->count; i++) {
        uint32_t b = ix->sorted[i].name_hash % APG_INDEX_BUCKET_COUNT;
        apg_bucket_push(&ix->buckets[b], i);
    }
    return ix;
}

/* ---- binary search ---- */
int apg_index_lookup(const APG_Index *ix, uint32_t name_hash, uint32_t *out_sym) {
    if (!ix || !ix->count) return 0;
    uint32_t lo = 0, hi = ix->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (ix->sorted[mid].name_hash < name_hash) lo = mid + 1;
        else hi = mid;
    }
    if (lo < ix->count && ix->sorted[lo].name_hash == name_hash) {
        if (out_sym) *out_sym = ix->sorted[lo].symbol_idx;
        return 1;
    }
    return 0;
}

/* ---- range query: all entries with hash in [lo_hash, hi_hash] ---- */
uint32_t apg_index_range(const APG_Index *ix, uint32_t lo_hash, uint32_t hi_hash,
                         uint32_t *out_buf, uint32_t buf_cap) {
    if (!ix || lo_hash > hi_hash) return 0;
    /* find first entry >= lo_hash */
    uint32_t lo = 0, hi = ix->count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (ix->sorted[mid].name_hash < lo_hash) lo = mid + 1;
        else hi = mid;
    }
    uint32_t n = 0;
    while (lo < ix->count && ix->sorted[lo].name_hash <= hi_hash) {
        if (out_buf && n < buf_cap) out_buf[n] = ix->sorted[lo].symbol_idx;
        n++;
        lo++;
    }
    return n;
}

/* ---- hash-table lookup ---- */
int apg_index_hash_lookup(const APG_Index *ix, uint32_t name_hash, uint32_t *out_sym) {
    if (!ix) return 0;
    uint32_t b = name_hash % APG_INDEX_BUCKET_COUNT;
    const APG_IndexBucket *bk = &ix->buckets[b];
    for (uint32_t i = 0; i < bk->count; i++) {
        uint32_t si = bk->indices[i];
        if (ix->sorted[si].name_hash == name_hash) {
            if (out_sym) *out_sym = ix->sorted[si].symbol_idx;
            return 1;
        }
    }
    return 0;
}

void apg_index_free(APG_Index *ix) {
    if (!ix) return;
    free(ix->sorted);
    for (uint32_t i = 0; i < APG_INDEX_BUCKET_COUNT; i++) free(ix->buckets[i].indices);
    free(ix);
}


/* ---- prefix trie for name-prefix lookups ---- */

#define APG_TRIE_CHILDREN 128u  /* ASCII printable range */

typedef struct APG_TrieNode {
    struct APG_TrieNode *children[APG_TRIE_CHILDREN];
    uint32_t *sym_indices;
    uint32_t  sym_count;
    uint32_t  sym_cap;
    uint32_t  subtree_count;
} APG_TrieNode;

static APG_TrieNode *apg_trie_new(void) {
    return (APG_TrieNode *)calloc(1, sizeof(APG_TrieNode));
}

static void apg_trie_insert(APG_TrieNode *root, const char *s, uint32_t len, uint32_t sym_idx) {
    APG_TrieNode *cur = root;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c >= APG_TRIE_CHILDREN) c = 0;
        if (!cur->children[c]) {
            cur->children[c] = apg_trie_new();
            if (!cur->children[c]) return;
        }
        cur = cur->children[c];
        cur->subtree_count++;
    }
    /* add symbol index at the terminal node */
    if (cur->sym_count == cur->sym_cap) {
        uint32_t next = cur->sym_cap ? cur->sym_cap * 2 : 4;
        uint32_t *p = (uint32_t *)realloc(cur->sym_indices, (size_t)next * sizeof(uint32_t));
        if (!p) return;
        cur->sym_indices = p;
        cur->sym_cap = next;
    }
    cur->sym_indices[cur->sym_count++] = sym_idx;
}

static APG_TrieNode *apg_trie_find_prefix(APG_TrieNode *root, const char *prefix, uint32_t len) {
    APG_TrieNode *cur = root;
    for (uint32_t i = 0; i < len && cur; i++) {
        uint8_t c = (uint8_t)prefix[i];
        if (c >= APG_TRIE_CHILDREN) return NULL;
        cur = cur->children[c];
    }
    return cur;
}

static void apg_trie_collect(APG_TrieNode *node, uint32_t *buf, uint32_t cap, uint32_t *n) {
    if (!node || *n >= cap) return;
    for (uint32_t i = 0; i < node->sym_count && *n < cap; i++)
        buf[(*n)++] = node->sym_indices[i];
    for (uint32_t c = 0; c < APG_TRIE_CHILDREN; c++)
        if (node->children[c]) apg_trie_collect(node->children[c], buf, cap, n);
}

static void apg_trie_free_node(APG_TrieNode *node) {
    if (!node) return;
    for (uint32_t c = 0; c < APG_TRIE_CHILDREN; c++)
        apg_trie_free_node(node->children[c]);
    free(node->sym_indices);
    free(node);
}

/* ---- public prefix-index API ---- */

typedef struct APG_PrefixIndex {
    APG_TrieNode *root;
    const APG_Document *doc;
} APG_PrefixIndex;

APG_PrefixIndex *apg_prefix_index_build(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return NULL;
    APG_PrefixIndex *pi = (APG_PrefixIndex *)calloc(1, sizeof(APG_PrefixIndex));
    if (!pi) return NULL;
    pi->doc = doc;
    pi->root = apg_trie_new();
    if (!pi->root) { free(pi); return NULL; }
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_String *ref = doc->symbols.items[i].name_ref;
        if (ref && ref->data && ref->length)
            apg_trie_insert(pi->root, ref->data, ref->length, i);
    }
    return pi;
}

uint32_t apg_prefix_search(const APG_PrefixIndex *pi, const char *prefix, uint32_t plen,
                            uint32_t *out, uint32_t cap) {
    if (!pi || !prefix) return 0;
    APG_TrieNode *node = apg_trie_find_prefix(pi->root, prefix, plen);
    if (!node) return 0;
    uint32_t n = 0;
    apg_trie_collect(node, out, cap, &n);
    return n;
}

uint32_t apg_prefix_count(const APG_PrefixIndex *pi, const char *prefix, uint32_t plen) {
    if (!pi || !prefix) return 0;
    APG_TrieNode *node = apg_trie_find_prefix(pi->root, prefix, plen);
    return node ? node->subtree_count : 0;
}

void apg_prefix_index_free(APG_PrefixIndex *pi) {
    if (!pi) return;
    apg_trie_free_node(pi->root);
    free(pi);
}
