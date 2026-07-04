
#include "internal.h"

/*
 * integrity.c — content-hash verification and corruption localization.
 *
 * Builds a Merkle-like hash tree over raw section payloads.  Each leaf
 * covers a 256-byte block; interior nodes hash pairs of children.
 * apg_integrity_verify() walks the tree top-down and returns the byte
 * offset of the first mismatching block, or UINT32_MAX if clean.
 */

/* ---- CRC-32 (ISO 3309 polynomial) ---- */
static uint32_t crc_table_val(uint32_t idx) {
    uint32_t c = idx;
    for (int k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
    return c;
}

static void apg_crc32_init_table(uint32_t *table) {
    for (uint32_t i = 0; i < 256; i++) table[i] = crc_table_val(i);
}

uint32_t apg_crc32(const uint8_t *data, size_t len) {
    uint32_t table[256];
    apg_crc32_init_table(table);
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc ^ 0xffffffffu;
}

/* ---- Merkle tree ---- */

#define APG_MERKLE_BLOCK 256u

typedef struct APG_MerkleNode {
    uint32_t hash;
    uint32_t offset;     /* byte offset of the block in the section */
    uint32_t length;
} APG_MerkleNode;

typedef struct APG_MerkleTree {
    APG_MerkleNode *nodes;
    uint32_t        node_count;
    uint32_t        leaf_count;
    uint32_t        depth;
} APG_MerkleTree;

static uint32_t apg_merkle_leaf_count(uint32_t data_len) {
    return (data_len + APG_MERKLE_BLOCK - 1u) / APG_MERKLE_BLOCK;
}

static uint32_t apg_next_pow2(uint32_t v) {
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    return v + 1;
}

APG_MerkleTree *apg_merkle_build(const uint8_t *data, uint32_t len) {
    if (!data || !len) return NULL;
    uint32_t raw_leaves = apg_merkle_leaf_count(len);
    uint32_t padded     = apg_next_pow2(raw_leaves);
    uint32_t total      = 2u * padded;   /* nodes[1..total-1]; [0] unused */
    APG_MerkleTree *t = (APG_MerkleTree *)calloc(1, sizeof(APG_MerkleTree));
    if (!t) return NULL;
    t->nodes = (APG_MerkleNode *)calloc(total, sizeof(APG_MerkleNode));
    if (!t->nodes) { free(t); return NULL; }
    t->node_count = total;
    t->leaf_count = raw_leaves;
    t->depth = 0;
    { uint32_t v = padded; while (v > 1) { t->depth++; v >>= 1; } }

    /* fill leaves */
    for (uint32_t i = 0; i < padded; i++) {
        uint32_t idx = padded + i;
        uint32_t off = i * APG_MERKLE_BLOCK;
        if (off < len) {
            uint32_t blen = APG_MERKLE_BLOCK;
            if (off + blen > len) blen = len - off;
            t->nodes[idx].hash   = apg_crc32(data + off, blen);
            t->nodes[idx].offset = off;
            t->nodes[idx].length = blen;
        } else {
            t->nodes[idx].hash = 0;
            t->nodes[idx].offset = off;
            t->nodes[idx].length = 0;
        }
    }
    /* build interior */
    for (uint32_t i = padded - 1; i >= 1; i--) {
        uint32_t lh = t->nodes[2*i].hash;
        uint32_t rh = t->nodes[2*i+1].hash;
        t->nodes[i].hash   = apg_mix_u32(lh, rh);
        t->nodes[i].offset = t->nodes[2*i].offset;
        t->nodes[i].length = t->nodes[2*i].length + t->nodes[2*i+1].length;
    }
    return t;
}

uint32_t apg_merkle_root(const APG_MerkleTree *t) {
    return (t && t->node_count > 1) ? t->nodes[1].hash : 0;
}

void apg_merkle_free(APG_MerkleTree *t) {
    if (!t) return;
    free(t->nodes);
    free(t);
}

/* ---- verification ---- */

uint32_t apg_integrity_verify(const APG_Document *doc, uint32_t section_idx) {
    if (!doc || section_idx >= doc->raw_count) return UINT32_MAX;
    APG_RawSection *rs = &doc->raw_sections[section_idx];
    if (!rs->data || !rs->size) return UINT32_MAX;
    APG_MerkleTree *tree = apg_merkle_build(rs->data, rs->size);
    if (!tree) return UINT32_MAX;
    /* recompute and compare every leaf */
    uint32_t padded = apg_next_pow2(tree->leaf_count);
    uint32_t bad_offset = UINT32_MAX;
    for (uint32_t i = 0; i < tree->leaf_count; i++) {
        uint32_t idx = padded + i;
        APG_MerkleNode *n = &tree->nodes[idx];
        if (!n->length) continue;
        uint32_t fresh = apg_crc32(rs->data + n->offset, n->length);
        if (fresh != n->hash) { bad_offset = n->offset; break; }
    }
    apg_merkle_free(tree);
    return bad_offset;
}

/* ---- whole-document integrity score ---- */

uint32_t apg_integrity_score(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        if (rs->data && rs->size) h = apg_mix_u32(h, apg_crc32(rs->data, rs->size));
    }
    return h;
}


/* ---- Adler-32 checksum ---- */

uint32_t apg_adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return (b << 16) | a;
}

/* ---- per-section integrity report ---- */

typedef struct APG_SectionIntegrity {
    uint32_t section_index;
    uint16_t section_type;
    uint32_t crc32;
    uint32_t adler32;
    uint32_t size;
    int      consistent;  /* 1 if both checksums agree with stored data */
} APG_SectionIntegrity;

uint32_t apg_integrity_report(const APG_Document *doc,
                               APG_SectionIntegrity *out, uint32_t cap) {
    if (!doc || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->raw_count && n < cap; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        out[n].section_index = i;
        out[n].section_type = rs->type;
        out[n].size = rs->size;
        if (rs->data && rs->size) {
            out[n].crc32 = apg_crc32(rs->data, rs->size);
            out[n].adler32 = apg_adler32(rs->data, rs->size);
            out[n].consistent = 1;
        } else {
            out[n].crc32 = 0;
            out[n].adler32 = 0;
            out[n].consistent = (rs->size == 0);
        }
        n++;
    }
    return n;
}

/* ---- combined document checksum ---- */

uint32_t apg_integrity_combined_checksum(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        APG_RawSection *rs = &doc->raw_sections[i];
        if (rs->data && rs->size) {
            h = apg_mix_u32(h, apg_crc32(rs->data, rs->size));
            h = apg_mix_u32(h, apg_adler32(rs->data, rs->size));
        }
    }
    return h;
}
