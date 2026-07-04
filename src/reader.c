
#include "internal.h"

void apg_reader_init(APG_Reader *r, const uint8_t *data, size_t size) {
    r->data = data;
    r->size = size;
    r->pos = 0;
    r->failed = 0;
}

uint8_t apg_read_u8(APG_Reader *r) {
    if (!r || r->pos + 1 > r->size) { if (r) r->failed = 1; return 0; }
    return r->data[r->pos++];
}

uint16_t apg_read_u16(APG_Reader *r) {
    uint16_t a = apg_read_u8(r);
    uint16_t b = apg_read_u8(r);
    return (uint16_t)(a | (uint16_t)(b << 8));
}

uint32_t apg_read_u32(APG_Reader *r) {
    uint32_t a = apg_read_u16(r);
    uint32_t b = apg_read_u16(r);
    return a | (b << 16);
}

int apg_read_bytes(APG_Reader *r, uint8_t *out, size_t n) {
    if (!r || r->pos + n > r->size) { if (r) r->failed = 1; return 0; }
    if (out && n) memcpy(out, r->data + r->pos, n);
    r->pos += n;
    return 1;
}

int apg_reader_seek(APG_Reader *r, size_t pos) {
    if (!r || pos > r->size) { if (r) r->failed = 1; return 0; }
    r->pos = pos;
    return 1;
}

size_t apg_reader_remaining(const APG_Reader *r) {
    if (!r || r->pos > r->size) return 0;
    return r->size - r->pos;
}

uint32_t apg_rotl32(uint32_t v, unsigned s) {
    s &= 31u;
    return (v << s) | (v >> ((32u - s) & 31u));
}

uint32_t apg_mix_u32(uint32_t a, uint32_t b) {
    uint32_t x = a ^ (b + 0x9e3779b9u + (a << 6) + (a >> 2));
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

uint32_t apg_hash_bytes(const uint8_t *data, size_t n) {
    uint32_t h = 2166136261u;
    if (!data) return 0;
    for (size_t i = 0; i < n; i++) {
        h ^= data[i];
        h *= 16777619u;
        h = apg_rotl32(h, 5) ^ (uint32_t)i;
    }
    return h ? h : 1u;
}

uint32_t apg_checksum_window(const uint8_t *data, size_t n, uint32_t seed) {
    uint32_t h = seed ^ 0xa5a55a5au;
    for (size_t i = 0; data && i < n; i++) {
        h = apg_mix_u32(h, (uint32_t)data[i] + (uint32_t)(i * 17u));
    }
    return h;
}

uint32_t apg_score_name(const char *s, size_t n) {
    uint32_t score = 0;
    for (size_t i = 0; s && i < n; i++) {
        unsigned c = (unsigned char)s[i];
        if (c >= 'a' && c <= 'z') score += 3u + (uint32_t)(c - 'a');
        else if (c >= 'A' && c <= 'Z') score += 5u + (uint32_t)(c - 'A');
        else if (c >= '0' && c <= '9') score += 11u + (uint32_t)(c - '0');
        else score += 1u;
        score = apg_rotl32(score, 3) ^ (uint32_t)i;
    }
    return score;
}


/* ---- read helpers for different endianness ---- */

uint32_t apg_read_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint16_t apg_read_u16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

/* ---- raw section lookup by type ---- */

const APG_RawSection *apg_reader_find_section(const APG_Document *doc, uint16_t type) {
    if (!doc) return NULL;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        if (doc->raw_sections[i].type == type) return &doc->raw_sections[i];
    }
    return NULL;
}

/* ---- section payload checksum ---- */

uint32_t apg_reader_section_checksum(const APG_Document *doc, uint32_t idx) {
    if (!doc || idx >= doc->raw_count) return 0;
    APG_RawSection *rs = &doc->raw_sections[idx];
    if (!rs->data || !rs->size) return 0;
    return apg_hash_bytes(rs->data, rs->size);
}

/* ---- count sections by type ---- */

uint32_t apg_reader_count_type(const APG_Document *doc, uint16_t type) {
    if (!doc) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        if (doc->raw_sections[i].type == type) n++;
    }
    return n;
}

/* ---- total payload size ---- */

uint32_t apg_reader_total_payload(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->raw_count; i++) total += doc->raw_sections[i].size;
    return total;
}
