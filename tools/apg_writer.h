#ifndef APG_POC_COMMON_H
#define APG_POC_COMMON_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__GNUC__)
#define APG_POC_UNUSED __attribute__((unused))
#else
#define APG_POC_UNUSED
#endif

#define APG_POC_MAGIC 0x31475041u
#define APG_POC_VERSION 1u
#define APG_SECTION_STRINGS 1u
#define APG_SECTION_ATTRS 2u
#define APG_SECTION_SYMBOLS 3u
#define APG_SECTION_RELOCS 4u
#define APG_SECTION_FRAMES 5u
#define APG_SECTION_KEYFRAMES 6u
#define APG_SECTION_STREAMS 7u
#define APG_SECTION_ALIAS 8u
#define APG_FLAG_ROLLBACK_ATTRS 0x0100u
#define APG_FLAG_ROLLBACK_STRINGS 0x0200u
#define APG_FLAG_ALIAS_UNWIND 0x0400u
#define APG_FLAG_TYPE_SWEEP 0x0800u
#define APG_FLAG_KEY_UNWIND 0x1000u
#define APG_FLAG_FRAME_TRUST 0x2000u

typedef struct PocBuf { uint8_t *p; size_t n; size_t cap; } PocBuf;
typedef struct PocSection { uint16_t type; uint16_t subtype; uint32_t aux; uint32_t link; uint32_t count; PocBuf data; } PocSection;
typedef struct PocFile { uint32_t flags; PocSection sec[24]; uint32_t nsec; } PocFile;

static void pb_reserve(PocBuf *b, size_t need) {
    if (need <= b->cap) return;
    size_t next = b->cap ? b->cap : 64;
    while (next < need) next *= 2;
    uint8_t *p = (uint8_t *)realloc(b->p, next);
    if (!p) { fprintf(stderr, "alloc\n"); exit(2); }
    b->p = p; b->cap = next;
}
static void pb_u8(PocBuf *b, uint8_t v) { pb_reserve(b, b->n + 1); b->p[b->n++] = v; }
static void pb_u16(PocBuf *b, uint16_t v) { pb_u8(b, (uint8_t)v); pb_u8(b, (uint8_t)(v >> 8)); }
static void pb_u32(PocBuf *b, uint32_t v) { pb_u16(b, (uint16_t)v); pb_u16(b, (uint16_t)(v >> 16)); }
static void pb_bytes(PocBuf *b, const void *p, size_t n) { pb_reserve(b, b->n + n); memcpy(b->p + b->n, p, n); b->n += n; }
static APG_POC_UNUSED PocBuf strings_payload(uint32_t count, const char **items) {
    PocBuf b = {0}; pb_u32(&b, count);
    for (uint32_t i = 0; i < count; i++) { size_t n = strlen(items[i]); pb_u16(&b, (uint16_t)n); pb_bytes(&b, items[i], n); }
    return b;
}
static APG_POC_UNUSED PocBuf attrs_payload(uint32_t count, const uint32_t *name, const uint32_t *value, const uint32_t *flags) {
    PocBuf b = {0}; pb_u32(&b, count);
    for (uint32_t i = 0; i < count; i++) { pb_u32(&b, name[i]); pb_u32(&b, value[i]); pb_u32(&b, flags[i]); }
    return b;
}
static APG_POC_UNUSED PocBuf symbols_payload(uint32_t count, const uint32_t *name, const uint32_t *attr) {
    PocBuf b = {0}; pb_u32(&b, count);
    for (uint32_t i = 0; i < count; i++) { pb_u32(&b, name[i]); pb_u32(&b, attr[i]); pb_u16(&b, 1); pb_u16(&b, 0); pb_u32(&b, 7 + i); }
    return b;
}
static APG_POC_UNUSED PocBuf relocs_payload(uint32_t count, const uint32_t *section, const uint32_t *sym) {
    PocBuf b = {0}; pb_u32(&b, count);
    for (uint32_t i = 0; i < count; i++) { pb_u32(&b, section[i]); pb_u32(&b, sym[i]); pb_u32(&b, 0x40 + i); pb_u32(&b, 0); }
    return b;
}
static APG_POC_UNUSED PocBuf frames_payload(uint32_t len, uint32_t mode) {
    PocBuf b = {0}; pb_u32(&b, 1); pb_u32(&b, len); pb_u32(&b, mode);
    for (uint32_t i = 0; i < len; i++) pb_u8(&b, (uint8_t)(i * 31u + 9u));
    return b;
}
static APG_POC_UNUSED PocBuf keys_payload(uint32_t marker) {
    PocBuf b = {0}; pb_u32(&b, 1); pb_u32(&b, 0); pb_u32(&b, 0); pb_u32(&b, marker); return b;
}
static APG_POC_UNUSED PocBuf streams_payload(void) {
    PocBuf b = {0}; pb_u32(&b, 1); pb_u32(&b, 11); pb_u32(&b, 0); pb_u32(&b, 3); pb_u32(&b, 0); return b;
}
static APG_POC_UNUSED PocBuf alias_payload(uint32_t id0, uint32_t id1) {
    PocBuf b = {0}; const char a[] = "alpha"; const char c[] = "omega"; pb_u32(&b, 2);
    pb_u32(&b, id0); pb_u32(&b, 5); pb_bytes(&b, a, 5);
    pb_u32(&b, id1); pb_u32(&b, 5); pb_bytes(&b, c, 5);
    return b;
}
static void poc_init(PocFile *f, uint32_t flags) { memset(f, 0, sizeof(*f)); f->flags = flags; }
static void poc_add(PocFile *f, uint16_t type, uint32_t aux, uint32_t link, uint32_t count, PocBuf data) {
    if (f->nsec >= 24) exit(3);
    PocSection *s = &f->sec[f->nsec++]; s->type = type; s->subtype = 0; s->aux = aux; s->link = link; s->count = count; s->data = data;
}
static void poc_write(PocFile *f, const char *path) {
    FILE *fp = fopen(path, "wb"); if (!fp) exit(4);
    PocBuf out = {0};
    uint32_t dir_off = 32;
    uint32_t payload_off = 32 + f->nsec * 24;
    pb_u32(&out, APG_POC_MAGIC); pb_u16(&out, APG_POC_VERSION); pb_u16(&out, (uint16_t)f->nsec); pb_u32(&out, f->flags);
    pb_u32(&out, dir_off); pb_u32(&out, 0x98761234u); pb_u32(&out, 0x13572468u); pb_u32(&out, 0); pb_u32(&out, 0);
    uint32_t off = payload_off;
    for (uint32_t i = 0; i < f->nsec; i++) {
        PocSection *s = &f->sec[i]; pb_u16(&out, s->type); pb_u16(&out, s->subtype); pb_u32(&out, off); pb_u32(&out, (uint32_t)s->data.n); pb_u32(&out, s->aux); pb_u32(&out, s->link); pb_u32(&out, s->count); off += (uint32_t)s->data.n;
    }
    for (uint32_t i = 0; i < f->nsec; i++) pb_bytes(&out, f->sec[i].data.p, f->sec[i].data.n);
    while (out.n < 80) pb_u8(&out, 0);
    fwrite(out.p, 1, out.n, fp); fclose(fp);
    for (uint32_t i = 0; i < f->nsec; i++) { free(f->sec[i].data.p); }
    free(out.p);
}
#endif
