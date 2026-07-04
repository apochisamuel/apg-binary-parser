
#include "internal.h"

/*
 * export.c — human-readable text dump and hex dump of APG documents.
 *
 * Produces structured text reports for debugging and inspection:
 *   apg_export_header()   — header fields
 *   apg_export_directory() — table of contents
 *   apg_export_symbols()  — symbol table with resolved names
 *   apg_export_hex()      — raw hex dump of a section payload
 *   apg_export_full()     — complete document dump
 */

typedef struct APG_Exporter {
    char  *buf;
    size_t len;
    size_t cap;
} APG_Exporter;

static void ex_grow(APG_Exporter *e, size_t need) {
    if (e->len + need <= e->cap) return;
    size_t next = e->cap ? e->cap : 256;
    while (next < e->len + need) next *= 2;
    char *p = (char *)realloc(e->buf, next);
    if (!p) return;
    e->buf = p;
    e->cap = next;
}

static void ex_str(APG_Exporter *e, const char *s) {
    while (*s) {
        ex_grow(e, 1);
        e->buf[e->len++] = *s++;
    }
}

static void ex_u32(APG_Exporter *e, uint32_t v) {
    char tmp[12];
    int n = 0;
    if (v == 0) { tmp[n++] = '0'; }
    else { uint32_t w = v; while (w) { tmp[n++] = (char)('0' + w % 10); w /= 10; } }
    for (int i = n - 1; i >= 0; i--) { ex_grow(e, 1); e->buf[e->len++] = tmp[i]; }
}

static void ex_hex8(APG_Exporter *e, uint8_t b) {
    static const char hex[] = "0123456789abcdef";
    ex_grow(e, 2);
    e->buf[e->len++] = hex[(b >> 4) & 0xf];
    e->buf[e->len++] = hex[b & 0xf];
}

static void ex_hex32(APG_Exporter *e, uint32_t v) {
    for (int i = 28; i >= 0; i -= 4) {
        static const char hex[] = "0123456789abcdef";
        ex_grow(e, 1);
        e->buf[e->len++] = hex[(v >> i) & 0xf];
    }
}

static void ex_newline(APG_Exporter *e) { ex_str(e, "\n"); }

/* ---- header ---- */
static void ex_header(APG_Exporter *e, const APG_Document *doc) {
    ex_str(e, "=== HEADER ===\n");
    ex_str(e, "magic:     0x"); ex_hex32(e, doc->header.magic); ex_newline(e);
    ex_str(e, "version:   "); ex_u32(e, doc->header.version); ex_newline(e);
    ex_str(e, "sections:  "); ex_u32(e, doc->header.directory_count); ex_newline(e);
    ex_str(e, "flags:     0x"); ex_hex32(e, doc->header.flags); ex_newline(e);
    ex_str(e, "file_id:   0x"); ex_hex32(e, doc->header.file_id); ex_newline(e);
}

/* ---- directory ---- */
static const char *apg_section_type_name(uint16_t t) {
    switch (t) {
        case APG_SECTION_STRINGS:   return "STRINGS";
        case APG_SECTION_ATTRS:     return "ATTRS";
        case APG_SECTION_SYMBOLS:   return "SYMBOLS";
        case APG_SECTION_RELOCS:    return "RELOCS";
        case APG_SECTION_FRAMES:    return "FRAMES";
        case APG_SECTION_KEYFRAMES: return "KEYFRAMES";
        case APG_SECTION_STREAMS:   return "STREAMS";
        case APG_SECTION_ALIAS:     return "ALIAS";
        default:                    return "UNKNOWN";
    }
}

static void ex_directory(APG_Exporter *e, const APG_Document *doc) {
    ex_str(e, "\n=== DIRECTORY ===\n");
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        const APG_DirectoryEntry *de = &doc->directory[i];
        ex_str(e, "["); ex_u32(e, i); ex_str(e, "] ");
        ex_str(e, apg_section_type_name(de->type));
        ex_str(e, "  offset="); ex_u32(e, de->offset);
        ex_str(e, "  size="); ex_u32(e, de->size);
        ex_str(e, "  aux="); ex_u32(e, de->aux);
        ex_str(e, "  count="); ex_u32(e, de->count);
        ex_newline(e);
    }
}

/* ---- symbols ---- */
static void ex_symbols(APG_Exporter *e, const APG_Document *doc) {
    if (!doc->symbols.items) return;
    ex_str(e, "\n=== SYMBOLS ("); ex_u32(e, doc->symbols.count); ex_str(e, ") ===\n");
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        ex_str(e, "  ["); ex_u32(e, i); ex_str(e, "] name=\"");
        if (s->name_ref && s->name_ref->data) {
            for (uint32_t j = 0; j < s->name_ref->length && j < 64; j++) {
                ex_grow(e, 1);
                e->buf[e->len++] = s->name_ref->data[j];
            }
            if (s->name_ref->length > 64) ex_str(e, "...");
        } else {
            ex_str(e, "(unresolved #"); ex_u32(e, s->name_index); ex_str(e, ")");
        }
        ex_str(e, "\"  class="); ex_u32(e, s->klass);
        ex_str(e, "  score="); ex_u32(e, s->derived_score);
        ex_newline(e);
    }
}

/* ---- hex dump ---- */
static void ex_hex_region(APG_Exporter *e, const uint8_t *data,
                          uint32_t len, uint32_t max_bytes) {
    uint32_t cap = (len < max_bytes) ? len : max_bytes;
    for (uint32_t off = 0; off < cap; off += 16) {
        ex_str(e, "  ");
        ex_hex32(e, off);
        ex_str(e, ": ");
        for (uint32_t j = 0; j < 16 && off + j < cap; j++) {
            ex_hex8(e, data[off + j]);
            ex_str(e, " ");
        }
        ex_str(e, " |");
        for (uint32_t j = 0; j < 16 && off + j < cap; j++) {
            uint8_t c = data[off + j];
            ex_grow(e, 1);
            e->buf[e->len++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
        ex_str(e, "|");
        ex_newline(e);
    }
    if (cap < len) {
        ex_str(e, "  ... ("); ex_u32(e, len - cap); ex_str(e, " more bytes)\n");
    }
}

/* ---- public API ---- */
char *apg_export_full(const APG_Document *doc, size_t *out_len) {
    if (!doc) return NULL;
    APG_Exporter e = {0};
    ex_header(&e, doc);
    ex_directory(&e, doc);
    ex_symbols(&e, doc);
    /* hex dump each raw section */
    if (doc->raw_sections) {
        ex_str(&e, "\n=== RAW SECTIONS ===\n");
        for (uint32_t i = 0; i < doc->raw_count; i++) {
            APG_RawSection *rs = &doc->raw_sections[i];
            ex_str(&e, "Section "); ex_u32(&e, i);
            ex_str(&e, " ("); ex_str(&e, apg_section_type_name(rs->type));
            ex_str(&e, ", "); ex_u32(&e, rs->size); ex_str(&e, " bytes):\n");
            if (rs->data && rs->size) ex_hex_region(&e, rs->data, rs->size, 256);
        }
    }
    /* streams */
    if (doc->streams.items && doc->streams.count) {
        ex_str(&e, "\n=== STREAMS ("); ex_u32(&e, doc->streams.count); ex_str(&e, ") ===\n");
        for (uint32_t i = 0; i < doc->streams.count; i++) {
            const APG_Stream *st = &doc->streams.items[i];
            ex_str(&e, "  ["); ex_u32(&e, i); ex_str(&e, "] id=");
            ex_u32(&e, st->id); ex_str(&e, " events="); ex_u32(&e, st->event_count);
            ex_str(&e, " score="); ex_u32(&e, st->materialized_score); ex_newline(&e);
        }
    }
    /* frames */
    if (doc->frames.items && doc->frames.count) {
        ex_str(&e, "\n=== FRAMES ("); ex_u32(&e, doc->frames.count); ex_str(&e, ") ===\n");
        for (uint32_t i = 0; i < doc->frames.count; i++) {
            const APG_Frame *f = &doc->frames.items[i];
            ex_str(&e, "  ["); ex_u32(&e, i); ex_str(&e, "] payload=");
            ex_u32(&e, f->payload_len); ex_str(&e, " storage="); ex_u32(&e, f->storage_len);
            ex_str(&e, " mode=0x"); ex_hex32(&e, f->mode);
            ex_str(&e, " checksum=0x"); ex_hex32(&e, f->checksum); ex_newline(&e);
        }
    }
    /* null-terminate */
    ex_grow(&e, 1);
    e.buf[e.len] = '\0';
    if (out_len) *out_len = e.len;
    return e.buf;
}

void apg_export_free(char *buf) { free(buf); }

/* compact one-line summary */
uint32_t apg_export_summary_hash(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = doc->header.magic ^ doc->header.flags;
    h = apg_mix_u32(h, doc->symbols.count + doc->streams.count);
    h = apg_mix_u32(h, doc->frames.count + doc->relocs.count);
    h = apg_mix_u32(h, doc->strings.count + doc->attrs.count);
    if (doc->directory) {
        for (uint32_t i = 0; i < doc->directory_count; i++)
            h = apg_mix_u32(h, doc->directory[i].size ^ doc->directory[i].type);
    }
    return h;
}


/* ---- JSON-like export ---- */

static void ex_json_string(APG_Exporter *e, const char *s, uint32_t len) {
    ex_str(e, "\"");
    for (uint32_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '"') ex_str(e, "\\\"");
        else if (c == '\\') ex_str(e, "\\\\");
        else if (c == '\n') ex_str(e, "\\n");
        else if (c == '\t') ex_str(e, "\\t");
        else if (c >= 0x20 && c < 0x7f) { ex_grow(e, 1); e->buf[e->len++] = c; }
        else { ex_str(e, "\\x"); ex_hex8(e, (uint8_t)c); }
    }
    ex_str(e, "\"");
}

char *apg_export_json(const APG_Document *doc, size_t *out_len) {
    if (!doc) return NULL;
    APG_Exporter e = {0};
    ex_str(&e, "{\n");
    /* header */
    ex_str(&e, "  \"header\": {\n");
    ex_str(&e, "    \"magic\": "); ex_u32(&e, doc->header.magic); ex_str(&e, ",\n");
    ex_str(&e, "    \"version\": "); ex_u32(&e, doc->header.version); ex_str(&e, ",\n");
    ex_str(&e, "    \"flags\": "); ex_u32(&e, doc->header.flags); ex_str(&e, ",\n");
    ex_str(&e, "    \"sections\": "); ex_u32(&e, doc->header.directory_count); ex_str(&e, "\n");
    ex_str(&e, "  },\n");
    /* symbols */
    ex_str(&e, "  \"symbols\": [\n");
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        const APG_Symbol *s = &doc->symbols.items[i];
        ex_str(&e, "    {\"name\": ");
        if (s->name_ref && s->name_ref->data)
            ex_json_string(&e, s->name_ref->data, s->name_ref->length);
        else { ex_str(&e, "null"); }
        ex_str(&e, ", \"class\": "); ex_u32(&e, s->klass);
        ex_str(&e, ", \"aux\": "); ex_u32(&e, s->aux);
        ex_str(&e, ", \"score\": "); ex_u32(&e, s->derived_score);
        ex_str(&e, "}");
        if (i + 1 < doc->symbols.count) ex_str(&e, ",");
        ex_newline(&e);
    }
    ex_str(&e, "  ],\n");
    /* strings */
    ex_str(&e, "  \"strings\": [\n");
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        ex_str(&e, "    ");
        if (s->data) ex_json_string(&e, s->data, s->length);
        else ex_str(&e, "null");
        if (i + 1 < doc->strings.count) ex_str(&e, ",");
        ex_newline(&e);
    }
    ex_str(&e, "  ],\n");
    /* relocs */
    ex_str(&e, "  \"relocs\": [\n");
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        const APG_Reloc *r = &doc->relocs.items[i];
        ex_str(&e, "    {\"section\": "); ex_u32(&e, r->section_index);
        ex_str(&e, ", \"symbol\": "); ex_u32(&e, r->symbol_index);
        ex_str(&e, ", \"target\": "); ex_u32(&e, r->target);
        ex_str(&e, ", \"hash\": "); ex_u32(&e, r->resolved_hash);
        ex_str(&e, "}");
        if (i + 1 < doc->relocs.count) ex_str(&e, ",");
        ex_newline(&e);
    }
    ex_str(&e, "  ],\n");
    /* summary */
    ex_str(&e, "  \"summary_hash\": "); ex_u32(&e, doc->summary_hash); ex_newline(&e);
    ex_str(&e, "}\n");
    ex_grow(&e, 1);
    e.buf[e.len] = '\0';
    if (out_len) *out_len = e.len;
    return e.buf;
}
