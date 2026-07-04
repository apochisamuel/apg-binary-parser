
#include "internal.h"

/*
 * writer.c — construct APG documents programmatically and serialise
 * them to the binary container format.
 *
 * Usage:
 *   APG_Writer *w = apg_writer_create(flags);
 *   uint32_t si = apg_writer_add_string(w, "hello", 5);
 *   apg_writer_add_attr(w, si, 0x42, 0);
 *   apg_writer_add_symbol(w, si, 0, 1, 0, 7);
 *   uint8_t *blob; size_t len;
 *   apg_writer_serialize(w, &blob, &len);
 *   apg_writer_free(w);
 */

#define APG_WRITER_MAX_STRINGS  4096u
#define APG_WRITER_MAX_ATTRS    4096u
#define APG_WRITER_MAX_SYMBOLS  4096u
#define APG_WRITER_MAX_RELOCS   4096u
#define APG_WRITER_MAX_FRAMES   512u
#define APG_WRITER_MAX_KEYS     4096u
#define APG_WRITER_MAX_STREAMS  4096u
#define APG_WRITER_MAX_ALIASES  512u

typedef struct WString  { char *data; uint32_t len; } WString;
typedef struct WAttr    { uint32_t name; uint32_t value; uint32_t flags; } WAttr;
typedef struct WSymbol  { uint32_t name; uint32_t attr; uint16_t klass; uint16_t flags; uint32_t aux; } WSymbol;
typedef struct WReloc   { uint32_t section; uint32_t sym; uint32_t target; uint32_t flags; } WReloc;
typedef struct WFrame   { uint8_t *data; uint32_t len; uint32_t mode; } WFrame;
typedef struct WKey     { uint32_t frame_no; uint32_t name; uint32_t marker; } WKey;
typedef struct WStream  { uint32_t id; uint32_t key; uint32_t events; uint32_t flags; } WStream;
typedef struct WAlias   { uint32_t id; uint8_t *data; uint32_t len; } WAlias;

struct APG_Writer {
    uint32_t flags;
    WString  strings[APG_WRITER_MAX_STRINGS];   uint32_t nstr;
    WAttr    attrs[APG_WRITER_MAX_ATTRS];       uint32_t nattr;
    WSymbol  symbols[APG_WRITER_MAX_SYMBOLS];   uint32_t nsym;
    WReloc   relocs[APG_WRITER_MAX_RELOCS];     uint32_t nrel;
    WFrame   frames[APG_WRITER_MAX_FRAMES];     uint32_t nfr;
    WKey     keys[APG_WRITER_MAX_KEYS];         uint32_t nkey;
    WStream  streams[APG_WRITER_MAX_STREAMS];   uint32_t nst;
    WAlias   aliases[APG_WRITER_MAX_ALIASES];   uint32_t nal;
};

APG_Writer *apg_writer_create(uint32_t flags) {
    APG_Writer *w = (APG_Writer *)calloc(1, sizeof(APG_Writer));
    if (w) w->flags = flags;
    return w;
}

/* ---- add elements ---- */

uint32_t apg_writer_add_string(APG_Writer *w, const char *s, uint32_t len) {
    if (!w || w->nstr >= APG_WRITER_MAX_STRINGS) return UINT32_MAX;
    uint32_t idx = w->nstr;
    w->strings[idx].data = (char *)malloc(len + 1);
    if (!w->strings[idx].data) return UINT32_MAX;
    memcpy(w->strings[idx].data, s, len);
    w->strings[idx].data[len] = '\0';
    w->strings[idx].len = len;
    w->nstr++;
    return idx;
}

uint32_t apg_writer_add_attr(APG_Writer *w, uint32_t name, uint32_t value, uint32_t flags) {
    if (!w || w->nattr >= APG_WRITER_MAX_ATTRS) return UINT32_MAX;
    uint32_t idx = w->nattr;
    w->attrs[idx].name  = name;
    w->attrs[idx].value = value;
    w->attrs[idx].flags = flags;
    w->nattr++;
    return idx;
}

uint32_t apg_writer_add_symbol(APG_Writer *w, uint32_t name, uint32_t attr,
                                uint16_t klass, uint16_t flags, uint32_t aux) {
    if (!w || w->nsym >= APG_WRITER_MAX_SYMBOLS) return UINT32_MAX;
    uint32_t idx = w->nsym;
    w->symbols[idx].name  = name;
    w->symbols[idx].attr  = attr;
    w->symbols[idx].klass = klass;
    w->symbols[idx].flags = flags;
    w->symbols[idx].aux   = aux;
    w->nsym++;
    return idx;
}

uint32_t apg_writer_add_reloc(APG_Writer *w, uint32_t section, uint32_t sym,
                               uint32_t target, uint32_t flags) {
    if (!w || w->nrel >= APG_WRITER_MAX_RELOCS) return UINT32_MAX;
    uint32_t idx = w->nrel;
    w->relocs[idx].section = section;
    w->relocs[idx].sym     = sym;
    w->relocs[idx].target  = target;
    w->relocs[idx].flags   = flags;
    w->nrel++;
    return idx;
}

uint32_t apg_writer_add_frame(APG_Writer *w, const uint8_t *payload,
                               uint32_t len, uint32_t mode) {
    if (!w || w->nfr >= APG_WRITER_MAX_FRAMES) return UINT32_MAX;
    uint32_t idx = w->nfr;
    w->frames[idx].mode = mode;
    w->frames[idx].len  = len;
    w->frames[idx].data = NULL;
    if (len) {
        w->frames[idx].data = (uint8_t *)malloc(len);
        if (!w->frames[idx].data) return UINT32_MAX;
        memcpy(w->frames[idx].data, payload, len);
    }
    w->nfr++;
    return idx;
}

uint32_t apg_writer_add_keyframe(APG_Writer *w, uint32_t frame_no,
                                  uint32_t name, uint32_t marker) {
    if (!w || w->nkey >= APG_WRITER_MAX_KEYS) return UINT32_MAX;
    uint32_t idx = w->nkey;
    w->keys[idx].frame_no = frame_no;
    w->keys[idx].name     = name;
    w->keys[idx].marker   = marker;
    w->nkey++;
    return idx;
}

uint32_t apg_writer_add_stream(APG_Writer *w, uint32_t id, uint32_t key,
                                uint32_t events, uint32_t flags) {
    if (!w || w->nst >= APG_WRITER_MAX_STREAMS) return UINT32_MAX;
    uint32_t idx = w->nst;
    w->streams[idx].id     = id;
    w->streams[idx].key    = key;
    w->streams[idx].events = events;
    w->streams[idx].flags  = flags;
    w->nst++;
    return idx;
}

uint32_t apg_writer_add_alias(APG_Writer *w, uint32_t id,
                               const uint8_t *data, uint32_t len) {
    if (!w || w->nal >= APG_WRITER_MAX_ALIASES) return UINT32_MAX;
    uint32_t idx = w->nal;
    w->aliases[idx].id  = id;
    w->aliases[idx].len = len;
    w->aliases[idx].data = NULL;
    if (len) {
        w->aliases[idx].data = (uint8_t *)malloc(len);
        if (!w->aliases[idx].data) return UINT32_MAX;
        memcpy(w->aliases[idx].data, data, len);
    }
    w->nal++;
    return idx;
}

/* ---- serialisation helpers ---- */

typedef struct WBuf { uint8_t *p; size_t n; size_t cap; } WBuf;

static void wb_grow(WBuf *b, size_t need) {
    if (b->n + need <= b->cap) return;
    size_t next = b->cap ? b->cap : 64;
    while (next < b->n + need) next *= 2;
    uint8_t *p = (uint8_t *)realloc(b->p, next);
    if (!p) return;
    b->p = p; b->cap = next;
}
static void wb_u8 (WBuf *b, uint8_t  v) { wb_grow(b,1); b->p[b->n++]=v; }
static void wb_u16(WBuf *b, uint16_t v) { wb_u8(b,(uint8_t)v); wb_u8(b,(uint8_t)(v>>8)); }
static void wb_u32(WBuf *b, uint32_t v) { wb_u16(b,(uint16_t)v); wb_u16(b,(uint16_t)(v>>16)); }
static void wb_raw(WBuf *b, const void *p, size_t n) { wb_grow(b,n); memcpy(b->p+b->n,p,n); b->n+=n; }

/* build one section payload into a WBuf */
static WBuf wb_strings(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nstr);
    for (uint32_t i=0; i<w->nstr; i++) {
        wb_u16(&b, (uint16_t)w->strings[i].len);
        wb_raw(&b, w->strings[i].data, w->strings[i].len);
    }
    return b;
}
static WBuf wb_attrs(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nattr);
    for (uint32_t i=0; i<w->nattr; i++) {
        wb_u32(&b, w->attrs[i].name);
        wb_u32(&b, w->attrs[i].value);
        wb_u32(&b, w->attrs[i].flags);
    }
    return b;
}
static WBuf wb_symbols(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nsym);
    for (uint32_t i=0; i<w->nsym; i++) {
        wb_u32(&b, w->symbols[i].name);
        wb_u32(&b, w->symbols[i].attr);
        wb_u16(&b, w->symbols[i].klass);
        wb_u16(&b, w->symbols[i].flags);
        wb_u32(&b, w->symbols[i].aux);
    }
    return b;
}
static WBuf wb_relocs(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nrel);
    for (uint32_t i=0; i<w->nrel; i++) {
        wb_u32(&b, w->relocs[i].section);
        wb_u32(&b, w->relocs[i].sym);
        wb_u32(&b, w->relocs[i].target);
        wb_u32(&b, w->relocs[i].flags);
    }
    return b;
}
static WBuf wb_frames(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nfr);
    for (uint32_t i=0; i<w->nfr; i++) {
        wb_u32(&b, w->frames[i].len);
        wb_u32(&b, w->frames[i].mode);
        wb_raw(&b, w->frames[i].data, w->frames[i].len);
    }
    return b;
}
static WBuf wb_keyframes(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nkey);
    for (uint32_t i=0; i<w->nkey; i++) {
        wb_u32(&b, w->keys[i].frame_no);
        wb_u32(&b, w->keys[i].name);
        wb_u32(&b, w->keys[i].marker);
    }
    return b;
}
static WBuf wb_streams_sec(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nst);
    for (uint32_t i=0; i<w->nst; i++) {
        wb_u32(&b, w->streams[i].id);
        wb_u32(&b, w->streams[i].key);
        wb_u32(&b, w->streams[i].events);
        wb_u32(&b, w->streams[i].flags);
    }
    return b;
}
static WBuf wb_aliases(APG_Writer *w) {
    WBuf b={0}; wb_u32(&b, w->nal);
    for (uint32_t i=0; i<w->nal; i++) {
        wb_u32(&b, w->aliases[i].id);
        wb_u32(&b, w->aliases[i].len);
        wb_raw(&b, w->aliases[i].data, w->aliases[i].len);
    }
    return b;
}

/* ---- main serialiser ---- */

int apg_writer_serialize(APG_Writer *w, uint8_t **out, size_t *out_len) {
    if (!w || !out || !out_len) return 0;
    /* collect section payloads */
    typedef struct { uint16_t type; WBuf payload; } SecBuf;
    SecBuf secs[8];
    uint32_t nsec = 0;
    if (w->nstr)  { secs[nsec].type=APG_SECTION_STRINGS;   secs[nsec].payload=wb_strings(w);     nsec++; }
    if (w->nattr) { secs[nsec].type=APG_SECTION_ATTRS;     secs[nsec].payload=wb_attrs(w);       nsec++; }
    if (w->nsym)  { secs[nsec].type=APG_SECTION_SYMBOLS;   secs[nsec].payload=wb_symbols(w);     nsec++; }
    if (w->nrel)  { secs[nsec].type=APG_SECTION_RELOCS;    secs[nsec].payload=wb_relocs(w);      nsec++; }
    if (w->nfr)   { secs[nsec].type=APG_SECTION_FRAMES;    secs[nsec].payload=wb_frames(w);      nsec++; }
    if (w->nkey)  { secs[nsec].type=APG_SECTION_KEYFRAMES; secs[nsec].payload=wb_keyframes(w);   nsec++; }
    if (w->nst)   { secs[nsec].type=APG_SECTION_STREAMS;   secs[nsec].payload=wb_streams_sec(w); nsec++; }
    if (w->nal)   { secs[nsec].type=APG_SECTION_ALIASES;   secs[nsec].payload=wb_aliases(w);     nsec++; }
    /* compute layout */
    uint32_t header_size = 32;
    uint32_t dir_size    = nsec * 24;
    uint32_t payload_off = header_size + dir_size;
    /* assemble */
    WBuf out_buf = {0};
    /* header: magic, version, nsec, flags, dir_offset, file_id, timeline_seed, reserved×2 */
    wb_u32(&out_buf, APG_MAGIC);
    wb_u16(&out_buf, APG_VERSION);
    wb_u16(&out_buf, (uint16_t)nsec);
    wb_u32(&out_buf, w->flags);
    wb_u32(&out_buf, header_size);
    wb_u32(&out_buf, 0x98761234u);  /* file_id */
    wb_u32(&out_buf, 0x13572468u);  /* timeline_seed */
    wb_u32(&out_buf, 0);
    wb_u32(&out_buf, 0);
    /* directory entries */
    uint32_t cur_off = payload_off;
    for (uint32_t i = 0; i < nsec; i++) {
        wb_u16(&out_buf, secs[i].type);
        wb_u16(&out_buf, 0);  /* subtype */
        wb_u32(&out_buf, cur_off);
        wb_u32(&out_buf, (uint32_t)secs[i].payload.n);
        wb_u32(&out_buf, 0);  /* aux */
        wb_u32(&out_buf, 0xffffffffu); /* link */
        wb_u32(&out_buf, 0);  /* count */
        cur_off += (uint32_t)secs[i].payload.n;
    }
    /* section payloads */
    for (uint32_t i = 0; i < nsec; i++) {
        wb_raw(&out_buf, secs[i].payload.p, secs[i].payload.n);
        free(secs[i].payload.p);
    }
    /* pad to minimum 80 bytes */
    while (out_buf.n < 80) wb_u8(&out_buf, 0);
    *out = out_buf.p;
    *out_len = out_buf.n;
    return 1;
}

/* ---- round-trip validation ---- */
int apg_writer_round_trip_check(APG_Writer *w) {
    if (!w) return 0;
    uint8_t *blob = NULL;
    size_t len = 0;
    if (!apg_writer_serialize(w, &blob, &len)) return 0;
    APG_Document *doc = apg_open_memory(blob, len, 0);
    int ok = 0;
    if (doc) {
        ok = (apg_document_symbol_count(doc) == w->nsym) &&
             (apg_document_stream_count(doc) == w->nst) &&
             (apg_document_frame_count(doc) == w->nfr);
        apg_close(doc);
    }
    free(blob);
    return ok;
}

void apg_writer_free(APG_Writer *w) {
    if (!w) return;
    for (uint32_t i = 0; i < w->nstr; i++) free(w->strings[i].data);
    for (uint32_t i = 0; i < w->nfr; i++)  free(w->frames[i].data);
    for (uint32_t i = 0; i < w->nal; i++)  free(w->aliases[i].data);
    free(w);
}


/* ---- deep clone a writer ---- */

APG_Writer *apg_writer_clone(const APG_Writer *src) {
    if (!src) return NULL;
    APG_Writer *w = apg_writer_create(src->flags);
    if (!w) return NULL;
    for (uint32_t i = 0; i < src->nstr; i++) {
        apg_writer_add_string(w, src->strings[i].data, src->strings[i].len);
    }
    for (uint32_t i = 0; i < src->nattr; i++) {
        apg_writer_add_attr(w, src->attrs[i].name, src->attrs[i].value, src->attrs[i].flags);
    }
    for (uint32_t i = 0; i < src->nsym; i++) {
        apg_writer_add_symbol(w, src->symbols[i].name, src->symbols[i].attr,
                               src->symbols[i].klass, src->symbols[i].flags, src->symbols[i].aux);
    }
    for (uint32_t i = 0; i < src->nrel; i++) {
        apg_writer_add_reloc(w, src->relocs[i].section, src->relocs[i].sym,
                              src->relocs[i].target, src->relocs[i].flags);
    }
    for (uint32_t i = 0; i < src->nfr; i++) {
        apg_writer_add_frame(w, src->frames[i].data, src->frames[i].len, src->frames[i].mode);
    }
    for (uint32_t i = 0; i < src->nkey; i++) {
        apg_writer_add_keyframe(w, src->keys[i].frame_no, src->keys[i].name, src->keys[i].marker);
    }
    for (uint32_t i = 0; i < src->nst; i++) {
        apg_writer_add_stream(w, src->streams[i].id, src->streams[i].key,
                               src->streams[i].events, src->streams[i].flags);
    }
    for (uint32_t i = 0; i < src->nal; i++) {
        apg_writer_add_alias(w, src->aliases[i].id, src->aliases[i].data, src->aliases[i].len);
    }
    return w;
}

/* ---- writer validation ---- */

typedef struct APG_WriterError {
    const char *field;
    const char *message;
    uint32_t    index;
} APG_WriterError;

uint32_t apg_writer_validate(const APG_Writer *w, APG_WriterError *out, uint32_t cap) {
    if (!w || !out) return 0;
    uint32_t n = 0;
    /* check symbol name references are valid */
    for (uint32_t i = 0; i < w->nsym && n < cap; i++) {
        if (w->symbols[i].name >= w->nstr) {
            out[n].field = "symbol.name";
            out[n].message = "name index references nonexistent string";
            out[n].index = i;
            n++;
        }
    }
    /* check symbol attr references are valid */
    for (uint32_t i = 0; i < w->nsym && n < cap; i++) {
        if (w->symbols[i].attr >= w->nattr && w->nattr > 0) {
            out[n].field = "symbol.attr";
            out[n].message = "attr index references nonexistent attribute";
            out[n].index = i;
            n++;
        }
    }
    /* check reloc section references */
    for (uint32_t i = 0; i < w->nrel && n < cap; i++) {
        if (w->relocs[i].sym >= w->nsym) {
            out[n].field = "reloc.sym";
            out[n].message = "reloc references nonexistent symbol";
            out[n].index = i;
            n++;
        }
    }
    /* check keyframe name references */
    for (uint32_t i = 0; i < w->nkey && n < cap; i++) {
        if (w->keys[i].name >= w->nstr) {
            out[n].field = "keyframe.name";
            out[n].message = "keyframe references nonexistent string";
            out[n].index = i;
            n++;
        }
    }
    /* check for duplicate alias IDs */
    for (uint32_t i = 0; i < w->nal && n < cap; i++) {
        for (uint32_t j = i + 1; j < w->nal; j++) {
            if (w->aliases[i].id == w->aliases[j].id) {
                out[n].field = "alias.id";
                out[n].message = "duplicate alias ID";
                out[n].index = j;
                n++;
                break;
            }
        }
    }
    return n;
}

/* ---- writer statistics ---- */

typedef struct APG_WriterStats {
    uint32_t total_strings;
    uint32_t total_string_bytes;
    uint32_t total_frame_bytes;
    uint32_t total_alias_bytes;
    uint32_t estimated_output_size;
} APG_WriterStats;

APG_WriterStats apg_writer_stats(const APG_Writer *w) {
    APG_WriterStats s = {0};
    if (!w) return s;
    s.total_strings = w->nstr;
    for (uint32_t i = 0; i < w->nstr; i++)
        s.total_string_bytes += w->strings[i].len;
    for (uint32_t i = 0; i < w->nfr; i++)
        s.total_frame_bytes += w->frames[i].len;
    for (uint32_t i = 0; i < w->nal; i++)
        s.total_alias_bytes += w->aliases[i].len;
    /* estimate output: header + directory + payloads */
    s.estimated_output_size = 32;                          /* header */
    s.estimated_output_size += 24 * 8;                     /* max 8 directory entries */
    s.estimated_output_size += 4 + s.total_string_bytes + w->nstr * 2;
    s.estimated_output_size += 4 + w->nattr * 12;
    s.estimated_output_size += 4 + w->nsym * 16;
    s.estimated_output_size += 4 + w->nrel * 16;
    s.estimated_output_size += 4 + s.total_frame_bytes + w->nfr * 8;
    s.estimated_output_size += 4 + w->nkey * 12;
    s.estimated_output_size += 4 + w->nst * 16;
    s.estimated_output_size += 4 + s.total_alias_bytes + w->nal * 8;
    return s;
}

/* ---- build from parsed document ---- */

APG_Writer *apg_writer_from_document(const APG_Document *doc) {
    if (!doc) return NULL;
    APG_Writer *w = apg_writer_create(doc->header.flags);
    if (!w) return NULL;
    /* copy strings */
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (s->data)
            apg_writer_add_string(w, s->data, s->length);
        else
            apg_writer_add_string(w, "", 0);
    }
    /* copy attrs */
    for (uint32_t i = 0; i < doc->attrs.count; i++) {
        APG_Attr *a = &doc->attrs.items[i];
        apg_writer_add_attr(w, a->name_index, a->value, a->flags);
    }
    /* copy symbols */
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_Symbol *s = &doc->symbols.items[i];
        apg_writer_add_symbol(w, s->name_index, s->attr_index,
                               s->klass, s->flags, s->aux);
    }
    /* copy relocs */
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        apg_writer_add_reloc(w, r->section_index, r->symbol_index, r->target, r->flags);
    }
    /* copy frames */
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        APG_Frame *f = &doc->frames.items[i];
        apg_writer_add_frame(w, f->payload, f->payload_len, f->mode);
    }
    /* copy keyframes */
    for (uint32_t i = 0; i < doc->keyframes.count; i++) {
        APG_Keyframe *k = &doc->keyframes.items[i];
        apg_writer_add_keyframe(w, k->frame_no, k->name_index, k->marker);
    }
    /* copy streams */
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        APG_Stream *s = &doc->streams.items[i];
        apg_writer_add_stream(w, s->id, s->key_index, s->event_count, s->flags);
    }
    return w;
}
