
#include "internal.h"

static APG_String *apg_string_ptr(APG_Document *doc, uint32_t idx) {
    if (!doc || !doc->strings.items || idx >= doc->strings.count) return NULL;
    return &doc->strings.items[idx];
}

int apg_parse_symbols(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_SYMBOLS);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "symbol count outside limits");
        return 0;
    }
    doc->symbols.items = (APG_Symbol *)calloc(count ? count : 1u, sizeof(APG_Symbol));
    if (!doc->symbols.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "symbol allocation failed");
        return 0;
    }
    doc->symbols.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->symbols.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        APG_Symbol *s = &doc->symbols.items[i];
        s->name_index = apg_read_u32(&r);
        s->attr_index = apg_read_u32(&r);
        s->klass = apg_read_u16(&r);
        s->flags = apg_read_u16(&r);
        s->aux = apg_read_u32(&r);
        if (r.failed) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "symbol entry is truncated");
            return 0;
        }
        s->name_ref = apg_string_ptr(doc, s->name_index);
        if (doc->attrs.items && s->attr_index < doc->attrs.count) s->cached_attr = &doc->attrs.items[s->attr_index];
        s->derived_score = apg_mix_u32(s->name_index, s->attr_index ^ s->aux);
    }
    return 1;
}

void apg_free_symbols(APG_SymbolTable *tab) {
    if (!tab || !tab->items) return;
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}

static void apg_prepare_frame_storage(APG_Frame *frame, uint32_t storage_len, uint32_t payload_len) {
    frame->storage_len = storage_len;
    frame->payload_len = payload_len;
    frame->payload = NULL;
    if (storage_len) frame->payload = (uint8_t *)malloc(storage_len);
}

/*
 * Decode frame payload with XOR obfuscation.
 *
 * BUG: When the frame mode has the FRAME_TRUST bit pattern (mode & 0x80),
 * the function uses payload_len directly for the decode loop. When FRAME_TRUST
 * is NOT set, it clamps to storage_len. However, the parse_frames function
 * sets storage_len via the directory budget computation, which in TRUST mode
 * may be smaller than payload_len. So the bug only fires when:
 *   1. FRAME_TRUST flag is set in header
 *   2. Directory budget returns a small value
 *   3. Frame's payload_len > storage_len (from budget)
 *   4. Frame mode has bit 7 set
 */
static void apg_decode_frame_payload(APG_Frame *frame, APG_Reader *r) {
    if (!frame || !r || !frame->payload) return;
    uint32_t decode_len = frame->payload_len;
    if (!(frame->mode & 0x80u)) {
        /* Non-trusted mode: clamp to storage */
        if (decode_len > frame->storage_len) decode_len = frame->storage_len;
    }
    /* BUG: trusted mode skips the clamp, payload_len may exceed storage_len */
    for (uint32_t i = 0; i < decode_len; i++) {
        uint8_t b = apg_read_u8(r);
        frame->payload[i] = (uint8_t)(b ^ (uint8_t)((frame->mode + i * 13u) & 0xffu));
    }
    frame->checksum = apg_checksum_window(frame->payload,
        decode_len <= frame->storage_len ? decode_len : frame->storage_len,
        frame->mode);
}

int apg_parse_frames(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_FRAMES);
    if (!rs) return 1;
    const APG_DirectoryEntry *de = apg_directory_by_type(doc, APG_SECTION_FRAMES);
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 512u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "frame count outside limits");
        return 0;
    }
    doc->frames.items = (APG_Frame *)calloc(count ? count : 1u, sizeof(APG_Frame));
    if (!doc->frames.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "frame allocation failed");
        return 0;
    }
    doc->frames.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->frames.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t payload_len = apg_read_u32(&r);
        uint32_t mode = apg_read_u32(&r);
        uint32_t storage_len = de ? apg_directory_frame_budget(doc, de, payload_len) : payload_len;
        doc->frames.items[i].mode = mode;
        apg_prepare_frame_storage(&doc->frames.items[i], storage_len, payload_len);
        if (!doc->frames.items[i].payload && storage_len) {
            apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "frame payload allocation failed");
            return 0;
        }
        if (payload_len > apg_reader_remaining(&r)) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "frame payload is truncated");
            return 0;
        }
        apg_decode_frame_payload(&doc->frames.items[i], &r);
        if (r.failed) return 0;
    }
    return 1;
}

void apg_free_frames(APG_FrameTable *tab) {
    if (!tab || !tab->items) return;
    for (uint32_t i = 0; i < tab->count; i++) free(tab->items[i].payload);
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}


/* ---- frame content analysis ---- */

uint32_t apg_frame_checksum(const APG_Frame *f) {
    if (!f || !f->payload || !f->payload_len) return 0;
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < f->payload_len; i++) {
        h ^= f->payload[i];
        h *= 0x01000193u;
    }
    return h;
}

int apg_frame_is_empty(const APG_Frame *f) {
    if (!f) return 1;
    if (!f->payload || f->payload_len == 0) return 1;
    /* check if all zeros */
    for (uint32_t i = 0; i < f->payload_len; i++) {
        if (f->payload[i] != 0) return 0;
    }
    return 1;
}

uint32_t apg_frames_total_payload(const APG_Document *doc) {
    if (!doc || !doc->frames.items) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++)
        total += doc->frames.items[i].payload_len;
    return total;
}

uint32_t apg_frames_max_payload(const APG_Document *doc) {
    if (!doc || !doc->frames.items) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++)
        if (doc->frames.items[i].payload_len > mx) mx = doc->frames.items[i].payload_len;
    return mx;
}

uint32_t apg_frames_non_empty_count(const APG_Document *doc) {
    if (!doc || !doc->frames.items) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++)
        if (doc->frames.items[i].payload_len > 0) n++;
    return n;
}

/* ---- frame mode statistics ---- */

typedef struct APG_FrameModeCount {
    uint32_t mode;
    uint32_t count;
} APG_FrameModeCount;

uint32_t apg_frames_mode_histogram(const APG_Document *doc,
                                    APG_FrameModeCount *out, uint32_t cap) {
    if (!doc || !doc->frames.items || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        uint32_t m = doc->frames.items[i].mode;
        uint32_t found = UINT32_MAX;
        for (uint32_t j = 0; j < n; j++) {
            if (out[j].mode == m) { found = j; break; }
        }
        if (found != UINT32_MAX) out[found].count++;
        else if (n < cap) { out[n].mode = m; out[n].count = 1; n++; }
    }
    return n;
}
