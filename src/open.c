
#include "internal.h"

static APG_Document *apg_document_new(void) {
    APG_Document *doc = (APG_Document *)calloc(1, sizeof(APG_Document));
    if (!doc) return NULL;
    apg_context_init(&doc->ctx);
    doc->symbols.directory_index = UINT32_MAX;
    doc->attrs.directory_index = UINT32_MAX;
    doc->strings.directory_index = UINT32_MAX;
    doc->relocs.directory_index = UINT32_MAX;
    doc->frames.directory_index = UINT32_MAX;
    doc->keyframes.directory_index = UINT32_MAX;
    doc->streams.directory_index = UINT32_MAX;
    return doc;
}

static int apg_parse_all(APG_Document *doc, const uint8_t *data, size_t size) {
    if (!apg_parse_header(doc, data, size)) return 0;
    if (!apg_parse_directory(doc, data, size)) return 0;
    if (!apg_capture_raw_sections(doc, data, size)) return 0;
    if (!apg_load_string_tables(doc)) return 0;
    if (!apg_parse_attributes(doc)) return 0;
    if (!apg_parse_symbols(doc)) return 0;
    if (!apg_parse_relocations(doc)) return 0;
    if (!apg_parse_frames(doc)) return 0;
    if (!apg_parse_keyframes(doc)) return 0;
    if (!apg_parse_streams(doc)) return 0;
    if (!apg_parse_aliases(doc)) return 0;
    if (!apg_validate_document(doc)) return 0;
    if (!apg_resolve_document(doc)) return 0;
    if (!apg_build_cache(doc)) return 0;
    return !apg_has_fatal(&doc->ctx);
}

APG_Document *apg_open_memory(const uint8_t *data, size_t size, uint32_t options) {
    (void)options;
    APG_Document *doc = apg_document_new();
    if (!doc) return NULL;
    if (!data || size < 32) {
        apg_set_fatal(&doc->ctx, APG_ERR_TRUNCATED, "input is shorter than header");
        return doc;
    }
    apg_parse_all(doc, data, size);
    return doc;
}

void apg_close(APG_Document *doc) {
    if (!doc) return;
    apg_free_cache(doc);
    apg_free_aliases(&doc->aliases);
    apg_free_streams(&doc->streams);
    apg_free_keyframes(&doc->keyframes);
    apg_free_frames(&doc->frames);
    apg_free_relocs(&doc->relocs);
    apg_free_symbols(&doc->symbols);
    apg_free_attrs(&doc->attrs);
    apg_free_strings(&doc->strings);
    if (doc->raw_sections) {
        for (uint32_t i = 0; i < doc->raw_count; i++) free(doc->raw_sections[i].data);
        free(doc->raw_sections);
    }
    free(doc->directory);
    free(doc);
}

uint32_t apg_document_symbol_count(const APG_Document *doc) { return doc ? doc->symbols.count : 0; }
uint32_t apg_document_stream_count(const APG_Document *doc) { return doc ? doc->streams.count : 0; }
uint32_t apg_document_frame_count(const APG_Document *doc) { return doc ? doc->frames.count : 0; }
uint32_t apg_document_warning_count(const APG_Document *doc) { return doc ? doc->warning_count : 0; }
uint32_t apg_document_summary_hash(const APG_Document *doc) { return doc ? doc->summary_hash ^ doc->cache.integrity_score : 0; }
int apg_document_error(const APG_Document *doc) { return doc ? doc->ctx.error_code : APG_ERR_FORMAT; }



/* ---- document count accessors ---- */

uint32_t apg_document_string_count(const APG_Document *doc) {
    return doc ? doc->strings.count : 0;
}

uint32_t apg_document_attr_count(const APG_Document *doc) {
    return doc ? doc->attrs.count : 0;
}

uint32_t apg_document_reloc_count(const APG_Document *doc) {
    return doc ? doc->relocs.count : 0;
}

uint32_t apg_document_keyframe_count(const APG_Document *doc) {
    return doc ? doc->keyframes.count : 0;
}

uint32_t apg_document_section_count(const APG_Document *doc) {
    return doc ? doc->raw_count : 0;
}

/* ---- open from buffer with pre-validation ---- */

APG_Document *apg_open_validated(const uint8_t *buf, size_t len, uint32_t flags) {
    if (!buf || len < 80) return NULL;
    uint32_t magic = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                     ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    if (magic != APG_MAGIC) return NULL;
    uint16_t version = (uint16_t)buf[4] | ((uint16_t)buf[5] << 8);
    if (version < 1 || version > 1) return NULL;
    return apg_open_memory(buf, len, flags);
}

/* ---- document summary hash ---- */

uint32_t apg_document_hash(const APG_Document *doc) {
    if (!doc) return 0;
    uint32_t h = doc->header.magic ^ doc->header.flags;
    h = apg_mix_u32(h, doc->symbols.count + doc->relocs.count);
    h = apg_mix_u32(h, doc->summary_hash);
    return h;
}
