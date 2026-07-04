
#include "internal.h"

int apg_parse_header(APG_Document *doc, const uint8_t *data, size_t size) {
    if (!doc || !data || size < 32) return 0;
    APG_Reader r;
    apg_reader_init(&r, data, size);
    doc->header.magic = apg_read_u32(&r);
    doc->header.version = apg_read_u16(&r);
    doc->header.directory_count = apg_read_u16(&r);
    doc->header.flags = apg_read_u32(&r);
    doc->header.directory_offset = apg_read_u32(&r);
    doc->header.file_id = apg_read_u32(&r);
    doc->header.timeline_seed = apg_read_u32(&r);
    doc->header.reserved_a = apg_read_u32(&r);
    doc->header.reserved_b = apg_read_u32(&r);
    if (r.failed || doc->header.magic != APG_MAGIC || doc->header.version != APG_VERSION) {
        apg_set_fatal(&doc->ctx, APG_ERR_FORMAT, "header is not an APG container");
        return 0;
    }
    if (doc->header.directory_count == 0 || doc->header.directory_count > APG_MAX_DIRECTORY) {
        apg_set_fatal(&doc->ctx, APG_ERR_RANGE, "directory count outside supported bounds");
        return 0;
    }
    if (doc->header.directory_offset < 32 || doc->header.directory_offset >= size) {
        apg_set_fatal(&doc->ctx, APG_ERR_RANGE, "directory offset outside input");
        return 0;
    }
    return 1;
}


/* ---- header comparison ---- */

int apg_header_match(const APG_Header *a, const APG_Header *b) {
    if (!a || !b) return 0;
    return a->magic == b->magic &&
           a->version == b->version &&
           a->directory_count == b->directory_count;
}

uint32_t apg_header_flags_popcount(const APG_Header *h) {
    if (!h) return 0;
    uint32_t flags = h->flags;
    uint32_t count = 0;
    while (flags) { count += flags & 1; flags >>= 1; }
    return count;
}
