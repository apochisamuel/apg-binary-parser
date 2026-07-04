
#include "internal.h"

static int apg_directory_region_ok(size_t input_size, uint32_t off, uint32_t len) {
    if (off > input_size) return 0;
    if (len > input_size - off) return 0;
    if (len > APG_MAX_SECTION_SIZE) return 0;
    return 1;
}

APG_DirectoryEntry *apg_directory_mut(APG_Document *doc, uint32_t idx) {
    if (!doc || idx >= doc->directory_count) return NULL;
    return &doc->directory[idx];
}

const APG_DirectoryEntry *apg_directory_by_type(const APG_Document *doc, uint16_t type) {
    if (!doc || !doc->directory) return NULL;
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        if (doc->directory[i].type == type) return &doc->directory[i];
    }
    return NULL;
}

APG_RawSection *apg_raw_section_by_index(APG_Document *doc, uint32_t index) {
    if (!doc || index >= doc->raw_count) return NULL;
    return &doc->raw_sections[index];
}

APG_RawSection *apg_find_raw_section(APG_Document *doc, uint16_t type) {
    if (!doc || !doc->raw_sections) return NULL;
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        if (doc->raw_sections[i].type == type) return &doc->raw_sections[i];
    }
    return NULL;
}

APG_RawSection *apg_directory_validate_reloc_source(APG_Document *doc, uint32_t index) {
    APG_RawSection *rs = apg_raw_section_by_index(doc, index);
    if (!rs) return NULL;
    if (doc->header.flags & APG_FLAG_TYPE_SWEEP) return rs;
    if (rs->type != APG_SECTION_SYMBOLS) return NULL;
    return rs;
}

uint32_t apg_directory_frame_budget(const APG_Document *doc,
                                    const APG_DirectoryEntry *de,
                                    uint32_t payload_len) {
    if (!doc || !de) return payload_len;
    uint32_t budget = de->aux;
    if (!(doc->header.flags & APG_FLAG_FRAME_TRUST)) {
        if (payload_len > budget) budget = payload_len;
    }
    return budget;
}

int apg_parse_directory(APG_Document *doc, const uint8_t *data, size_t size) {
    if (!doc || !data) return 0;
    APG_Reader r;
    apg_reader_init(&r, data, size);
    if (!apg_reader_seek(&r, doc->header.directory_offset)) return 0;
    doc->directory_count = doc->header.directory_count;
    doc->directory = (APG_DirectoryEntry *)calloc(doc->directory_count, sizeof(APG_DirectoryEntry));
    if (!doc->directory) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "directory allocation failed");
        return 0;
    }
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        APG_DirectoryEntry *e = &doc->directory[i];
        e->type = apg_read_u16(&r);
        e->subtype = apg_read_u16(&r);
        e->offset = apg_read_u32(&r);
        e->size = apg_read_u32(&r);
        e->aux = apg_read_u32(&r);
        e->link = apg_read_u32(&r);
        e->count = apg_read_u32(&r);
        if (r.failed || !apg_directory_region_ok(size, e->offset, e->size)) {
            apg_set_fatal(&doc->ctx, APG_ERR_RANGE, "directory entry points outside input");
            return 0;
        }
    }
    return 1;
}

int apg_capture_raw_sections(APG_Document *doc, const uint8_t *data, size_t size) {
    if (!doc || !data || !doc->directory) return 0;
    doc->raw_count = doc->directory_count;
    doc->raw_sections = (APG_RawSection *)calloc(doc->raw_count, sizeof(APG_RawSection));
    if (!doc->raw_sections) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "raw section allocation failed");
        return 0;
    }
    for (uint32_t i = 0; i < doc->raw_count; i++) {
        const APG_DirectoryEntry *de = &doc->directory[i];
        APG_RawSection *rs = &doc->raw_sections[i];
        rs->type = de->type;
        rs->subtype = de->subtype;
        rs->offset = de->offset;
        rs->size = de->size;
        if (de->size) {
            rs->data = (uint8_t *)malloc(de->size);
            if (!rs->data) {
                apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "raw payload allocation failed");
                return 0;
            }
            memcpy(rs->data, data + de->offset, de->size);
        }
        (void)size;
    }
    return 1;
}


/* ---- directory analysis ---- */

uint32_t apg_directory_total_size(const APG_Document *doc) {
    if (!doc || !doc->directory) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < doc->directory_count; i++)
        total += doc->directory[i].size;
    return total;
}

uint32_t apg_directory_max_section(const APG_Document *doc) {
    if (!doc || !doc->directory) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->directory_count; i++)
        if (doc->directory[i].size > mx) mx = doc->directory[i].size;
    return mx;
}

/* ---- directory entry lookup by type ---- */

int apg_directory_find_type(const APG_Document *doc, uint16_t type, uint32_t *out_idx) {
    if (!doc || !doc->directory) return 0;
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        if (doc->directory[i].type == type) {
            if (out_idx) *out_idx = i;
            return 1;
        }
    }
    return 0;
}

/* ---- check if sections are contiguous ---- */

int apg_directory_is_contiguous(const APG_Document *doc) {
    if (!doc || !doc->directory || doc->directory_count < 2) return 1;
    for (uint32_t i = 1; i < doc->directory_count; i++) {
        uint32_t prev_end = doc->directory[i-1].offset + doc->directory[i-1].size;
        if (doc->directory[i].offset != prev_end) return 0;
    }
    return 1;
}

/* ---- directory gap analysis ---- */

uint32_t apg_directory_gap_bytes(const APG_Document *doc) {
    if (!doc || !doc->directory || doc->directory_count < 2) return 0;
    uint32_t gaps = 0;
    for (uint32_t i = 1; i < doc->directory_count; i++) {
        uint32_t prev_end = doc->directory[i-1].offset + doc->directory[i-1].size;
        if (doc->directory[i].offset > prev_end)
            gaps += doc->directory[i].offset - prev_end;
    }
    return gaps;
}
