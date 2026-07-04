
#include "internal.h"

/*
 * format.c — APG format version detection and migration utilities.
 *
 * Handles differences between format versions, provides forward and
 * backward compatibility checks, and maps fields that moved between
 * versions.
 */

typedef struct APG_FormatInfo {
    uint16_t version;
    uint32_t min_header_size;
    uint32_t max_directory_entries;
    uint32_t max_section_size;
    uint32_t supported_section_types;
    int      has_keyframes;
    int      has_streams;
    int      has_aliases;
    int      has_relocations;
} APG_FormatInfo;

static APG_FormatInfo apg_format_v1(void) {
    APG_FormatInfo info = {0};
    info.version = 1;
    info.min_header_size = 32;
    info.max_directory_entries = APG_MAX_DIRECTORY;
    info.max_section_size = APG_MAX_SECTION_SIZE;
    info.supported_section_types = 0x1FF;  /* types 1-9 */
    info.has_keyframes = 1;
    info.has_streams = 1;
    info.has_aliases = 1;
    info.has_relocations = 1;
    return info;
}

APG_FormatInfo apg_format_detect(const uint8_t *data, size_t size) {
    APG_FormatInfo info = {0};
    if (!data || size < 32) return info;
    uint32_t magic = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (magic != APG_MAGIC) return info;
    uint16_t version = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    if (version == 1) return apg_format_v1();
    /* future versions would be handled here */
    info.version = version;
    return info;
}

int apg_format_compatible(uint16_t file_version, uint16_t lib_version) {
    /* v1 is only supported version */
    return file_version == lib_version;
}

/* ---- format validation ---- */

typedef struct APG_FormatError {
    const char *field;
    const char *message;
    uint32_t    offset;
} APG_FormatError;

uint32_t apg_format_validate(const uint8_t *data, size_t size,
                              APG_FormatError *errors, uint32_t cap) {
    uint32_t n = 0;
    if (!data || size < 32 || !errors) return 0;

    /* check magic */
    uint32_t magic = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    if (magic != APG_MAGIC && n < cap) {
        errors[n].field = "magic";
        errors[n].message = "invalid magic number";
        errors[n].offset = 0;
        n++;
    }

    /* check version */
    uint16_t version = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    if (version == 0 && n < cap) {
        errors[n].field = "version";
        errors[n].message = "version zero is reserved";
        errors[n].offset = 4;
        n++;
    }
    if (version > 1 && n < cap) {
        errors[n].field = "version";
        errors[n].message = "unsupported version";
        errors[n].offset = 4;
        n++;
    }

    /* check directory count */
    uint16_t dir_count = (uint16_t)data[6] | ((uint16_t)data[7] << 8);
    if (dir_count > APG_MAX_DIRECTORY && n < cap) {
        errors[n].field = "directory_count";
        errors[n].message = "exceeds maximum directory entries";
        errors[n].offset = 6;
        n++;
    }

    /* check directory offset */
    uint32_t dir_off = (uint32_t)data[12] | ((uint32_t)data[13] << 8) |
                       ((uint32_t)data[14] << 16) | ((uint32_t)data[15] << 24);
    if (dir_off > size && n < cap) {
        errors[n].field = "directory_offset";
        errors[n].message = "points beyond input";
        errors[n].offset = 12;
        n++;
    }

    /* check directory entries fit */
    size_t dir_end = (size_t)dir_off + (size_t)dir_count * 24;
    if (dir_end > size && n < cap) {
        errors[n].field = "directory";
        errors[n].message = "directory extends beyond input";
        errors[n].offset = dir_off;
        n++;
    }

    /* validate each directory entry */
    if (dir_end <= size) {
        for (uint16_t i = 0; i < dir_count && n < cap; i++) {
            size_t entry_off = (size_t)dir_off + (size_t)i * 24;
            uint32_t sec_off = (uint32_t)data[entry_off + 4] | ((uint32_t)data[entry_off + 5] << 8) |
                               ((uint32_t)data[entry_off + 6] << 16) | ((uint32_t)data[entry_off + 7] << 24);
            uint32_t sec_sz  = (uint32_t)data[entry_off + 8] | ((uint32_t)data[entry_off + 9] << 8) |
                               ((uint32_t)data[entry_off + 10] << 16) | ((uint32_t)data[entry_off + 11] << 24);
            if ((size_t)sec_off + sec_sz > size && n < cap) {
                errors[n].field = "section";
                errors[n].message = "section payload extends beyond input";
                errors[n].offset = (uint32_t)entry_off;
                n++;
            }
            if (sec_sz > APG_MAX_SECTION_SIZE && n < cap) {
                errors[n].field = "section_size";
                errors[n].message = "section exceeds maximum size";
                errors[n].offset = (uint32_t)entry_off;
                n++;
            }
        }
    }

    return n;
}

/* ---- format summary ---- */

typedef struct APG_FormatSummary {
    uint32_t magic;
    uint16_t version;
    uint16_t directory_count;
    uint32_t flags;
    uint32_t file_id;
    uint32_t total_payload;
    uint32_t validation_errors;
} APG_FormatSummary;

APG_FormatSummary apg_format_summarize(const uint8_t *data, size_t size) {
    APG_FormatSummary s = {0};
    if (!data || size < 32) return s;
    s.magic   = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    s.version = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    s.directory_count = (uint16_t)data[6] | ((uint16_t)data[7] << 8);
    s.flags   = (uint32_t)data[8] | ((uint32_t)data[9] << 8) |
                ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
    s.file_id = (uint32_t)data[16] | ((uint32_t)data[17] << 8) |
                ((uint32_t)data[18] << 16) | ((uint32_t)data[19] << 24);
    APG_FormatError errs[32];
    s.validation_errors = apg_format_validate(data, size, errs, 32);
    return s;
}


/* ---- raw header extraction without full parse ---- */

typedef struct APG_RawHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t directory_count;
    uint32_t flags;
    uint32_t directory_offset;
    uint32_t file_id;
    uint32_t timeline_seed;
    int      valid;
} APG_RawHeader;

APG_RawHeader apg_extract_raw_header(const uint8_t *data, size_t size) {
    APG_RawHeader h = {0};
    if (!data || size < 32) return h;
    h.magic   = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
    h.version = (uint16_t)data[4] | ((uint16_t)data[5] << 8);
    h.directory_count = (uint16_t)data[6] | ((uint16_t)data[7] << 8);
    h.flags   = (uint32_t)data[8] | ((uint32_t)data[9] << 8) |
                ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
    h.directory_offset = (uint32_t)data[12] | ((uint32_t)data[13] << 8) |
                         ((uint32_t)data[14] << 16) | ((uint32_t)data[15] << 24);
    h.file_id = (uint32_t)data[16] | ((uint32_t)data[17] << 8) |
                ((uint32_t)data[18] << 16) | ((uint32_t)data[19] << 24);
    h.timeline_seed = (uint32_t)data[20] | ((uint32_t)data[21] << 8) |
                      ((uint32_t)data[22] << 16) | ((uint32_t)data[23] << 24);
    h.valid = (h.magic == APG_MAGIC && h.version >= 1 && h.version <= 1);
    return h;
}

/* ---- flag name lookup ---- */

const char *apg_flag_name(uint32_t flag) {
    switch (flag) {
        case APG_FLAG_ROLLBACK_ATTRS:  return "ROLLBACK_ATTRS";
        case APG_FLAG_ROLLBACK_STRINGS: return "ROLLBACK_STRINGS";
        case APG_FLAG_KEY_UNWIND:      return "KEY_UNWIND";
        case APG_FLAG_ALIAS_UNWIND:    return "ALIAS_UNWIND";
        case APG_FLAG_FRAME_TRUST:     return "FRAME_TRUST";
        case APG_FLAG_TYPE_SWEEP:      return "TYPE_SWEEP";
        default:                       return "UNKNOWN";
    }
}

/* ---- active flag enumeration ---- */

uint32_t apg_enumerate_flags(uint32_t flags, const char **names, uint32_t cap) {
    uint32_t n = 0;
    uint32_t known[] = {
        APG_FLAG_ROLLBACK_ATTRS, APG_FLAG_ROLLBACK_STRINGS,
        APG_FLAG_KEY_UNWIND, APG_FLAG_ALIAS_UNWIND,
        APG_FLAG_FRAME_TRUST, APG_FLAG_TYPE_SWEEP
    };
    for (uint32_t i = 0; i < 6 && n < cap; i++) {
        if (flags & known[i]) {
            names[n++] = apg_flag_name(known[i]);
        }
    }
    return n;
}

/* ---- section type name lookup ---- */

const char *apg_section_name(uint16_t type) {
    switch (type) {
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
