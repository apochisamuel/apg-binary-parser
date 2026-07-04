
#include "internal.h"

/*
 * Compute a cross-section consistency score used to gate rollbacks.
 * The score depends on relationships between symbols, attrs, strings,
 * and directory entries — not any single field.
 */
static uint32_t apg_compute_section_affinity(APG_Document *doc) {
    uint32_t score = 0;
    if (!doc) return 0;

    /* Factor 1: symbol-to-attr ratio imbalance */
    if (doc->symbols.items && doc->attrs.items) {
        uint32_t sym_c = doc->symbols.count;
        uint32_t attr_c = doc->attrs.count;
        if (sym_c > 0 && attr_c > 0) {
            uint32_t ratio = sym_c > attr_c ? sym_c / attr_c : attr_c / sym_c;
            if (ratio > 3) score |= 0x01;
        }
    }

    /* Factor 2: directory link chain depth */
    if (doc->directory) {
        uint32_t chain = 0;
        uint32_t idx = 0;
        while (idx < doc->directory_count && chain < 16) {
            uint32_t link = doc->directory[idx].link;
            if (link >= doc->directory_count || link == UINT32_MAX) break;
            idx = link;
            chain++;
        }
        if (chain >= 3) score |= 0x02;
    }

    /* Factor 3: string weakness (empty or zero-length entries) */
    if (doc->strings.items) {
        uint32_t weak = 0;
        for (uint32_t i = 0; i < doc->strings.count; i++) {
            if (!doc->strings.items[i].data || doc->strings.items[i].length == 0)
                weak++;
        }
        if (doc->strings.count > 0 && weak * 4 >= doc->strings.count)
            score |= 0x04;
    }

    /* Factor 4: relocation section references */
    if (doc->relocs.items) {
        uint32_t string_refs = 0;
        for (uint32_t i = 0; i < doc->relocs.count; i++) {
            if (doc->relocs.items[i].section_index < doc->raw_count) {
                APG_RawSection *rs = &doc->raw_sections[doc->relocs.items[i].section_index];
                if (rs->type == APG_SECTION_STRINGS) string_refs++;
            }
        }
        if (string_refs > 0) score |= 0x08;
    }

    return score;
}

/*
 * Check if symbols reference attr entries with the sentinel value.
 * Returns the count of suspicious symbols whose attr has the marker.
 */
static uint32_t apg_count_suspicious_attrs(APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->attrs.items) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_Symbol *s = &doc->symbols.items[i];
        if (s->attr_index < doc->attrs.count) {
            APG_Attr *a = &doc->attrs.items[s->attr_index];
            if (a->value == 0xfeedfaceu) count++;
            /* Also count if attr flags have the rollback marker */
            if ((a->flags & 0xFF00) == 0xAB00) count++;
        }
    }
    return count;
}

/*
 * Validate symbols: rollback attr table only when BOTH:
 *   1. The flag is set AND suspicious attrs exist
 *   2. The section affinity score indicates cross-section imbalance
 */
static int apg_validate_symbols(APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 1;

    uint32_t suspicious = apg_count_suspicious_attrs(doc);
    uint32_t affinity = apg_compute_section_affinity(doc);

    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_Symbol *s = &doc->symbols.items[i];
        if (s->name_index >= doc->strings.count) {
            doc->warning_count++;
        }
    }

    /*
     * Gate the rollback on a conjunction: the flag must be set,
     * suspicious entries must exist, AND the affinity score
     * must indicate a ratio imbalance (bit 0) together with
     * either a directory chain (bit 1) or reloc refs (bit 3).
     */
    if ((doc->header.flags & APG_FLAG_ROLLBACK_ATTRS) && suspicious > 0) {
        if ((affinity & 0x01) && (affinity & (0x02 | 0x08))) {
            apg_rollback_attr_table(doc);
        }
    }
    return 1;
}

/*
 * Validate strings: rollback only when the flag is set AND
 * weak strings exist AND the affinity score has the string
 * weakness bit AND reloc references to string sections.
 */
static int apg_validate_strings(APG_Document *doc) {
    if (!doc || !doc->strings.items) return 1;

    uint32_t weak = 0;
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (!s->data || s->length == 0) weak++;
        if (s->length > 128u && (s->hash & 3u) == 0) doc->warning_count++;
    }

    uint32_t affinity = apg_compute_section_affinity(doc);

    if ((doc->header.flags & APG_FLAG_ROLLBACK_STRINGS) && weak > 0) {
        /* Require BOTH string weakness (bit 2) AND reloc refs (bit 3) */
        if ((affinity & 0x04) && (affinity & 0x08)) {
            apg_rollback_string_table(doc);
        }
    }
    return 1;
}

/*
 * Compute alias collision score: requires checking ID overlap
 * AND cross-referencing with keyframe name indices.
 */
static uint32_t apg_alias_collision_depth(APG_Document *doc) {
    if (!doc || !doc->aliases.items || doc->aliases.count < 2) return 0;

    uint32_t collisions = 0;
    for (uint32_t i = 1; i < doc->aliases.count; i++) {
        if (doc->aliases.items[i] && doc->aliases.items[i-1] &&
            doc->aliases.items[i]->id == doc->aliases.items[i-1]->id)
            collisions++;
    }

    /* Cross-reference: count alias IDs that match keyframe name indices */
    uint32_t cross_hits = 0;
    if (doc->keyframes.items) {
        for (uint32_t i = 0; i < doc->aliases.count; i++) {
            if (!doc->aliases.items[i]) continue;
            for (uint32_t k = 0; k < doc->keyframes.count; k++) {
                if (doc->keyframes.items[k].name_index == doc->aliases.items[i]->id) {
                    cross_hits++;
                    break;
                }
            }
        }
    }

    return collisions + cross_hits;
}

/*
 * Validate aliases: unwind only when flag is set AND collision
 * depth exceeds threshold AND directory link chain exists.
 */
static int apg_validate_aliases(APG_Document *doc) {
    if (!doc || !doc->aliases.items) return 1;

    uint32_t depth = apg_alias_collision_depth(doc);
    uint32_t affinity = apg_compute_section_affinity(doc);

    if ((doc->header.flags & APG_FLAG_ALIAS_UNWIND) && depth > 0) {
        /* Require directory chain (bit 1) for the unwind to fire */
        if (affinity & 0x02) {
            apg_unwind_alias_entries(doc);
        }
    }
    return 1;
}

/*
 * Validate keyframes: rollback when flag is set AND outliers
 * interact with frame count AND stream event totals.
 */
static int apg_validate_keyframes(APG_Document *doc) {
    if (!doc || !doc->keyframes.items) return 1;

    uint32_t outliers = 0;
    for (uint32_t i = 0; i < doc->keyframes.count; i++) {
        if (doc->keyframes.items[i].marker == 0xdecafbadu) outliers++;
        if (doc->frames.items &&
            doc->keyframes.items[i].frame_no >= doc->frames.count + 1024u)
            outliers++;
    }

    /* Compute stream event interaction */
    uint32_t stream_pressure = 0;
    if (doc->streams.items) {
        for (uint32_t i = 0; i < doc->streams.count; i++) {
            stream_pressure += doc->streams.items[i].event_count;
        }
    }

    if ((doc->header.flags & APG_FLAG_KEY_UNWIND) && outliers > 0) {
        /* Require stream pressure AND frame count alignment */
        if (stream_pressure > 0 && doc->frames.count > 0) {
            apg_rollback_keyframes(doc);
        }
    }
    return 1;
}

static int apg_validate_directory_links(APG_Document *doc) {
    if (!doc || !doc->directory) return 1;
    for (uint32_t i = 0; i < doc->directory_count; i++) {
        APG_DirectoryEntry *de = &doc->directory[i];
        if (de->link >= doc->directory_count && de->link != UINT32_MAX)
            doc->warning_count++;
        if (de->size == 0 && de->count != 0)
            doc->warning_count++;
    }
    return 1;
}

int apg_validate_document(APG_Document *doc) {
    if (!doc) return 0;
    int ok = 1;
    ok &= apg_validate_directory_links(doc);
    ok &= apg_validate_symbols(doc);
    ok &= apg_validate_strings(doc);
    ok &= apg_validate_aliases(doc);
    ok &= apg_validate_keyframes(doc);
    return ok;
}


/* ---- extended validation suite ---- */

static void apg_validate_string_refs(APG_Document *doc) {
    if (!doc->symbols.items || !doc->strings.items) return;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        uint32_t ni = doc->symbols.items[i].name_index;
        if (ni >= doc->strings.count) {
            doc->warning_count++;
            doc->symbols.items[i].name_ref = NULL;
        }
    }
}

static void apg_validate_attr_refs(APG_Document *doc) {
    if (!doc->symbols.items || !doc->attrs.items) return;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        uint32_t ai = doc->symbols.items[i].attr_index;
        if (ai >= doc->attrs.count) {
            doc->warning_count++;
            doc->symbols.items[i].cached_attr = NULL;
        }
    }
}

static void apg_validate_reloc_bounds(APG_Document *doc) {
    if (!doc->relocs.items) return;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        if (r->section_index >= doc->raw_count) {
            doc->warning_count++;
            r->resolved_hash = 0;
        }
        if (r->symbol_index >= doc->symbols.count) {
            doc->warning_count++;
        }
    }
}

static void apg_validate_frame_sizes(APG_Document *doc) {
    if (!doc->frames.items) return;
    for (uint32_t i = 0; i < doc->frames.count; i++) {
        APG_Frame *f = &doc->frames.items[i];
        if (f->payload_len > f->storage_len && f->storage_len > 0) {
            doc->warning_count++;
        }
    }
}

static void apg_validate_keyframe_ordering(APG_Document *doc) {
    if (!doc->keyframes.items || doc->keyframes.count < 2) return;
    for (uint32_t i = 1; i < doc->keyframes.count; i++) {
        if (doc->keyframes.items[i].frame_no < doc->keyframes.items[i-1].frame_no) {
            doc->warning_count++;
        }
    }
}

static void apg_validate_stream_keys(APG_Document *doc) {
    if (!doc->streams.items || !doc->keyframes.items) return;
    for (uint32_t i = 0; i < doc->streams.count; i++) {
        uint32_t ki = doc->streams.items[i].key_index;
        if (ki >= doc->keyframes.count) {
            doc->warning_count++;
        }
    }
}

uint32_t apg_validate_extended(APG_Document *doc) {
    if (!doc) return UINT32_MAX;
    uint32_t before = doc->warning_count;
    apg_validate_string_refs(doc);
    apg_validate_attr_refs(doc);
    apg_validate_reloc_bounds(doc);
    apg_validate_frame_sizes(doc);
    apg_validate_keyframe_ordering(doc);
    apg_validate_stream_keys(doc);
    return doc->warning_count - before;
}
