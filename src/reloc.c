
#include "internal.h"

typedef struct APG_DiskSymbol {
    uint32_t name_index;
    uint32_t attr_index;
    uint16_t klass;
    uint16_t flags;
    uint32_t aux;
} APG_DiskSymbol;

int apg_parse_relocations(APG_Document *doc) {
    APG_RawSection *rs = apg_find_raw_section(doc, APG_SECTION_RELOCS);
    if (!rs) return 1;
    APG_Reader r;
    apg_reader_init(&r, rs->data, rs->size);
    uint32_t count = apg_read_u32(&r);
    if (r.failed || count > 4096u) {
        apg_set_error(&doc->ctx, APG_ERR_RANGE, "relocation count outside limits");
        return 0;
    }
    doc->relocs.items = (APG_Reloc *)calloc(count ? count : 1u, sizeof(APG_Reloc));
    if (!doc->relocs.items) {
        apg_set_fatal(&doc->ctx, APG_ERR_ALLOC, "relocation allocation failed");
        return 0;
    }
    doc->relocs.count = count;
    for (uint32_t i = 0; i < doc->raw_count; i++) if (&doc->raw_sections[i] == rs) doc->relocs.directory_index = i;
    for (uint32_t i = 0; i < count; i++) {
        doc->relocs.items[i].section_index = apg_read_u32(&r);
        doc->relocs.items[i].symbol_index = apg_read_u32(&r);
        doc->relocs.items[i].target = apg_read_u32(&r);
        doc->relocs.items[i].flags = apg_read_u32(&r);
        if (r.failed) {
            apg_set_error(&doc->ctx, APG_ERR_TRUNCATED, "relocation entry is truncated");
            return 0;
        }
    }
    return 1;
}

void apg_free_relocs(APG_RelocTable *tab) {
    if (!tab || !tab->items) return;
    free(tab->items);
    tab->items = NULL;
    tab->count = 0;
}

static APG_RawSection *apg_select_relocation_symbol_source(APG_Document *doc, const APG_Reloc *rel) {
    if (!doc || !rel) return NULL;
    return apg_directory_validate_reloc_source(doc, rel->section_index);
}

/*
 * Resolve relocation entries against source section data.
 *
 * The resolution walks the relocation table, locates the source
 * section via directory validation, computes an element budget
 * from the directory entry's aux field (when present), and uses
 * that budget as the bounds limit for symbol indexing.
 *
 * BUG: When the TYPE_SWEEP flag is set, the source section is
 * accepted regardless of type. In that path, the element budget
 * is computed from the directory entry's 'count' field rather
 * than the actual section data size. A crafted input can set
 * count to a large value while the section data is small,
 * causing the symbol_index check to pass against 'count' but
 * the actual array access to go out of bounds.
 */
uint32_t apg_apply_relocations(APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t applied = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *rel = &doc->relocs.items[i];
        APG_RawSection *source = apg_select_relocation_symbol_source(doc, rel);
        if (!source || source->size < 4) continue;

        /* Compute element budget from directory metadata.
         * When TYPE_SWEEP is active, the directory entry's count
         * field is used as the budget. This is the intended design
         * for sweep mode, but the count field comes from the input
         * and may not reflect the actual data size. */
        uint32_t budget = (source->size - 4u) / (uint32_t)sizeof(APG_DiskSymbol);
        if (doc->header.flags & APG_FLAG_TYPE_SWEEP) {
            const APG_DirectoryEntry *de = NULL;
            for (uint32_t d = 0; d < doc->directory_count; d++) {
                if (doc->directory[d].offset == source->offset) {
                    de = &doc->directory[d];
                    break;
                }
            }
            if (de && de->count > 0) {
                budget = de->count;  /* BUG: trusts input count field */
            }
        }
        if (rel->symbol_index >= budget) continue;

        APG_DiskSymbol *disk = (APG_DiskSymbol *)(void *)(source->data + 4u);
        APG_DiskSymbol pick = disk[rel->symbol_index];
        uint32_t h = apg_mix_u32(pick.name_index, pick.aux ^ rel->target);
        rel->resolved_hash = h;
        applied += (h != 0);
    }
    return applied;
}

uint32_t apg_reloc_post_validate(APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t valid = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        if (doc->relocs.items[i].resolved_hash != 0) valid++;
    }
    return valid;
}


/* ---- relocation analysis ---- */

uint32_t apg_reloc_unresolved_count(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++)
        if (doc->relocs.items[i].resolved_hash == 0) n++;
    return n;
}

uint32_t apg_reloc_resolved_count(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    return doc->relocs.count - apg_reloc_unresolved_count(doc);
}

uint32_t apg_reloc_distinct_sections(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t secs[64];
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].section_index;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) if (secs[j] == si) { found = 1; break; }
        if (!found && n < 64) secs[n++] = si;
    }
    return n;
}

uint32_t apg_reloc_max_target(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++)
        if (doc->relocs.items[i].target > mx) mx = doc->relocs.items[i].target;
    return mx;
}

uint32_t apg_reloc_distinct_symbols(const APG_Document *doc) {
    if (!doc || !doc->relocs.items) return 0;
    uint32_t syms[256];
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].symbol_index;
        int found = 0;
        for (uint32_t j = 0; j < n; j++) if (syms[j] == si) { found = 1; break; }
        if (!found && n < 256) syms[n++] = si;
    }
    return n;
}
