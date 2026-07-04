
#include "internal.h"

uint32_t apg_resolve_symbol_names(APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t resolved = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        APG_Symbol *s = &doc->symbols.items[i];
        uint32_t attr_value = 0;
        if (s->cached_attr) attr_value = s->cached_attr->value ^ s->cached_attr->flags;
        if (s->name_ref && s->name_ref->data) {
            uint32_t score = apg_score_name(s->name_ref->data, s->name_ref->length);
            s->derived_score = apg_mix_u32(score, attr_value + s->aux);
            resolved++;
        } else {
            s->derived_score = apg_mix_u32(s->name_index, attr_value);
        }
    }
    return resolved;
}

int apg_resolve_document(APG_Document *doc) {
    if (!doc) return 0;
    uint32_t total = 0;
    total += apg_resolve_symbol_names(doc);
    total += apg_apply_relocations(doc);
    total += apg_reloc_post_validate(doc);
    total ^= apg_materialize_streams(doc);
    doc->summary_hash = apg_mix_u32(doc->summary_hash, total);
    return 1;
}


/* ---- resolution statistics ---- */

uint32_t apg_resolve_count_resolved(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        if (doc->symbols.items[i].name_ref && doc->symbols.items[i].name_ref->data) n++;
    return n;
}

uint32_t apg_resolve_count_with_attrs(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        if (doc->symbols.items[i].cached_attr) n++;
    return n;
}

uint32_t apg_resolve_max_score(const APG_Document *doc) {
    if (!doc || !doc->symbols.items) return 0;
    uint32_t mx = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        if (doc->symbols.items[i].derived_score > mx) mx = doc->symbols.items[i].derived_score;
    return mx;
}

double apg_resolve_avg_score(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->symbols.count) return 0.0;
    uint64_t total = 0;
    for (uint32_t i = 0; i < doc->symbols.count; i++)
        total += doc->symbols.items[i].derived_score;
    return (double)total / (double)doc->symbols.count;
}
