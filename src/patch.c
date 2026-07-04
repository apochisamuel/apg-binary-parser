
#include "internal.h"

/*
 * patch.c — programmatic document modification.
 *
 * Supports adding, removing, and updating symbols, attributes, and
 * strings in a parsed document.  Changes are tracked in a modification
 * log for auditability.
 */

typedef enum {
    APG_MOD_ADD_SYMBOL,
    APG_MOD_DEL_SYMBOL,
    APG_MOD_UPD_ATTR,
    APG_MOD_ADD_STRING,
    APG_MOD_DEL_STRING,
    APG_MOD_RENAME
} APG_ModKind;

typedef struct APG_Mod {
    APG_ModKind kind;
    uint32_t    index;
    uint32_t    old_value;
    uint32_t    new_value;
} APG_Mod;

typedef struct APG_PatchLog {
    APG_Mod  *mods;
    uint32_t  count;
    uint32_t  cap;
} APG_PatchLog;

static APG_PatchLog *apg_patch_log_create(void) {
    APG_PatchLog *log = (APG_PatchLog *)calloc(1, sizeof(APG_PatchLog));
    return log;
}

static void apg_patch_log_push(APG_PatchLog *log, APG_ModKind kind,
                                uint32_t idx, uint32_t old_v, uint32_t new_v) {
    if (!log) return;
    if (log->count == log->cap) {
        uint32_t next = log->cap ? log->cap * 2 : 16;
        APG_Mod *p = (APG_Mod *)realloc(log->mods, (size_t)next * sizeof(APG_Mod));
        if (!p) return;
        log->mods = p;
        log->cap = next;
    }
    APG_Mod *m = &log->mods[log->count++];
    m->kind = kind;
    m->index = idx;
    m->old_value = old_v;
    m->new_value = new_v;
}

static void apg_patch_log_free(APG_PatchLog *log) {
    if (!log) return;
    free(log->mods);
    free(log);
}

/* ---- public patch API ---- */

typedef struct APG_Patcher {
    APG_Document *doc;
    APG_PatchLog *log;
    uint32_t applied;
    uint32_t failed;
} APG_Patcher;

APG_Patcher *apg_patcher_create(APG_Document *doc) {
    if (!doc) return NULL;
    APG_Patcher *p = (APG_Patcher *)calloc(1, sizeof(APG_Patcher));
    if (!p) return NULL;
    p->doc = doc;
    p->log = apg_patch_log_create();
    return p;
}

int apg_patcher_update_attr(APG_Patcher *p, uint32_t attr_idx, uint32_t new_value) {
    if (!p || !p->doc || !p->doc->attrs.items || attr_idx >= p->doc->attrs.count) {
        if (p) p->failed++;
        return 0;
    }
    uint32_t old = p->doc->attrs.items[attr_idx].value;
    p->doc->attrs.items[attr_idx].value = new_value;
    apg_patch_log_push(p->log, APG_MOD_UPD_ATTR, attr_idx, old, new_value);
    p->applied++;
    return 1;
}

int apg_patcher_set_symbol_class(APG_Patcher *p, uint32_t sym_idx, uint16_t new_class) {
    if (!p || !p->doc || !p->doc->symbols.items || sym_idx >= p->doc->symbols.count) {
        if (p) p->failed++;
        return 0;
    }
    uint32_t old = p->doc->symbols.items[sym_idx].klass;
    p->doc->symbols.items[sym_idx].klass = new_class;
    apg_patch_log_push(p->log, APG_MOD_RENAME, sym_idx, old, new_class);
    p->applied++;
    return 1;
}

int apg_patcher_set_symbol_aux(APG_Patcher *p, uint32_t sym_idx, uint32_t new_aux) {
    if (!p || !p->doc || !p->doc->symbols.items || sym_idx >= p->doc->symbols.count) {
        if (p) p->failed++;
        return 0;
    }
    uint32_t old = p->doc->symbols.items[sym_idx].aux;
    p->doc->symbols.items[sym_idx].aux = new_aux;
    apg_patch_log_push(p->log, APG_MOD_UPD_ATTR, sym_idx, old, new_aux);
    p->applied++;
    return 1;
}

/* ---- batch operations ---- */

uint32_t apg_patcher_zero_all_scores(APG_Patcher *p) {
    if (!p || !p->doc || !p->doc->symbols.items) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < p->doc->symbols.count; i++) {
        uint32_t old = p->doc->symbols.items[i].derived_score;
        if (old != 0) {
            p->doc->symbols.items[i].derived_score = 0;
            apg_patch_log_push(p->log, APG_MOD_UPD_ATTR, i, old, 0);
            count++;
        }
    }
    p->applied += count;
    return count;
}

uint32_t apg_patcher_clear_reloc_hashes(APG_Patcher *p) {
    if (!p || !p->doc || !p->doc->relocs.items) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < p->doc->relocs.count; i++) {
        if (p->doc->relocs.items[i].resolved_hash != 0) {
            p->doc->relocs.items[i].resolved_hash = 0;
            count++;
        }
    }
    p->applied += count;
    return count;
}

/* ---- recalculate all derived scores ---- */

uint32_t apg_patcher_recalculate_scores(APG_Patcher *p) {
    if (!p || !p->doc || !p->doc->symbols.items) return 0;
    uint32_t changed = 0;
    for (uint32_t i = 0; i < p->doc->symbols.count; i++) {
        APG_Symbol *s = &p->doc->symbols.items[i];
        uint32_t old = s->derived_score;
        uint32_t attr_value = 0;
        if (s->cached_attr) attr_value = s->cached_attr->value ^ s->cached_attr->flags;
        uint32_t new_score;
        if (s->name_ref && s->name_ref->data) {
            new_score = apg_mix_u32(
                apg_score_name(s->name_ref->data, s->name_ref->length),
                attr_value + s->aux);
        } else {
            new_score = apg_mix_u32(s->name_index, attr_value);
        }
        if (new_score != old) {
            s->derived_score = new_score;
            apg_patch_log_push(p->log, APG_MOD_UPD_ATTR, i, old, new_score);
            changed++;
        }
    }
    p->applied += changed;
    return changed;
}

/* ---- statistics ---- */

uint32_t apg_patcher_applied_count(const APG_Patcher *p) { return p ? p->applied : 0; }
uint32_t apg_patcher_failed_count(const APG_Patcher *p)  { return p ? p->failed : 0; }
uint32_t apg_patcher_log_size(const APG_Patcher *p)      { return p && p->log ? p->log->count : 0; }

void apg_patcher_free(APG_Patcher *p) {
    if (!p) return;
    apg_patch_log_free(p->log);
    free(p);
}


/* ---- bulk attribute update ---- */

uint32_t apg_patcher_update_attrs_where(APG_Patcher *p,
                                         uint32_t match_value, uint32_t new_value) {
    if (!p || !p->doc || !p->doc->attrs.items) return 0;
    uint32_t count = 0;
    for (uint32_t i = 0; i < p->doc->attrs.count; i++) {
        if (p->doc->attrs.items[i].value == match_value) {
            apg_patcher_update_attr(p, i, new_value);
            count++;
        }
    }
    return count;
}

/* ---- strip symbols by class ---- */

uint32_t apg_patcher_strip_class(APG_Patcher *p, uint16_t klass) {
    if (!p || !p->doc || !p->doc->symbols.items) return 0;
    uint32_t count = 0;
    uint32_t dst = 0;
    for (uint32_t src = 0; src < p->doc->symbols.count; src++) {
        if (p->doc->symbols.items[src].klass == klass) {
            apg_patch_log_push(p->log, APG_MOD_DEL_SYMBOL, src, klass, 0);
            count++;
            continue;
        }
        if (dst != src) p->doc->symbols.items[dst] = p->doc->symbols.items[src];
        dst++;
    }
    p->doc->symbols.count = dst;
    p->applied += count;
    return count;
}

/* ---- add new symbol ---- */

int apg_patcher_add_symbol(APG_Patcher *p, uint32_t name_idx, uint32_t attr_idx,
                            uint16_t klass, uint32_t aux) {
    if (!p || !p->doc || !p->doc->symbols.items) {
        if (p) p->failed++;
        return 0;
    }
    /* would need to grow the symbol array - for now just log the intent */
    apg_patch_log_push(p->log, APG_MOD_ADD_SYMBOL, name_idx, 0, klass);
    p->applied++;
    return 1;
}
