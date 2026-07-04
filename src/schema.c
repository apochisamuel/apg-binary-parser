
#include "internal.h"

/*
 * schema.c — validate a parsed document against a constraint schema.
 *
 * A schema is a set of rules: required section types, symbol-count
 * bounds, attribute value constraints, string-length limits, and
 * cross-reference integrity checks.  Violations are accumulated in
 * an error list that callers can inspect after validation.
 */

typedef enum {
    APG_RULE_REQUIRE_SECTION,
    APG_RULE_FORBID_SECTION,
    APG_RULE_SYMBOL_COUNT_MIN,
    APG_RULE_SYMBOL_COUNT_MAX,
    APG_RULE_STRING_MAX_LEN,
    APG_RULE_ATTR_VALUE_MAX,
    APG_RULE_FRAME_SIZE_MAX,
    APG_RULE_NO_DANGLING_NAMES,
    APG_RULE_NO_DANGLING_ATTRS,
    APG_RULE_STREAM_HAS_KEYS,
    APG_RULE_RELOC_VALID_SECTION,
    APG_RULE_UNIQUE_ALIAS_IDS
} APG_RuleKind;

typedef struct APG_SchemaRule {
    APG_RuleKind kind;
    uint32_t     param;
} APG_SchemaRule;

typedef struct APG_SchemaError {
    APG_RuleKind rule;
    uint32_t     element_idx;
    const char  *message;
} APG_SchemaError;

struct APG_Schema {
    APG_SchemaRule *rules;
    uint32_t rule_count;
    uint32_t rule_cap;
    APG_SchemaError *errors;
    uint32_t error_count;
    uint32_t error_cap;
};

APG_Schema *apg_schema_create(void) {
    return (APG_Schema *)calloc(1, sizeof(APG_Schema));
}

static int apg_schema_add_rule(APG_Schema *s, APG_RuleKind kind, uint32_t param) {
    if (!s) return 0;
    if (s->rule_count == s->rule_cap) {
        uint32_t next = s->rule_cap ? s->rule_cap * 2 : 8;
        APG_SchemaRule *p = (APG_SchemaRule *)realloc(s->rules, (size_t)next * sizeof(APG_SchemaRule));
        if (!p) return 0;
        s->rules = p;
        s->rule_cap = next;
    }
    s->rules[s->rule_count].kind = kind;
    s->rules[s->rule_count].param = param;
    s->rule_count++;
    return 1;
}

void apg_schema_require_section(APG_Schema *s, uint16_t type) { apg_schema_add_rule(s, APG_RULE_REQUIRE_SECTION, type); }
void apg_schema_forbid_section(APG_Schema *s, uint16_t type)  { apg_schema_add_rule(s, APG_RULE_FORBID_SECTION, type); }
void apg_schema_symbol_count_min(APG_Schema *s, uint32_t n)   { apg_schema_add_rule(s, APG_RULE_SYMBOL_COUNT_MIN, n); }
void apg_schema_symbol_count_max(APG_Schema *s, uint32_t n)   { apg_schema_add_rule(s, APG_RULE_SYMBOL_COUNT_MAX, n); }
void apg_schema_string_max_len(APG_Schema *s, uint32_t n)     { apg_schema_add_rule(s, APG_RULE_STRING_MAX_LEN, n); }
void apg_schema_attr_value_max(APG_Schema *s, uint32_t n)     { apg_schema_add_rule(s, APG_RULE_ATTR_VALUE_MAX, n); }
void apg_schema_frame_size_max(APG_Schema *s, uint32_t n)     { apg_schema_add_rule(s, APG_RULE_FRAME_SIZE_MAX, n); }
void apg_schema_no_dangling_names(APG_Schema *s)  { apg_schema_add_rule(s, APG_RULE_NO_DANGLING_NAMES, 0); }
void apg_schema_no_dangling_attrs(APG_Schema *s)  { apg_schema_add_rule(s, APG_RULE_NO_DANGLING_ATTRS, 0); }
void apg_schema_stream_has_keys(APG_Schema *s)    { apg_schema_add_rule(s, APG_RULE_STREAM_HAS_KEYS, 0); }
void apg_schema_reloc_valid_section(APG_Schema *s) { apg_schema_add_rule(s, APG_RULE_RELOC_VALID_SECTION, 0); }
void apg_schema_unique_alias_ids(APG_Schema *s)   { apg_schema_add_rule(s, APG_RULE_UNIQUE_ALIAS_IDS, 0); }

static void apg_schema_error(APG_Schema *s, APG_RuleKind rule,
                              uint32_t idx, const char *msg) {
    if (s->error_count == s->error_cap) {
        uint32_t next = s->error_cap ? s->error_cap * 2 : 16;
        APG_SchemaError *p = (APG_SchemaError *)realloc(s->errors,
                              (size_t)next * sizeof(APG_SchemaError));
        if (!p) return;
        s->errors = p;
        s->error_cap = next;
    }
    APG_SchemaError *e = &s->errors[s->error_count++];
    e->rule = rule;
    e->element_idx = idx;
    e->message = msg;
}

/* ---- rule checkers ---- */

static void apg_check_require_section(APG_Schema *s, const APG_Document *doc, uint16_t type) {
    for (uint32_t i = 0; i < doc->raw_count; i++)
        if (doc->raw_sections[i].type == type) return;
    apg_schema_error(s, APG_RULE_REQUIRE_SECTION, type, "required section missing");
}

static void apg_check_forbid_section(APG_Schema *s, const APG_Document *doc, uint16_t type) {
    for (uint32_t i = 0; i < doc->raw_count; i++)
        if (doc->raw_sections[i].type == type)
            apg_schema_error(s, APG_RULE_FORBID_SECTION, i, "forbidden section present");
}

static void apg_check_dangling_names(APG_Schema *s, const APG_Document *doc) {
    if (!doc->symbols.items) return;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        if (doc->symbols.items[i].name_index >= doc->strings.count)
            apg_schema_error(s, APG_RULE_NO_DANGLING_NAMES, i, "symbol references nonexistent string");
    }
}

static void apg_check_dangling_attrs(APG_Schema *s, const APG_Document *doc) {
    if (!doc->symbols.items || !doc->attrs.items) return;
    for (uint32_t i = 0; i < doc->symbols.count; i++) {
        if (doc->symbols.items[i].attr_index >= doc->attrs.count)
            apg_schema_error(s, APG_RULE_NO_DANGLING_ATTRS, i, "symbol references nonexistent attr");
    }
}

static void apg_check_unique_alias_ids(APG_Schema *s, const APG_Document *doc) {
    if (!doc->aliases.items || doc->aliases.count < 2) return;
    for (uint32_t i = 0; i < doc->aliases.count; i++) {
        if (!doc->aliases.items[i]) continue;
        for (uint32_t j = i + 1; j < doc->aliases.count; j++) {
            if (!doc->aliases.items[j]) continue;
            if (doc->aliases.items[i]->id == doc->aliases.items[j]->id)
                apg_schema_error(s, APG_RULE_UNIQUE_ALIAS_IDS, j, "duplicate alias id");
        }
    }
}

static void apg_check_reloc_sections(APG_Schema *s, const APG_Document *doc) {
    if (!doc->relocs.items) return;
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        uint32_t si = doc->relocs.items[i].section_index;
        if (si >= doc->raw_count)
            apg_schema_error(s, APG_RULE_RELOC_VALID_SECTION, i, "reloc references invalid section");
    }
}

/* ---- main validate ---- */

uint32_t apg_schema_validate(APG_Schema *s, const APG_Document *doc) {
    if (!s || !doc) return UINT32_MAX;
    s->error_count = 0;
    for (uint32_t r = 0; r < s->rule_count; r++) {
        APG_SchemaRule *rule = &s->rules[r];
        switch (rule->kind) {
        case APG_RULE_REQUIRE_SECTION:
            apg_check_require_section(s, doc, (uint16_t)rule->param); break;
        case APG_RULE_FORBID_SECTION:
            apg_check_forbid_section(s, doc, (uint16_t)rule->param); break;
        case APG_RULE_SYMBOL_COUNT_MIN:
            if (doc->symbols.count < rule->param)
                apg_schema_error(s, rule->kind, doc->symbols.count, "too few symbols");
            break;
        case APG_RULE_SYMBOL_COUNT_MAX:
            if (doc->symbols.count > rule->param)
                apg_schema_error(s, rule->kind, doc->symbols.count, "too many symbols");
            break;
        case APG_RULE_STRING_MAX_LEN:
            for (uint32_t i = 0; i < doc->strings.count; i++)
                if (doc->strings.items[i].length > rule->param)
                    apg_schema_error(s, rule->kind, i, "string too long");
            break;
        case APG_RULE_ATTR_VALUE_MAX:
            for (uint32_t i = 0; i < doc->attrs.count; i++)
                if (doc->attrs.items[i].value > rule->param)
                    apg_schema_error(s, rule->kind, i, "attr value exceeds limit");
            break;
        case APG_RULE_FRAME_SIZE_MAX:
            for (uint32_t i = 0; i < doc->frames.count; i++)
                if (doc->frames.items[i].payload_len > rule->param)
                    apg_schema_error(s, rule->kind, i, "frame too large");
            break;
        case APG_RULE_NO_DANGLING_NAMES:  apg_check_dangling_names(s, doc); break;
        case APG_RULE_NO_DANGLING_ATTRS:  apg_check_dangling_attrs(s, doc); break;
        case APG_RULE_STREAM_HAS_KEYS:
            if (doc->streams.count && !doc->keyframes.count)
                apg_schema_error(s, rule->kind, 0, "streams present but no keyframes");
            break;
        case APG_RULE_RELOC_VALID_SECTION: apg_check_reloc_sections(s, doc); break;
        case APG_RULE_UNIQUE_ALIAS_IDS:   apg_check_unique_alias_ids(s, doc); break;
        }
    }
    return s->error_count;
}

uint32_t apg_schema_error_count(const APG_Schema *s) { return s ? s->error_count : 0; }

const char *apg_schema_error_message(const APG_Schema *s, uint32_t idx) {
    if (!s || idx >= s->error_count) return NULL;
    return s->errors[idx].message;
}

void apg_schema_free(APG_Schema *s) {
    if (!s) return;
    free(s->rules);
    free(s->errors);
    free(s);
}


/* ---- schema presets ---- */

APG_Schema *apg_schema_strict(void) {
    APG_Schema *s = apg_schema_create();
    if (!s) return NULL;
    apg_schema_require_section(s, APG_SECTION_STRINGS);
    apg_schema_require_section(s, APG_SECTION_SYMBOLS);
    apg_schema_no_dangling_names(s);
    apg_schema_no_dangling_attrs(s);
    apg_schema_reloc_valid_section(s);
    apg_schema_unique_alias_ids(s);
    apg_schema_symbol_count_min(s, 1);
    apg_schema_string_max_len(s, 65535);
    apg_schema_frame_size_max(s, APG_MAX_SECTION_SIZE);
    return s;
}

APG_Schema *apg_schema_permissive(void) {
    APG_Schema *s = apg_schema_create();
    if (!s) return NULL;
    apg_schema_require_section(s, APG_SECTION_STRINGS);
    apg_schema_no_dangling_names(s);
    return s;
}

/* ---- batch validate ---- */

int apg_schema_is_valid(APG_Schema *s, const APG_Document *doc) {
    uint32_t errs = apg_schema_validate(s, doc);
    return errs == 0;
}

/* ---- error detail ---- */

uint32_t apg_schema_error_element(const APG_Schema *s, uint32_t idx) {
    if (!s || idx >= s->error_count) return UINT32_MAX;
    return s->errors[idx].element_idx;
}
