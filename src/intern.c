
#include "internal.h"

/*
 * intern.c — hash-based string interning table.
 *
 * Strings are stored once and looked up by hash.  Interning eliminates
 * duplicate storage and enables O(1) equality checks via pointer
 * comparison.  The table uses open addressing with linear probing.
 */

#define APG_INTERN_INIT_CAP 128u
#define APG_INTERN_LOAD_MAX 70   /* percent */

typedef struct APG_InternSlot {
    char    *data;
    uint32_t length;
    uint32_t hash;
    int      occupied;
} APG_InternSlot;

struct APG_Intern {
    APG_InternSlot *slots;
    uint32_t capacity;
    uint32_t count;
    uint32_t collisions;
};

static uint32_t apg_intern_hash(const char *s, uint32_t len) {
    uint32_t h = 0x811c9dc5u;
    for (uint32_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 0x01000193u;
    }
    return h;
}

APG_Intern *apg_intern_create(void) {
    APG_Intern *t = (APG_Intern *)calloc(1, sizeof(APG_Intern));
    if (!t) return NULL;
    t->capacity = APG_INTERN_INIT_CAP;
    t->slots = (APG_InternSlot *)calloc(t->capacity, sizeof(APG_InternSlot));
    if (!t->slots) { free(t); return NULL; }
    return t;
}

static int apg_intern_grow(APG_Intern *t) {
    uint32_t new_cap = t->capacity * 2;
    APG_InternSlot *new_slots = (APG_InternSlot *)calloc(new_cap, sizeof(APG_InternSlot));
    if (!new_slots) return 0;
    /* re-insert all existing entries */
    for (uint32_t i = 0; i < t->capacity; i++) {
        if (!t->slots[i].occupied) continue;
        uint32_t idx = t->slots[i].hash % new_cap;
        while (new_slots[idx].occupied) idx = (idx + 1) % new_cap;
        new_slots[idx] = t->slots[i];
    }
    free(t->slots);
    t->slots = new_slots;
    t->capacity = new_cap;
    return 1;
}

const char *apg_intern_insert(APG_Intern *t, const char *s, uint32_t len) {
    if (!t || !s) return NULL;
    /* check load factor */
    if (t->count * 100 >= t->capacity * APG_INTERN_LOAD_MAX) {
        if (!apg_intern_grow(t)) return NULL;
    }
    uint32_t h = apg_intern_hash(s, len);
    uint32_t idx = h % t->capacity;
    while (t->slots[idx].occupied) {
        APG_InternSlot *slot = &t->slots[idx];
        if (slot->hash == h && slot->length == len) {
            int eq = 1;
            for (uint32_t i = 0; i < len; i++) {
                if (slot->data[i] != s[i]) { eq = 0; break; }
            }
            if (eq) return slot->data;  /* already interned */
        }
        t->collisions++;
        idx = (idx + 1) % t->capacity;
    }
    /* insert new */
    char *copy = (char *)malloc(len + 1);
    if (!copy) return NULL;
    memcpy(copy, s, len);
    copy[len] = '\0';
    t->slots[idx].data = copy;
    t->slots[idx].length = len;
    t->slots[idx].hash = h;
    t->slots[idx].occupied = 1;
    t->count++;
    return copy;
}

const char *apg_intern_lookup(const APG_Intern *t, const char *s, uint32_t len) {
    if (!t || !s) return NULL;
    uint32_t h = apg_intern_hash(s, len);
    uint32_t idx = h % t->capacity;
    uint32_t probes = 0;
    while (t->slots[idx].occupied && probes < t->capacity) {
        const APG_InternSlot *slot = &t->slots[idx];
        if (slot->hash == h && slot->length == len) {
            int eq = 1;
            for (uint32_t i = 0; i < len; i++) {
                if (slot->data[i] != s[i]) { eq = 0; break; }
            }
            if (eq) return slot->data;
        }
        idx = (idx + 1) % t->capacity;
        probes++;
    }
    return NULL;
}

/* intern all strings from a document */
uint32_t apg_intern_document_strings(APG_Intern *t, const APG_Document *doc) {
    if (!t || !doc || !doc->strings.items) return 0;
    uint32_t interned = 0;
    for (uint32_t i = 0; i < doc->strings.count; i++) {
        APG_String *s = &doc->strings.items[i];
        if (s->data && s->length) {
            const char *p = apg_intern_insert(t, s->data, s->length);
            if (p && p != s->data) interned++;
        }
    }
    return interned;
}

uint32_t apg_intern_count(const APG_Intern *t) { return t ? t->count : 0; }
uint32_t apg_intern_collisions(const APG_Intern *t) { return t ? t->collisions : 0; }

double apg_intern_load_factor(const APG_Intern *t) {
    if (!t || !t->capacity) return 0.0;
    return (double)t->count / (double)t->capacity;
}

void apg_intern_free(APG_Intern *t) {
    if (!t) return;
    for (uint32_t i = 0; i < t->capacity; i++) {
        if (t->slots[i].occupied) free(t->slots[i].data);
    }
    free(t->slots);
    free(t);
}


/* ---- batch intern from raw buffer ---- */

uint32_t apg_intern_bulk(APG_Intern *t, const char *data, uint32_t len,
                          char separator) {
    if (!t || !data) return 0;
    uint32_t count = 0;
    uint32_t start = 0;
    for (uint32_t i = 0; i <= len; i++) {
        if (i == len || data[i] == separator) {
            if (i > start) {
                apg_intern_insert(t, data + start, i - start);
                count++;
            }
            start = i + 1;
        }
    }
    return count;
}

/* ---- export interned strings ---- */

uint32_t apg_intern_export(const APG_Intern *t, const char **out, uint32_t cap) {
    if (!t || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < t->capacity && n < cap; i++) {
        if (t->slots[i].occupied)
            out[n++] = t->slots[i].data;
    }
    return n;
}

/* ---- total bytes stored ---- */

uint32_t apg_intern_total_bytes(const APG_Intern *t) {
    if (!t) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < t->capacity; i++) {
        if (t->slots[i].occupied) total += t->slots[i].length;
    }
    return total;
}
