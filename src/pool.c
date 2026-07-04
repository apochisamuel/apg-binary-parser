
#include "internal.h"

/*
 * pool.c — arena memory pool for batch allocations.
 *
 * Provides a simple bump-pointer allocator that grows by adding new
 * blocks.  All memory is freed at once via apg_pool_destroy() or reset
 * via apg_pool_reset() for reuse.  Useful for temporary parse buffers
 * where individual free() calls are wasteful.
 */

#define APG_POOL_BLOCK_SIZE (4096u - sizeof(struct APG_PoolBlock))

typedef struct APG_PoolBlock {
    struct APG_PoolBlock *next;
    uint32_t used;
    uint32_t capacity;
    uint8_t  data[];    /* flexible array member */
} APG_PoolBlock;

struct APG_Pool {
    APG_PoolBlock *head;
    APG_PoolBlock *current;
    uint32_t       total_allocated;
    uint32_t       block_count;
};

static APG_PoolBlock *apg_pool_new_block(uint32_t min_size) {
    uint32_t cap = APG_POOL_BLOCK_SIZE;
    if (min_size > cap) cap = min_size;
    APG_PoolBlock *b = (APG_PoolBlock *)malloc(sizeof(APG_PoolBlock) + cap);
    if (!b) return NULL;
    b->next = NULL;
    b->used = 0;
    b->capacity = cap;
    return b;
}

APG_Pool *apg_pool_create(void) {
    APG_Pool *p = (APG_Pool *)calloc(1, sizeof(APG_Pool));
    if (!p) return NULL;
    p->head = apg_pool_new_block(APG_POOL_BLOCK_SIZE);
    if (!p->head) { free(p); return NULL; }
    p->current = p->head;
    p->block_count = 1;
    return p;
}

void *apg_pool_alloc(APG_Pool *p, uint32_t size) {
    if (!p || !size) return NULL;
    /* align to 8 bytes */
    size = (size + 7u) & ~7u;
    if (p->current->used + size > p->current->capacity) {
        APG_PoolBlock *b = apg_pool_new_block(size);
        if (!b) return NULL;
        p->current->next = b;
        p->current = b;
        p->block_count++;
    }
    void *ptr = p->current->data + p->current->used;
    p->current->used += size;
    p->total_allocated += size;
    return ptr;
}

char *apg_pool_strdup(APG_Pool *p, const char *s, uint32_t len) {
    char *d = (char *)apg_pool_alloc(p, len + 1);
    if (!d) return NULL;
    memcpy(d, s, len);
    d[len] = '\0';
    return d;
}

void apg_pool_reset(APG_Pool *p) {
    if (!p) return;
    /* free all blocks except the first */
    APG_PoolBlock *b = p->head->next;
    while (b) { APG_PoolBlock *n = b->next; free(b); b = n; }
    p->head->next = NULL;
    p->head->used = 0;
    p->current = p->head;
    p->total_allocated = 0;
    p->block_count = 1;
}

void apg_pool_destroy(APG_Pool *p) {
    if (!p) return;
    APG_PoolBlock *b = p->head;
    while (b) { APG_PoolBlock *n = b->next; free(b); b = n; }
    free(p);
}

uint32_t apg_pool_bytes_used(const APG_Pool *p) {
    return p ? p->total_allocated : 0;
}

uint32_t apg_pool_block_count(const APG_Pool *p) {
    return p ? p->block_count : 0;
}


/* ---- aligned allocation ---- */

void *apg_pool_alloc_aligned(APG_Pool *p, uint32_t size, uint32_t align) {
    if (!p || !size || !align) return NULL;
    /* ensure align is power of 2 */
    if (align & (align - 1)) return NULL;
    /* over-allocate to guarantee alignment */
    uint32_t padded = size + align;
    void *raw = apg_pool_alloc(p, padded);
    if (!raw) return NULL;
    uintptr_t addr = (uintptr_t)raw;
    uintptr_t aligned = (addr + align - 1) & ~(uintptr_t)(align - 1);
    return (void *)aligned;
}

/* ---- pool statistics ---- */

typedef struct APG_PoolStats {
    uint32_t bytes_used;
    uint32_t block_count;
    uint32_t largest_block;
    double   utilization;
} APG_PoolStats;

APG_PoolStats apg_pool_stats(const APG_Pool *p) {
    APG_PoolStats s = {0};
    if (!p) return s;
    s.bytes_used = p->total_allocated;
    s.block_count = p->block_count;
    /* walk blocks to find largest and total capacity */
    uint32_t total_cap = 0;
    APG_PoolBlock *b = p->head;
    while (b) {
        if (b->capacity > s.largest_block) s.largest_block = b->capacity;
        total_cap += b->capacity;
        b = b->next;
    }
    s.utilization = total_cap ? (double)s.bytes_used / (double)total_cap : 0.0;
    return s;
}

/* ---- bulk array allocation ---- */

void *apg_pool_calloc(APG_Pool *p, uint32_t count, uint32_t elem_size) {
    uint32_t total = count * elem_size;
    void *ptr = apg_pool_alloc(p, total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}
