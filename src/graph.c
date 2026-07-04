
#include "internal.h"

/*
 * graph.c — relocation dependency graph with cycle detection.
 *
 * Builds an adjacency-list graph where each symbol that appears as a
 * relocation target gets an edge from the source symbol.  Provides
 * topological sort and DFS-based cycle detection.
 */

typedef struct APG_AdjNode {
    uint32_t target;
    struct APG_AdjNode *next;
} APG_AdjNode;

typedef struct APG_Graph {
    APG_AdjNode **adj;       /* adj[i] = head of adjacency list for node i */
    uint32_t      node_count;
    uint8_t      *visited;   /* DFS bookkeeping */
    uint8_t      *on_stack;
    uint32_t     *topo;      /* topological order output */
    uint32_t      topo_len;
    int           has_cycle;
} APG_Graph;

APG_Graph *apg_graph_build(const APG_Document *doc) {
    if (!doc || !doc->symbols.items || !doc->relocs.items) return NULL;
    uint32_t n = doc->symbols.count;
    APG_Graph *g = (APG_Graph *)calloc(1, sizeof(APG_Graph));
    if (!g) return NULL;
    g->node_count = n;
    g->adj = (APG_AdjNode **)calloc(n, sizeof(APG_AdjNode *));
    g->visited  = (uint8_t *)calloc(n, 1);
    g->on_stack = (uint8_t *)calloc(n, 1);
    g->topo     = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!g->adj || !g->visited || !g->on_stack || !g->topo) {
        apg_graph_free(g);
        return NULL;
    }
    /* Add edges from relocations.  Each relocation connects
       rel->symbol_index → target-symbol implied by rel->target. */
    for (uint32_t i = 0; i < doc->relocs.count; i++) {
        APG_Reloc *r = &doc->relocs.items[i];
        uint32_t src = r->symbol_index;
        uint32_t dst = r->target % n;
        if (src >= n) continue;
        APG_AdjNode *node = (APG_AdjNode *)calloc(1, sizeof(APG_AdjNode));
        if (!node) continue;
        node->target = dst;
        node->next = g->adj[src];
        g->adj[src] = node;
    }
    return g;
}

/* ---- DFS with cycle detection ---- */
static void apg_graph_dfs(APG_Graph *g, uint32_t u) {
    g->visited[u]  = 1;
    g->on_stack[u] = 1;
    APG_AdjNode *cur = g->adj[u];
    while (cur) {
        uint32_t v = cur->target;
        if (!g->visited[v]) {
            apg_graph_dfs(g, v);
        } else if (g->on_stack[v]) {
            g->has_cycle = 1;
        }
        cur = cur->next;
    }
    g->on_stack[u] = 0;
    g->topo[g->topo_len++] = u;
}

int apg_graph_detect_cycles(APG_Graph *g) {
    if (!g) return 0;
    memset(g->visited,  0, g->node_count);
    memset(g->on_stack, 0, g->node_count);
    g->topo_len = 0;
    g->has_cycle = 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        if (!g->visited[i]) apg_graph_dfs(g, i);
    }
    return g->has_cycle;
}

const uint32_t *apg_graph_topo_order(const APG_Graph *g, uint32_t *out_len) {
    if (!g || !g->topo_len) { if (out_len) *out_len = 0; return NULL; }
    if (out_len) *out_len = g->topo_len;
    return g->topo;
}

uint32_t apg_graph_edge_count(const APG_Graph *g) {
    if (!g) return 0;
    uint32_t total = 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        APG_AdjNode *cur = g->adj[i];
        while (cur) { total++; cur = cur->next; }
    }
    return total;
}

/* ---- in-degree computation (for scheduling) ---- */
uint32_t *apg_graph_in_degrees(const APG_Graph *g) {
    if (!g) return NULL;
    uint32_t *deg = (uint32_t *)calloc(g->node_count, sizeof(uint32_t));
    if (!deg) return NULL;
    for (uint32_t i = 0; i < g->node_count; i++) {
        APG_AdjNode *cur = g->adj[i];
        while (cur) { deg[cur->target]++; cur = cur->next; }
    }
    return deg;
}

void apg_graph_free(APG_Graph *g) {
    if (!g) return;
    if (g->adj) {
        for (uint32_t i = 0; i < g->node_count; i++) {
            APG_AdjNode *cur = g->adj[i];
            while (cur) { APG_AdjNode *nxt = cur->next; free(cur); cur = nxt; }
        }
        free(g->adj);
    }
    free(g->visited);
    free(g->on_stack);
    free(g->topo);
    free(g);
}


/* ---- connected components via union-find ---- */

typedef struct APG_UnionFind {
    uint32_t *parent;
    uint32_t *rank;
    uint32_t  size;
} APG_UnionFind;

static APG_UnionFind *uf_create(uint32_t n) {
    APG_UnionFind *uf = (APG_UnionFind *)calloc(1, sizeof(APG_UnionFind));
    if (!uf) return NULL;
    uf->size = n;
    uf->parent = (uint32_t *)malloc(n * sizeof(uint32_t));
    uf->rank   = (uint32_t *)calloc(n, sizeof(uint32_t));
    if (!uf->parent || !uf->rank) { free(uf->parent); free(uf->rank); free(uf); return NULL; }
    for (uint32_t i = 0; i < n; i++) uf->parent[i] = i;
    return uf;
}

static uint32_t uf_find(APG_UnionFind *uf, uint32_t x) {
    while (uf->parent[x] != x) {
        uf->parent[x] = uf->parent[uf->parent[x]];
        x = uf->parent[x];
    }
    return x;
}

static void uf_union(APG_UnionFind *uf, uint32_t a, uint32_t b) {
    a = uf_find(uf, a);
    b = uf_find(uf, b);
    if (a == b) return;
    if (uf->rank[a] < uf->rank[b]) { uint32_t t = a; a = b; b = t; }
    uf->parent[b] = a;
    if (uf->rank[a] == uf->rank[b]) uf->rank[a]++;
}

static void uf_free(APG_UnionFind *uf) {
    if (!uf) return;
    free(uf->parent);
    free(uf->rank);
    free(uf);
}

uint32_t apg_graph_connected_components(const APG_Graph *g) {
    if (!g || !g->node_count) return 0;
    APG_UnionFind *uf = uf_create(g->node_count);
    if (!uf) return 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        APG_AdjNode *cur = g->adj[i];
        while (cur) {
            uf_union(uf, i, cur->target);
            cur = cur->next;
        }
    }
    /* count unique roots */
    uint32_t count = 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        if (uf_find(uf, i) == i) count++;
    }
    uf_free(uf);
    return count;
}

/* ---- BFS shortest path (unweighted) ---- */

uint32_t apg_graph_shortest_path(const APG_Graph *g, uint32_t src, uint32_t dst) {
    if (!g || src >= g->node_count || dst >= g->node_count) return UINT32_MAX;
    if (src == dst) return 0;
    uint32_t *dist = (uint32_t *)malloc(g->node_count * sizeof(uint32_t));
    uint32_t *queue = (uint32_t *)malloc(g->node_count * sizeof(uint32_t));
    if (!dist || !queue) { free(dist); free(queue); return UINT32_MAX; }
    for (uint32_t i = 0; i < g->node_count; i++) dist[i] = UINT32_MAX;
    dist[src] = 0;
    uint32_t qh = 0, qt = 0;
    queue[qt++] = src;
    while (qh < qt) {
        uint32_t u = queue[qh++];
        APG_AdjNode *cur = g->adj[u];
        while (cur) {
            if (dist[cur->target] == UINT32_MAX) {
                dist[cur->target] = dist[u] + 1;
                if (cur->target == dst) {
                    uint32_t result = dist[dst];
                    free(dist); free(queue);
                    return result;
                }
                queue[qt++] = cur->target;
            }
            cur = cur->next;
        }
    }
    free(dist); free(queue);
    return UINT32_MAX;
}

/* ---- graph density ---- */
double apg_graph_density(const APG_Graph *g) {
    if (!g || g->node_count < 2) return 0.0;
    uint32_t edges = apg_graph_edge_count(g);
    double max_edges = (double)g->node_count * (double)(g->node_count - 1);
    return (double)edges / max_edges;
}


/* ---- reverse adjacency (incoming edges) ---- */

uint32_t apg_graph_incoming(const APG_Graph *g, uint32_t node,
                             uint32_t *out, uint32_t cap) {
    if (!g || node >= g->node_count || !out) return 0;
    uint32_t n = 0;
    for (uint32_t i = 0; i < g->node_count && n < cap; i++) {
        APG_AdjNode *cur = g->adj[i];
        while (cur) {
            if (cur->target == node) { out[n++] = i; break; }
            cur = cur->next;
        }
    }
    return n;
}

/* ---- leaf nodes (no outgoing edges) ---- */

uint32_t apg_graph_leaf_count(const APG_Graph *g) {
    if (!g) return 0;
    uint32_t leaves = 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        if (!g->adj[i]) leaves++;
    }
    return leaves;
}

/* ---- root nodes (no incoming edges) ---- */

uint32_t apg_graph_root_count(const APG_Graph *g) {
    if (!g) return 0;
    uint32_t *indeg = apg_graph_in_degrees(g);
    if (!indeg) return 0;
    uint32_t roots = 0;
    for (uint32_t i = 0; i < g->node_count; i++)
        if (indeg[i] == 0) roots++;
    free(indeg);
    return roots;
}

/* ---- max out-degree ---- */

uint32_t apg_graph_max_out_degree(const APG_Graph *g) {
    if (!g) return 0;
    uint32_t max_d = 0;
    for (uint32_t i = 0; i < g->node_count; i++) {
        uint32_t d = 0;
        APG_AdjNode *cur = g->adj[i];
        while (cur) { d++; cur = cur->next; }
        if (d > max_d) max_d = d;
    }
    return max_d;
}

/* ---- DFS visit order ---- */

uint32_t apg_graph_dfs_order(const APG_Graph *g, uint32_t start,
                              uint32_t *out, uint32_t cap) {
    if (!g || start >= g->node_count || !out) return 0;
    uint8_t *seen = (uint8_t *)calloc(g->node_count, 1);
    uint32_t *stack = (uint32_t *)malloc(g->node_count * sizeof(uint32_t));
    if (!seen || !stack) { free(seen); free(stack); return 0; }
    uint32_t sp = 0, n = 0;
    stack[sp++] = start;
    while (sp > 0 && n < cap) {
        uint32_t u = stack[--sp];
        if (seen[u]) continue;
        seen[u] = 1;
        out[n++] = u;
        /* push neighbors in reverse order so first neighbor is visited first */
        APG_AdjNode *cur = g->adj[u];
        uint32_t nbuf[256];
        uint32_t nc = 0;
        while (cur && nc < 256) { nbuf[nc++] = cur->target; cur = cur->next; }
        for (uint32_t i = nc; i-- > 0; ) {
            if (!seen[nbuf[i]]) stack[sp++] = nbuf[i];
        }
    }
    free(seen);
    free(stack);
    return n;
}
