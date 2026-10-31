#define _POSIX_C_SOURCE 200809L
#include "lab.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table { route_t *routes; size_t count, capacity; };

/* No octal notation, signs, whitespace, suffixes or empty octets. */
bool ip_parse(const char *text, uint32_t *addr) {
    if (!text || !addr) return false;
    const char *p = text;
    uint32_t result = 0;
    for (unsigned i = 0; i < 4; ++i) {
        if (*p < '0' || *p > '9') return false;
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
        unsigned octet = 0;
        do {
            octet = octet * 10u + (unsigned)(*p - '0');
            if (octet > 255u) return false;
            ++p;
        } while (*p >= '0' && *p <= '9');
        result = (result << 8) | octet;
        if (i != 3) {
            if (*p != '.') return false;
            ++p;
        } else if (*p != '\0') return false;
    }
    *addr = result;
    return true;
}
void ip_format(uint32_t addr, char out[IP_STR_LEN]) {
    snprintf(out, IP_STR_LEN, "%u.%u.%u.%u", (unsigned)(addr >> 24),
        (unsigned)((addr >> 16) & 255u), (unsigned)((addr >> 8) & 255u), (unsigned)(addr & 255u));
}
bool cidr_parse(const char *text, cidr_t *block) {
    if (!text || !block) return false;
    const char *slash = strchr(text, '/');
    if (!slash || slash == text || strchr(slash + 1, '/')) return false;
    size_t len = (size_t)(slash - text);
    if (len >= IP_STR_LEN) return false;
    char ip[IP_STR_LEN];
    memcpy(ip, text, len); ip[len] = '\0';
    uint32_t addr;
    if (!ip_parse(ip, &addr)) return false;
    const char *p = slash + 1;
    if (*p < '0' || *p > '9') return false;
    if (*p == '0' && p[1] != '\0') return false;
    unsigned prefix = 0;
    while (*p >= '0' && *p <= '9') {
        prefix = prefix * 10u + (unsigned)(*p++ - '0');
        if (prefix > 32u) return false;
    }
    if (*p) return false;
    cidr_t parsed = {addr, (uint8_t)prefix};
    *block = parsed;
    return true;
}
void cidr_format(cidr_t block, char out[CIDR_STR_LEN]) {
    char ip[IP_STR_LEN]; ip_format(block.addr, ip);
    snprintf(out, CIDR_STR_LEN, "%s/%u", ip, (unsigned)(block.prefix > 32 ? 32 : block.prefix));
}
uint32_t cidr_mask(uint8_t prefix) {
    if (!prefix) return 0;
    if (prefix >= 32) return UINT32_MAX;
    return UINT32_MAX << (32u - prefix);
}
uint32_t cidr_network(cidr_t block) { return block.addr & cidr_mask(block.prefix); }
uint32_t cidr_broadcast(cidr_t block) { return block.addr | ~cidr_mask(block.prefix); }
uint32_t cidr_first_host(cidr_t block) { return cidr_network(block) + (block.prefix < 31); }
uint32_t cidr_last_host(cidr_t block) { return cidr_broadcast(block) - (block.prefix < 31); }
uint64_t cidr_host_count(cidr_t block) {
    if (block.prefix >= 32) return 1;
    if (block.prefix == 31) return 2;
    return (UINT64_C(1) << (32u - block.prefix)) - 2;
}
bool cidr_contains(cidr_t block, uint32_t addr) {
    uint32_t mask = cidr_mask(block.prefix);
    return (addr & mask) == (block.addr & mask);
}
bool cidr_is_network(cidr_t block) { return block.addr == cidr_network(block); }
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out) {
    if (!out || !cidr_is_network(block) || !n || (n & (n - 1)) || i >= n) return false;
    uint8_t prefix = block.prefix > 32 ? 32 : block.prefix;
    unsigned extra = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++extra;
    if (extra > 32u - prefix) return false;
    unsigned next = prefix + extra;
    uint64_t size = UINT64_C(1) << (32u - next);
    cidr_t result = {(uint32_t)((uint64_t)block.addr + size * i), (uint8_t)next};
    *out = result;
    return true;
}

/* Tokenize a private copy to leave callers' buffers untouched. */
bool route_parse(const char *line, route_t *route) {
    if (!line || !route) return false;
    const char *p = line;
    const char *parts[3]; size_t lens[3];
    for (int i = 0; i < 3; ++i) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\v' || *p == '\f') ++p;
        if (!*p) return false;
        parts[i] = p;
        while (*p && !isspace((unsigned char)*p)) ++p;
        lens[i] = (size_t)(p - parts[i]);
    }
    while (*p && isspace((unsigned char)*p)) ++p;
    if (*p || lens[0] >= CIDR_STR_LEN || lens[1] >= IP_STR_LEN || lens[2] == 0 || lens[2] >= DEV_NAME_LEN) return false;
    char dst[CIDR_STR_LEN], gw[IP_STR_LEN];
    memcpy(dst, parts[0], lens[0]); dst[lens[0]] = '\0';
    memcpy(gw, parts[1], lens[1]); gw[lens[1]] = '\0';
    route_t parsed = {0};
    if (!strcmp(dst, "default")) parsed.dest = (cidr_t){0, 0};
    else if (!cidr_parse(dst, &parsed.dest) || !cidr_is_network(parsed.dest)) return false;
    if (strcmp(gw, "direct") && !ip_parse(gw, &parsed.gateway)) return false;
    memcpy(parsed.dev, parts[2], lens[2]); parsed.dev[lens[2]] = '\0';
    *route = parsed;
    return true;
}
fwd_table_t *table_create(void) { return calloc(1, sizeof(fwd_table_t)); }
void table_destroy(fwd_table_t *table) {
    if (!table) return;
    free(table->routes); free(table);
}
size_t table_count(const fwd_table_t *table) { return table ? table->count : 0; }
bool table_add(fwd_table_t *table, const route_t *route) {
    if (!table || !route || !cidr_is_network(route->dest)) return false;
    for (size_t i = 0; i < table->count; ++i) {
        cidr_t d = table->routes[i].dest;
        if (d.addr == route->dest.addr && d.prefix == route->dest.prefix) return false;
    }
    if (table->count == table->capacity) {
        size_t next = table->capacity ? table->capacity * 2 : 8;
        if (next < table->capacity || next > SIZE_MAX / sizeof(route_t)) return false;
        route_t *grown = realloc(table->routes, next * sizeof(route_t));
        if (!grown) return false;
        table->routes = grown; table->capacity = next;
    }
    table->routes[table->count++] = *route;
    return true;
}
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line) {
    if (bad_line) *bad_line = 0;
    if (!table || !in) return false;
    char *line = NULL; size_t capacity = 0, number = 0;
    ssize_t len;
    while ((len = getline(&line, &capacity, in)) != -1) {
        (void)len;
        ++number;
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';
        const char *p = line;
        while (*p && isspace((unsigned char)*p)) ++p;
        if (!*p) continue;
        route_t route;
        if (!route_parse(p, &route) || !table_add(table, &route)) {
            if (bad_line) *bad_line = number;
            free(line); return false;
        }
    }
    bool ok = !ferror(in);
    free(line);
    return ok;
}
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest) {
    if (!table) return NULL;
    const route_t *best = NULL;
    for (size_t i = 0; i < table->count; ++i) {
        const route_t *r = &table->routes[i];
        if (cidr_contains(r->dest, dest) && (!best || r->dest.prefix > best->dest.prefix)) best = r;
    }
    return best;
}
