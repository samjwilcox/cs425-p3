#ifndef LAB_H
#define LAB_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
/* Every address is a uint32_t in host byte order, with first octet most significant. */
#define IP_STR_LEN 16
#define CIDR_STR_LEN 19
#define DEV_NAME_LEN 16
typedef struct { uint32_t addr; uint8_t prefix; } cidr_t;
typedef struct { cidr_t dest; uint32_t gateway; char dev[DEV_NAME_LEN]; } route_t;
typedef struct fwd_table fwd_table_t;
bool ip_parse(const char *text, uint32_t *addr);
void ip_format(uint32_t addr, char out[IP_STR_LEN]);
bool cidr_parse(const char *text, cidr_t *block);
void cidr_format(cidr_t block, char out[CIDR_STR_LEN]);
uint32_t cidr_mask(uint8_t prefix);
uint32_t cidr_network(cidr_t block);
uint32_t cidr_broadcast(cidr_t block);
uint32_t cidr_first_host(cidr_t block);
uint32_t cidr_last_host(cidr_t block);
uint64_t cidr_host_count(cidr_t block);
bool cidr_contains(cidr_t block, uint32_t addr);
bool cidr_is_network(cidr_t block);
bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out);
bool route_parse(const char *line, route_t *route);
fwd_table_t *table_create(void);
void table_destroy(fwd_table_t *table);
size_t table_count(const fwd_table_t *table);
bool table_add(fwd_table_t *table, const route_t *route);
bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line);
const route_t *table_lookup(const fwd_table_t *table, uint32_t dest);
#endif // LAB_H
