#ifndef TEST
#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(void) {
    puts("Usage: myapp info <address>/<prefix>\n"
         "       myapp split <network>/<prefix> <count>\n"
         "       myapp lookup <table-file> <address>...");
}
static int info(const char *arg) {
    cidr_t block;
    if (!cidr_parse(arg, &block)) { fprintf(stderr, "myapp: invalid CIDR address: %s\n", arg); return 1; }
    char addr[IP_STR_LEN], mask[IP_STR_LEN], net[IP_STR_LEN], broadcast[IP_STR_LEN];
    char first[IP_STR_LEN], last[IP_STR_LEN];
    ip_format(block.addr, addr); ip_format(cidr_mask(block.prefix), mask);
    ip_format(cidr_network(block), net); ip_format(cidr_broadcast(block), broadcast);
    ip_format(cidr_first_host(block), first); ip_format(cidr_last_host(block), last);
    printf("address       %s\nprefix        /%u\nnetmask       %s\nnetwork       %s\n"
           "broadcast     %s\nfirst host    %s\nlast host     %s\nhosts         %" PRIu64 "\n",
           addr, (unsigned)block.prefix, mask, net, broadcast, first, last, cidr_host_count(block));
    return 0;
}
static int split(const char *arg, const char *count_arg) {
    cidr_t block;
    if (!cidr_parse(arg, &block) || !cidr_is_network(block)) {
        fprintf(stderr, "myapp: split requires a valid network CIDR: %s\n", arg); return 1;
    }
    if (!*count_arg || *count_arg == '-' || *count_arg == '+') {
        fprintf(stderr, "myapp: invalid subnet count: %s\n", count_arg); return 1;
    }
    for (const char *p = count_arg; *p; ++p) if (*p < '0' || *p > '9') {
        fprintf(stderr, "myapp: invalid subnet count: %s\n", count_arg); return 1;
    }
    errno = 0;
    unsigned long long value = strtoull(count_arg, NULL, 10);
    if (errno || !value || value > UINT32_MAX || (value & (value - 1))) {
        fprintf(stderr, "myapp: subnet count must be a power of two: %s\n", count_arg); return 1;
    }
    uint32_t n = (uint32_t)value;
    cidr_t sub;
    if (!cidr_subnet(block, n, 0, &sub)) {
        fprintf(stderr, "myapp: cannot split %s into %u subnets\n", arg, n); return 1;
    }
    for (uint32_t i = 0; i < n; ++i) {
        cidr_subnet(block, n, i, &sub);
        char output[CIDR_STR_LEN]; cidr_format(sub, output); puts(output);
    }
    return 0;
}
static int lookup(int argc, char **argv) {
    const char *filename = argv[2];
    FILE *in = fopen(filename, "r");
    if (!in) { fprintf(stderr, "myapp: cannot open %s: %s\n", filename, strerror(errno)); return 2; }
    fwd_table_t *table = table_create();
    if (!table) { fclose(in); fputs("myapp: out of memory\n", stderr); return 2; }
    size_t bad_line = 0;
    bool ok = table_load(table, in, &bad_line);
    int read_error = ferror(in);
    fclose(in);
    if (!ok) {
        if (bad_line) fprintf(stderr, "myapp: %s:%zu: not a valid route\n", filename, bad_line);
        else fprintf(stderr, "myapp: could not read %s%s\n", filename, read_error ? " (I/O error)" : "");
        table_destroy(table); return 2;
    }
    int status = 0;
    for (int i = 3; i < argc; ++i) {
        uint32_t dest;
        if (!ip_parse(argv[i], &dest)) {
            fprintf(stderr, "myapp: invalid IP address: %s\n", argv[i]); status = 1; continue;
        }
        const route_t *route = table_lookup(table, dest);
        if (!route) { printf("%s unreachable\n", argv[i]); if (!status) status = 3; continue; }
        if (route->gateway) {
            char gw[IP_STR_LEN]; ip_format(route->gateway, gw);
            printf("%s via %s dev %s\n", argv[i], gw, route->dev);
        } else printf("%s dev %s\n", argv[i], route->dev);
    }
    table_destroy(table);
    return status;
}
int main(int argc, char **argv) {
    if (argc == 1) { usage(); return 0; }
    if (!strcmp(argv[1], "info") && argc == 3) return info(argv[2]);
    if (!strcmp(argv[1], "split") && argc == 4) return split(argv[2], argv[3]);
    if (!strcmp(argv[1], "lookup") && argc >= 4) return lookup(argc, argv);
    fprintf(stderr, "myapp: invalid command line\n");
    usage(); return 1;
}

#endif /* !TEST */
