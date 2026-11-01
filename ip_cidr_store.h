#ifndef IP_CIDR_STORE_H
#define IP_CIDR_STORE_H

#include <stdint.h>

#include "ip_cidr.h"

typedef enum {
    IP_CIDR_STORE_LIST,
    IP_CIDR_STORE_TRIE,
    IP_CIDR_STORE_RADIX
} ip_cidr_store_kind_t;

typedef struct ip_cidr_store_ops {
    int (*init)(void *state);
    void (*free)(void *state);
    int (*insert)(void *state, const ip_cidr_t *cidr);
    int (*contains_address)(const void *state, uint32_t address);
} ip_cidr_store_ops_t;

typedef struct {
    ip_cidr_store_kind_t kind;
    const ip_cidr_store_ops_t *ops;
    void *state;
} ip_cidr_store_t;

int ip_cidr_store_init(ip_cidr_store_t *store,
                       ip_cidr_store_kind_t kind);
void ip_cidr_store_free(ip_cidr_store_t *store);

int ip_cidr_store_insert(ip_cidr_store_t *store,
                         const ip_cidr_t *cidr);

int ip_cidr_store_insert_callback(void *context,
                                  const ip_cidr_t *cidr);

int ip_cidr_store_parse(ip_cidr_store_t *store, const char *input);

int ip_cidr_store_contains_address(const ip_cidr_store_t *store,
                                   uint32_t address);

#endif
