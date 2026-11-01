#ifndef IP_CIDR_RADIX_H
#define IP_CIDR_RADIX_H

#include <stdint.h>

#include "ip_cidr.h"

typedef struct ip_cidr_radix_node ip_cidr_radix_node_t;

typedef struct {
    ip_cidr_radix_node_t *root;
} ip_cidr_radix_t;

/* Initialize an empty compressed binary radix trie. */
void ip_cidr_radix_init(ip_cidr_radix_t *radix);

/* Release all nodes owned by the radix trie. */
void ip_cidr_radix_free(ip_cidr_radix_t *radix);

/* Insert an already-parsed and normalized CIDR. */
int ip_cidr_radix_insert(ip_cidr_radix_t *radix, const ip_cidr_t *cidr);

/* Look up a numeric IPv4 address in the radix trie. */
int ip_cidr_radix_contains_address(const ip_cidr_radix_t *radix,
                                   uint32_t address);

#endif
