#ifndef IP_CIDR_TRIE_H
#define IP_CIDR_TRIE_H

#include <stdint.h>

#include "ip_cidr.h"

typedef struct ip_cidr_trie_node ip_cidr_trie_node_t;

typedef struct {
    ip_cidr_trie_node_t *root;
} ip_cidr_trie_t;

/* Initialize an empty trie. */
void ip_cidr_trie_init(ip_cidr_trie_t *trie);

/* Release all nodes owned by the trie and return it to the empty state. */
void ip_cidr_trie_free(ip_cidr_trie_t *trie);

/*
 * Insert an already-parsed and normalized CIDR.
 *
 * The CIDR's network and prefix_len fields are used; no text parsing occurs
 * in this function. Returns 1 on success and 0 on invalid input or allocation
 * failure.
 */
int ip_cidr_trie_insert(ip_cidr_trie_t *trie, const ip_cidr_t *cidr);

/* Build a trie from an existing parsed CIDR list. */
int ip_cidr_trie_build(ip_cidr_trie_t *trie, const ip_cidr_list_t *list);

/* Look up a numeric IPv4 address in the trie. */
int ip_cidr_trie_contains_address(const ip_cidr_trie_t *trie,
                                  uint32_t address);

#endif
