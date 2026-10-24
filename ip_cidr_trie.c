#include "ip_cidr_trie.h"

#include <limits.h>
#include <stdlib.h>

struct ip_cidr_trie_node {
    struct ip_cidr_trie_node *child[2];
    int terminal;
};

static ip_cidr_trie_node_t *node_create(void)
{
    return calloc(1, sizeof(ip_cidr_trie_node_t));
}

static void node_free(ip_cidr_trie_node_t *node)
{
    if (node == NULL) {
        return;
    }

    node_free(node->child[0]);
    node_free(node->child[1]);
    free(node);
}

static uint32_t prefix_mask(uint8_t prefix_len)
{
    if (prefix_len == 0) {
        return 0;
    }
    if (prefix_len == 32) {
        return UINT32_MAX;
    }
    return UINT32_MAX << (32 - prefix_len);
}

void ip_cidr_trie_init(ip_cidr_trie_t *trie)
{
    if (trie != NULL) {
        trie->root = NULL;
    }
}

void ip_cidr_trie_free(ip_cidr_trie_t *trie)
{
    if (trie == NULL) {
        return;
    }

    node_free(trie->root);
    trie->root = NULL;
}

int ip_cidr_trie_insert(ip_cidr_trie_t *trie, const ip_cidr_t *cidr)
{
    ip_cidr_trie_node_t *node;
    uint32_t network;

    if (trie == NULL || cidr == NULL || cidr->prefix_len > 32) {
        return 0;
    }

    if (trie->root == NULL) {
        trie->root = node_create();
        if (trie->root == NULL) {
            return 0;
        }
    }

    /* Normalize defensively, even though parsed ip_cidr_t values already are. */
    network = cidr->network & prefix_mask(cidr->prefix_len);
    node = trie->root;

    for (uint8_t bit = 0; bit < cidr->prefix_len; bit++) {
        unsigned int direction = (network >> (31 - bit)) & 1U;

        if (node->child[direction] == NULL) {
            node->child[direction] = node_create();
            if (node->child[direction] == NULL) {
                return 0;
            }
        }
        node = node->child[direction];
    }

    node->terminal = 1;
    return 1;
}

int ip_cidr_trie_build(ip_cidr_trie_t *trie, const ip_cidr_list_t *list)
{
    ip_cidr_trie_t built;

    if (trie == NULL || list == NULL) {
        return 0;
    }

    /* Build transactionally so an allocation failure does not damage trie. */
    ip_cidr_trie_init(&built);
    for (size_t i = 0; i < list->count; i++) {
        if (!ip_cidr_trie_insert(&built, &list->items[i])) {
            ip_cidr_trie_free(&built);
            return 0;
        }
    }

    ip_cidr_trie_free(trie);
    *trie = built;
    return 1;
}

int ip_cidr_trie_contains_address(const ip_cidr_trie_t *trie,
                                  uint32_t address)
{
    const ip_cidr_trie_node_t *node;

    if (trie == NULL || trie->root == NULL) {
        return 0;
    }

    node = trie->root;
    if (node->terminal) {
        return 1;
    }

    for (unsigned int bit = 0; bit < 32; bit++) {
        unsigned int direction = (address >> (31 - bit)) & 1U;

        node = node->child[direction];
        if (node == NULL) {
            return 0;
        }
        if (node->terminal) {
            return 1;
        }
    }

    return 0;
}
