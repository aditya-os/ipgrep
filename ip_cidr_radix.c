#include "ip_cidr_radix.h"

#include <limits.h>
#include <stdlib.h>

struct ip_cidr_radix_node {
    uint32_t network;
    uint8_t prefix_len;
    int terminal;
    struct ip_cidr_radix_node *child[2];
};

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

static uint32_t normalized_network(uint32_t network, uint8_t prefix_len)
{
    return network & prefix_mask(prefix_len);
}

static unsigned int bit_at(uint32_t value, uint8_t bit)
{
    return (value >> (31 - bit)) & 1U;
}

static int prefix_matches(uint32_t address,
                          uint32_t network,
                          uint8_t prefix_len)
{
    return (address & prefix_mask(prefix_len)) == network;
}

/* Return the number of equal leading bits in two prefixes. */
static uint8_t common_prefix_len(uint32_t left,
                                 uint8_t left_len,
                                 uint32_t right,
                                 uint8_t right_len)
{
    uint8_t limit = left_len < right_len ? left_len : right_len;
    uint8_t common = 0;

    while (common < limit && bit_at(left, common) == bit_at(right, common)) {
        common++;
    }
    return common;
}

static ip_cidr_radix_node_t *node_create(uint32_t network,
                                         uint8_t prefix_len,
                                         int terminal)
{
    ip_cidr_radix_node_t *node = calloc(1, sizeof(*node));

    if (node != NULL) {
        node->network = normalized_network(network, prefix_len);
        node->prefix_len = prefix_len;
        node->terminal = terminal;
    }
    return node;
}

static void node_free(ip_cidr_radix_node_t *node)
{
    if (node == NULL) {
        return;
    }

    node_free(node->child[0]);
    node_free(node->child[1]);
    free(node);
}

static int insert_at(ip_cidr_radix_node_t **link,
                     uint32_t network,
                     uint8_t prefix_len)
{
    ip_cidr_radix_node_t *node = *link;
    uint8_t common;

    if (node == NULL) {
        node = node_create(network, prefix_len, 1);
        if (node == NULL) {
            return 0;
        }
        *link = node;
        return 1;
    }

    common = common_prefix_len(node->network, node->prefix_len,
                               network, prefix_len);

    if (common == node->prefix_len && common == prefix_len) {
        node->terminal = 1;
        return 1;
    }

    if (common == node->prefix_len) {
        /* The new CIDR is more specific than this node. */
        return insert_at(&node->child[bit_at(network, node->prefix_len)],
                         network, prefix_len);
    }

    if (common == prefix_len) {
        /* The new CIDR is a parent of this node. */
        ip_cidr_radix_node_t *parent = node_create(network, prefix_len, 1);

        if (parent == NULL) {
            return 0;
        }
        parent->child[bit_at(node->network, prefix_len)] = node;
        *link = parent;
        return 1;
    }

    /* The two prefixes diverge inside this compressed path. */
    {
        ip_cidr_radix_node_t *parent;
        ip_cidr_radix_node_t *new_node;
        unsigned int node_direction = bit_at(node->network, common);
        unsigned int new_direction = bit_at(network, common);

        parent = node_create(node->network, common, 0);
        new_node = node_create(network, prefix_len, 1);
        if (parent == NULL || new_node == NULL) {
            free(parent);
            free(new_node);
            return 0;
        }

        parent->child[node_direction] = node;
        parent->child[new_direction] = new_node;
        *link = parent;
    }
    return 1;
}

void ip_cidr_radix_init(ip_cidr_radix_t *radix)
{
    if (radix != NULL) {
        radix->root = NULL;
    }
}

void ip_cidr_radix_free(ip_cidr_radix_t *radix)
{
    if (radix == NULL) {
        return;
    }

    node_free(radix->root);
    radix->root = NULL;
}

int ip_cidr_radix_insert(ip_cidr_radix_t *radix, const ip_cidr_t *cidr)
{
    if (radix == NULL || cidr == NULL || cidr->prefix_len > 32) {
        return 0;
    }

    return insert_at(&radix->root,
                     cidr->network,
                     cidr->prefix_len);
}

int ip_cidr_radix_contains_address(const ip_cidr_radix_t *radix,
                                   uint32_t address)
{
    const ip_cidr_radix_node_t *node;

    if (radix == NULL) {
        return 0;
    }

    node = radix->root;
    while (node != NULL) {
        if (!prefix_matches(address, node->network, node->prefix_len)) {
            return 0;
        }
        if (node->terminal) {
            return 1;
        }
        if (node->prefix_len == 32) {
            return 0;
        }
        node = node->child[bit_at(address, node->prefix_len)];
    }

    return 0;
}
