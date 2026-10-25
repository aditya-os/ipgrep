#include "ip_cidr_store.h"

#include <stdlib.h>

#include "ip_cidr_trie.h"

static int list_init(void *state)
{
    ip_cidr_list_init(state);
    return 1;
}

static void list_free(void *state)
{
    ip_cidr_list_free(state);
}

static int list_insert(void *state, const ip_cidr_t *cidr)
{
    return ip_cidr_list_insert(state, cidr);
}

static int list_contains_address(const void *state, uint32_t address)
{
    return ip_cidr_list_contains_address(state, address);
}

static int trie_init(void *state)
{
    ip_cidr_trie_init(state);
    return 1;
}

static void trie_free(void *state)
{
    ip_cidr_trie_free(state);
}

static int trie_insert(void *state, const ip_cidr_t *cidr)
{
    return ip_cidr_trie_insert(state, cidr);
}

static int trie_contains_address(const void *state, uint32_t address)
{
    return ip_cidr_trie_contains_address(state, address);
}

static const ip_cidr_store_ops_t list_ops = {
    .init = list_init,
    .free = list_free,
    .insert = list_insert,
    .contains_address = list_contains_address,
};

static const ip_cidr_store_ops_t trie_ops = {
    .init = trie_init,
    .free = trie_free,
    .insert = trie_insert,
    .contains_address = trie_contains_address,
};

static const ip_cidr_store_ops_t *ops_for_kind(ip_cidr_store_kind_t kind,
                                               size_t *state_size)
{
    if (kind == IP_CIDR_STORE_LIST) {
        *state_size = sizeof(ip_cidr_list_t);
        return &list_ops;
    }
    if (kind == IP_CIDR_STORE_TRIE) {
        *state_size = sizeof(ip_cidr_trie_t);
        return &trie_ops;
    }
    return NULL;
}

int ip_cidr_store_init(ip_cidr_store_t *store,
                       ip_cidr_store_kind_t kind)
{
    const ip_cidr_store_ops_t *ops;
    size_t state_size;

    if (store == NULL) {
        return 0;
    }

    ops = ops_for_kind(kind, &state_size);
    if (ops == NULL) {
        return 0;
    }

    store->kind = kind;
    store->ops = ops;
    store->state = calloc(1, state_size);
    if (store->state == NULL) {
        store->ops = NULL;
        return 0;
    }

    if (!store->ops->init(store->state)) {
        free(store->state);
        store->state = NULL;
        store->ops = NULL;
        return 0;
    }
    return 1;
}

void ip_cidr_store_free(ip_cidr_store_t *store)
{
    if (store == NULL) {
        return;
    }

    if (store->ops != NULL && store->state != NULL) {
        store->ops->free(store->state);
        free(store->state);
    }
    store->ops = NULL;
    store->state = NULL;
}

int ip_cidr_store_insert(ip_cidr_store_t *store,
                         const ip_cidr_t *cidr)
{
    if (store == NULL || store->ops == NULL || store->state == NULL) {
        return 0;
    }
    return store->ops->insert(store->state, cidr);
}

int ip_cidr_store_insert_callback(void *context,
                                  const ip_cidr_t *cidr)
{
    return ip_cidr_store_insert(context, cidr);
}

int ip_cidr_store_parse(ip_cidr_store_t *store, const char *input)
{
    ip_cidr_store_t built;

    if (store == NULL || store->ops == NULL || input == NULL) {
        return 0;
    }

    if (!ip_cidr_store_init(&built, store->kind)) {
        return 0;
    }

    if (!ip_cidr_parse_entries(input,
                               ip_cidr_store_insert_callback,
                               &built)) {
        ip_cidr_store_free(&built);
        return 0;
    }

    ip_cidr_store_free(store);
    *store = built;
    return 1;
}

int ip_cidr_store_contains_address(const ip_cidr_store_t *store,
                                   uint32_t address)
{
    if (store == NULL || store->ops == NULL || store->state == NULL) {
        return 0;
    }
    return store->ops->contains_address(store->state, address);
}
