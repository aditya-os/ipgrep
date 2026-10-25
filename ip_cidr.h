#ifndef IP_CIDR_H
#define IP_CIDR_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    /* The original address, retained for matching detected text. */
    uint32_t address;
    /* The address masked by prefix_len, used for configured filters. */
    uint32_t network;
    uint8_t prefix_len;
} ip_cidr_t;

typedef struct {
    ip_cidr_t *items;
    size_t count;
    size_t capacity;
} ip_cidr_list_t;

typedef int (*ip_cidr_insert_fn)(void *context, const ip_cidr_t *cidr);

void ip_cidr_list_init(ip_cidr_list_t *list);
void ip_cidr_list_free(ip_cidr_list_t *list);
int ip_cidr_list_insert(ip_cidr_list_t *list, const ip_cidr_t *cidr);
int ip_cidr_list_contains_address(const ip_cidr_list_t *list,
                                  uint32_t address);
int ip_cidr_parse(const char *input, ip_cidr_t *result);
int ip_cidr_parse_entries(const char *input,
                          ip_cidr_insert_fn insert,
                          void *context);
int ip_cidr_list_parse(ip_cidr_list_t *list, const char *input);
int ip_cidr_list_contains(const ip_cidr_list_t *list, const char *address_text);

#endif
