#ifndef IP_CIDR_H
#define IP_CIDR_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t network;
    uint8_t prefix_len;
} ip_cidr_t;

typedef struct {
    ip_cidr_t *items;
    size_t count;
} ip_cidr_list_t;

void ip_cidr_list_init(ip_cidr_list_t *list);
void ip_cidr_list_free(ip_cidr_list_t *list);
int ip_cidr_list_parse(ip_cidr_list_t *list, const char *input);
int ip_cidr_list_contains(const ip_cidr_list_t *list, const char *address_text);

#endif
