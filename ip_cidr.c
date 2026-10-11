#include "ip_cidr.h"

#include <ctype.h>
#include <stdlib.h>

static void skip_spaces(const char **cursor)
{
    while (isspace((unsigned char)**cursor)) {
        (*cursor)++;
    }
}

static int parse_uint(const char **cursor, unsigned int max, unsigned int *value)
{
    const char *start = *cursor;
    unsigned int result = 0;

    while (isdigit((unsigned char)**cursor)) {
        unsigned int digit = (unsigned int)(**cursor - '0');
        if (result > (max - digit) / 10) {
            return 0;
        }
        result = result * 10 + digit;
        (*cursor)++;
    }

    if (*cursor == start) {
        return 0;
    }
    *value = result;
    return 1;
}

static int parse_one(const char **cursor, ip_cidr_t *result)
{
    unsigned int octet[4];
    unsigned int prefix = 32;

    skip_spaces(cursor);
    for (int i = 0; i < 4; i++) {
        if (!parse_uint(cursor, 255, &octet[i])) {
            return 0;
        }
        if (i < 3) {
            if (**cursor != '.') {
                return 0;
            }
            (*cursor)++;
        }
    }

    if (**cursor == '/') {
        (*cursor)++;
        if (!parse_uint(cursor, 32, &prefix)) {
            return 0;
        }
    }

    result->network = ((uint32_t)octet[0] << 24) |
                      ((uint32_t)octet[1] << 16) |
                      ((uint32_t)octet[2] << 8) |
                      (uint32_t)octet[3];
    result->prefix_len = (uint8_t)prefix;
    if (prefix != 0) {
        result->network &= UINT32_MAX << (32 - prefix);
    }
    return 1;
}

void ip_cidr_list_init(ip_cidr_list_t *list)
{
    list->items = NULL;
    list->count = 0;
}

void ip_cidr_list_free(ip_cidr_list_t *list)
{
    free(list->items);
    ip_cidr_list_init(list);
}

int ip_cidr_list_parse(ip_cidr_list_t *list, const char *input)
{
    const char *cursor = input;

    ip_cidr_list_free(list);
    for (;;) {
        ip_cidr_t parsed;
        ip_cidr_t *new_items;

        if (!parse_one(&cursor, &parsed)) {
            ip_cidr_list_free(list);
            return 0;
        }

        new_items = realloc(list->items, (list->count + 1) * sizeof(*new_items));
        if (new_items == NULL) {
            ip_cidr_list_free(list);
            return 0;
        }
        list->items = new_items;
        list->items[list->count++] = parsed;

        skip_spaces(&cursor);
        if (*cursor == '\0') {
            return 1;
        }
        if (*cursor != ',') {
            ip_cidr_list_free(list);
            return 0;
        }
        cursor++;
    }
}

int ip_cidr_list_contains(const ip_cidr_list_t *list, const char *address_text)
{
    const char *cursor = address_text;
    ip_cidr_t address;

    if (!parse_one(&cursor, &address)) {
        return 0;
    }
    skip_spaces(&cursor);
    if (*cursor != '\0') {
        return 0;
    }

    for (size_t i = 0; i < list->count; i++) {
        uint32_t mask = list->items[i].prefix_len == 0
                      ? 0
                      : UINT32_MAX << (32 - list->items[i].prefix_len);
        if ((address.network & mask) == list->items[i].network) {
            return 1;
        }
    }
    return 0;
}
