#include "ip_cidr.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void skip_spaces(const char **cursor)
{
    while (isspace((unsigned char)**cursor)) {
        (*cursor)++;
    }
}

static void skip_horizontal_spaces(const char **cursor)
{
    while (**cursor == ' ' || **cursor == '\t' || **cursor == '\r') {
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

    result->address = ((uint32_t)octet[0] << 24) |
                      ((uint32_t)octet[1] << 16) |
                      ((uint32_t)octet[2] << 8) |
                      (uint32_t)octet[3];
    result->network = result->address;
    result->prefix_len = (uint8_t)prefix;
    if (prefix != 0) {
        result->network &= UINT32_MAX << (32 - prefix);
    }
    return 1;
}

int ip_cidr_parse(const char *input, ip_cidr_t *result)
{
    const char *cursor;

    if (input == NULL || result == NULL) {
        return 0;
    }

    cursor = input;
    if (!parse_one(&cursor, result)) {
        return 0;
    }

    skip_spaces(&cursor);
    return *cursor == '\0';
}

void ip_cidr_list_init(ip_cidr_list_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void ip_cidr_list_free(ip_cidr_list_t *list)
{
    free(list->items);
    ip_cidr_list_init(list);
}

static int ip_cidr_list_reserve(ip_cidr_list_t *list, size_t capacity)
{
    if (capacity <= list->capacity) {
        return 1;
    }

    ip_cidr_t *items = realloc(list->items, capacity * sizeof(*items));
    if (items == NULL) {
        return 0;
    }

    list->items = items;
    list->capacity = capacity;
    return 1;
}

int ip_cidr_list_insert(ip_cidr_list_t *list, const ip_cidr_t *cidr)
{
    size_t new_capacity;

    if (list == NULL || cidr == NULL) {
        return 0;
    }

    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 1 : list->capacity * 2;
        if (new_capacity < list->capacity ||
            !ip_cidr_list_reserve(list, new_capacity)) {
            return 0;
        }
    }

    list->items[list->count++] = *cidr;
    return 1;
}

static int ip_cidr_list_insert_callback(void *context,
                                        const ip_cidr_t *cidr)
{
    return ip_cidr_list_insert(context, cidr);
}

int ip_cidr_list_parse(ip_cidr_list_t *list, const char *input)
{
    size_t estimated_count;
    int result;

    if (list == NULL || input == NULL) {
        return 0;
    }

    estimated_count = strlen(input) / 16 + 1;
    ip_cidr_list_free(list);
    if (!ip_cidr_list_reserve(list, estimated_count)) {
        return 0;
    }

    result = ip_cidr_parse_entries(input,
                                   ip_cidr_list_insert_callback,
                                   list);
    if (!result) {
        ip_cidr_list_free(list);
    }
    return result;
}

int ip_cidr_parse_entries(const char *input,
                          ip_cidr_insert_fn insert,
                          void *context)
{
    const char *cursor;

    if (input == NULL || insert == NULL) {
        return 0;
    }

    cursor = input;

    for (;;) {
        ip_cidr_t parsed;

        skip_spaces(&cursor);
        if (*cursor == '\0') {
            break;
        }

        if (!parse_one(&cursor, &parsed)) {
            return 0;
        }

        if (!insert(context, &parsed)) {
            return 0;
        }

        skip_horizontal_spaces(&cursor);
        if (*cursor == '\0') {
            break;
        }
        if (*cursor == ',') {
            cursor++;
            skip_spaces(&cursor);
            if (*cursor == '\0') {
                /* A final comma is allowed. */
                break;
            }
            continue;
        }
        if (*cursor == '\n') {
            do {
                cursor++;
            } while (*cursor == '\n');
            continue;
        }
        {
            return 0;
        }
    }

    return 1;
}

int ip_cidr_covers(const ip_cidr_t *outer, const ip_cidr_t *inner)
{
    uint32_t mask;

    if (outer == NULL || inner == NULL ||
        outer->prefix_len > 32 || inner->prefix_len > 32 ||
        outer->prefix_len > inner->prefix_len) {
        return 0;
    }

    mask = prefix_mask(outer->prefix_len);
    return (inner->network & mask) == (outer->network & mask);
}

int ip_cidr_format(const ip_cidr_t *cidr,
                   char *output,
                   size_t output_size)
{
    uint32_t address;
    int length;

    if (cidr == NULL || output == NULL || output_size == 0 ||
        cidr->prefix_len > 32) {
        return 0;
    }

    address = cidr->network;
    length = snprintf(output, output_size, "%u.%u.%u.%u/%u",
                      (unsigned int)((address >> 24) & 0xffU),
                      (unsigned int)((address >> 16) & 0xffU),
                      (unsigned int)((address >> 8) & 0xffU),
                      (unsigned int)(address & 0xffU),
                      (unsigned int)cidr->prefix_len);
    return length >= 0 && (size_t)length < output_size;
}

int ip_cidr_list_contains_address(const ip_cidr_list_t *list,
                                  uint32_t address)
{
    if (list == NULL) {
        return 0;
    }

    for (size_t i = 0; i < list->count; i++) {
        uint32_t mask = prefix_mask(list->items[i].prefix_len);
        if ((address & mask) == list->items[i].network) {
            return 1;
        }
    }
    return 0;
}

int ip_cidr_list_contains(const ip_cidr_list_t *list, const char *address_text)
{
    ip_cidr_t address;

    if (!ip_cidr_parse(address_text, &address)) {
        return 0;
    }
    return ip_cidr_list_contains_address(list, address.address);
}
