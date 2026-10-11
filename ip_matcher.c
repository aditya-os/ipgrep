#include "ip_matcher.h"

#include <string.h>

typedef enum {
    IP_START,
    IP_OCT1,
    IP_DOT1,
    IP_OCT2,
    IP_DOT2,
    IP_OCT3,
    IP_DOT3,
    IP_OCT4,
    IP_PREFIX,
} ip_state_t;

struct ip_matcher_impl {
    ip_state_t state;
    char buf[IP_CIDR_MAX_LEN + 1];
    char last_match[IP_CIDR_MAX_LEN + 1];
    int len;
    int octet_val;
    int octet_digits;
    int prefix_val;
    int prefix_digits;
};

typedef struct ip_matcher_impl ip_matcher_impl_t;

_Static_assert(sizeof(ip_matcher_impl_t) <= IP_MATCHER_STORAGE,
               "IP_MATCHER_STORAGE is too small for ip_matcher_impl_t");

static ip_matcher_impl_t *impl(ip_matcher_t *m)
{
    return (ip_matcher_impl_t *)m->storage;
}

static const ip_matcher_impl_t *impl_const(const ip_matcher_t *m)
{
    return (const ip_matcher_impl_t *)m->storage;
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static void ip_matcher_reset(ip_matcher_t *m)
{
    ip_matcher_impl_t *self = impl(m);
    self->state = IP_START;
    self->len = 0;
    self->octet_val = 0;
    self->octet_digits = 0;
    self->prefix_val = 0;
    self->prefix_digits = 0;
}

static void ip_matcher_start_octet(ip_matcher_t *m, char c)
{
    ip_matcher_impl_t *self = impl(m);
    self->octet_val = c - '0';
    self->octet_digits = 1;
    self->buf[self->len++] = c;
}

static int ip_matcher_append_digit(ip_matcher_t *m, char c)
{
    ip_matcher_impl_t *self = impl(m);
    if (self->octet_digits >= 3) {
        return 0;
    }

    int next = self->octet_val * 10 + (c - '0');
    if (next > 255) {
        return 0;
    }

    self->octet_val = next;
    self->octet_digits++;
    self->buf[self->len++] = c;
    return 1;
}

static int ip_matcher_emit(ip_matcher_t *m)
{
    ip_matcher_impl_t *self = impl(m);
    self->buf[self->len] = '\0';
    strcpy(self->last_match, self->buf);
    ip_matcher_reset(m);
    return 1;
}

void ip_matcher_init(ip_matcher_t *m)
{
    ip_matcher_reset(m);
    impl(m)->last_match[0] = '\0';
}

int ip_matcher_feed(ip_matcher_t *m, char c)
{
    ip_matcher_impl_t *self = impl(m);

again:
    switch (self->state) {
    case IP_START:
        if (is_digit(c)) {
            self->state = IP_OCT1;
            ip_matcher_start_octet(m, c);
        }
        break;

    case IP_OCT1:
        if (is_digit(c)) {
            if (!ip_matcher_append_digit(m, c)) {
                goto fail;
            }
        } else if (c == '.' && self->octet_digits > 0) {
            self->buf[self->len++] = c;
            self->state = IP_DOT1;
            self->octet_val = 0;
            self->octet_digits = 0;
        } else {
            goto fail;
        }
        break;

    case IP_DOT1:
        if (is_digit(c)) {
            self->state = IP_OCT2;
            ip_matcher_start_octet(m, c);
        } else {
            goto fail;
        }
        break;

    case IP_OCT2:
        if (is_digit(c)) {
            if (!ip_matcher_append_digit(m, c)) {
                goto fail;
            }
        } else if (c == '.' && self->octet_digits > 0) {
            self->buf[self->len++] = c;
            self->state = IP_DOT2;
            self->octet_val = 0;
            self->octet_digits = 0;
        } else {
            goto fail;
        }
        break;

    case IP_DOT2:
        if (is_digit(c)) {
            self->state = IP_OCT3;
            ip_matcher_start_octet(m, c);
        } else {
            goto fail;
        }
        break;

    case IP_OCT3:
        if (is_digit(c)) {
            if (!ip_matcher_append_digit(m, c)) {
                goto fail;
            }
        } else if (c == '.' && self->octet_digits > 0) {
            self->buf[self->len++] = c;
            self->state = IP_DOT3;
            self->octet_val = 0;
            self->octet_digits = 0;
        } else {
            goto fail;
        }
        break;

    case IP_DOT3:
        if (is_digit(c)) {
            self->state = IP_OCT4;
            ip_matcher_start_octet(m, c);
        } else {
            goto fail;
        }
        break;

    case IP_OCT4:
        if (is_digit(c)) {
            if (!ip_matcher_append_digit(m, c)) {
                goto fail;
            }
        } else {
            /*
             * A tcpdump endpoint is commonly written as
             *     address.port
             * The dot after the fourth octet is therefore also a valid
             * boundary for the IPv4 address.  Do not feed it back into the
             * matcher: the caller will process the following port digits on
             * the next call.
             */
            if (c == '/') {
                self->buf[self->len++] = c;
                self->state = IP_PREFIX;
                self->prefix_val = 0;
                self->prefix_digits = 0;
            } else {
                return ip_matcher_emit(m);
            }
        }
        break;

    case IP_PREFIX:
        if (is_digit(c)) {
            if (self->prefix_digits >= 2) {
                goto fail;
            }

            int next = self->prefix_val * 10 + (c - '0');
            if (next > 32) {
                goto fail;
            }

            self->prefix_val = next;
            self->prefix_digits++;
            self->buf[self->len++] = c;
        } else if (self->prefix_digits > 0) {
            return ip_matcher_emit(m);
        } else {
            goto fail;
        }
        break;
    }

    return 0;

fail:
    ip_matcher_reset(m);
    self = impl(m);
    goto again;
}

int ip_matcher_flush(ip_matcher_t *m)
{
    ip_matcher_impl_t *self = impl(m);
    if (self->state == IP_OCT4 && self->octet_digits > 0) {
        return ip_matcher_emit(m);
    }
    if (self->state == IP_PREFIX && self->prefix_digits > 0) {
        return ip_matcher_emit(m);
    }
    return 0;
}

const char *ip_matcher_get_match(const ip_matcher_t *m)
{
    return impl_const(m)->last_match;
}
