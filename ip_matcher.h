#ifndef IP_MATCHER_H
#define IP_MATCHER_H

#define IP_MAX_LEN 15
#define IP_CIDR_MAX_LEN (IP_MAX_LEN + 3) /* IPv4 plus "/32" */

/*
 * Opaque storage sized for stack allocation without exposing internals.
 * Must be at least sizeof(struct ip_matcher) — checked in ip_matcher.c.
 */
#define IP_MATCHER_STORAGE 64

typedef struct ip_matcher {
    unsigned char storage[IP_MATCHER_STORAGE];
} ip_matcher_t;

void ip_matcher_init(ip_matcher_t *m);

/*
 * Feed one character into the IP matcher.
 * Returns 1 when a complete IPv4 address is identified; use
 * ip_matcher_get_match() to read the result.
 */
int ip_matcher_feed(ip_matcher_t *m, char c);

/*
 * Finalize a trailing match when input ends after the last octet.
 * Returns 1 if a complete IPv4 was pending.
 */
int ip_matcher_flush(ip_matcher_t *m);

const char *ip_matcher_get_match(const ip_matcher_t *m);

#endif
