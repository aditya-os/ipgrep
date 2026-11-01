#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ip_cidr.h"
#include "ip_cidr_store.h"
#include "ip_matcher.h"

#define BUF_SIZE 4096
#define FILTER_FILE_MAX_SIZE (1024U * 1024U)

static void write_str(int fd, const char *s)
{
    write(fd, s, strlen(s));
}

static void print_match(const char *match, size_t line, size_t position)
{
    char output[128];
    int length = snprintf(output, sizeof(output), "%zu:%zu:%s\n",
                          line, position, match);
    if (length > 0) {
        write(STDOUT_FILENO, output, (size_t)length);
    }
}

static void print_coverage_match(const char *match,
                                 size_t line,
                                 size_t position)
{
    char output[128];
    int length = snprintf(output, sizeof(output), "M,%zu,%zu:%s\n",
                          line, position, match);
    if (length > 0) {
        write(STDOUT_FILENO, output, (size_t)length);
    }
}

static void print_unmatched_cidr(const ip_cidr_t *cidr)
{
    char formatted[IP_CIDR_MAX_LEN + 1];
    char output[IP_CIDR_MAX_LEN + 4];
    int length;

    if (!ip_cidr_format(cidr, formatted, sizeof(formatted))) {
        return;
    }

    length = snprintf(output, sizeof(output), "U,%s\n", formatted);
    if (length > 0) {
        write(STDOUT_FILENO, output, (size_t)length);
    }
}

static void print_usage(const char *program)
{
    dprintf(STDERR_FILENO,
            "Usage: %s [-f <input-file>] [-n <ip-or-cidr>[,<ip-or-cidr>...] | "
            "-nf <cidr-file> | -s <cidr>[,<cidr>...]]\n",
            program);
}

static int env_flag_enabled(const char *name)
{
    const char *value = getenv(name);

    return value != NULL &&
           (strcmp(value, "1") == 0 ||
            strcmp(value, "true") == 0 ||
            strcmp(value, "yes") == 0 ||
            strcmp(value, "on") == 0);
}

static int address_matches(const ip_cidr_store_t *store,
                           const char *address_text)
{
    ip_cidr_t address;
    if (!ip_cidr_parse(address_text, &address)) {
        return 0;
    }
    return ip_cidr_store_contains_address(store, address.address);
}

static int coverage_matches(const char *cidr_text,
                            const ip_cidr_list_t *targets,
                            bool *matched)
{
    ip_cidr_t candidate;
    int matched_any = 0;

    if (!ip_cidr_parse(cidr_text, &candidate)) {
        return 0;
    }

    for (size_t i = 0; i < targets->count; i++) {
        if (ip_cidr_covers(&candidate, &targets->items[i])) {
            matched[i] = 1;
            matched_any = 1;
        }
    }
    return matched_any;
}

typedef struct {
    const ip_cidr_store_t *address_store;
    bool address_filter_enabled;
    const ip_cidr_list_t *subnet_targets;
    bool *subnet_matched;
    bool subnet_filter_enabled;
} match_context_t;

static void process_detected_match(const match_context_t *context,
                                   const char *match,
                                   size_t line,
                                   size_t position)
{
    size_t match_position = position - strlen(match);

    if (context->subnet_filter_enabled) {
        if (coverage_matches(match, context->subnet_targets,
                             context->subnet_matched)) {
            print_coverage_match(match, line, match_position);
        }
        return;
    }

    if (context->address_filter_enabled &&
        !address_matches(context->address_store, match)) {
        return;
    }

    print_match(match, line, match_position);
}

static int load_filter_file(const char *filename, const char **input,
                            char **owned_input)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    struct stat file_info;
    if (fstat(fd, &file_info) < 0) {
        close(fd);
        return 0;
    }

    if (file_info.st_size < 0 ||
        (uintmax_t)file_info.st_size >= FILTER_FILE_MAX_SIZE) {
        errno = EFBIG;
        close(fd);
        return 0;
    }

    size_t file_size = (size_t)file_info.st_size;
    char *contents = malloc(file_size + 1);
    if (contents == NULL) {
        close(fd);
        return 0;
    }

    size_t length = 0;
    while (length < file_size) {
        ssize_t count = read(fd, contents + length, file_size - length);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(contents);
            close(fd);
            return 0;
        }
        if (count == 0) {
            errno = EIO;
            free(contents);
            close(fd);
            return 0;
        }
        length += (size_t)count;
    }
    contents[length] = '\0';
    close(fd);

    *input = contents;
    *owned_input = contents;
    return 1;
}

static bool initialize_network_filter(const char *program,
                                      const char *network_input,
                                      const char *network_file,
                                      ip_cidr_store_t *store)
{
    const char *filter_input = network_input;
    char *owned_filter_input = NULL;
    bool parsed;

    if (network_file != NULL) {
        if (!load_filter_file(network_file, &filter_input,
                              &owned_filter_input)) {
            dprintf(STDERR_FILENO, "Cannot read CIDR file %s: %s\n",
                    network_file, strerror(errno));
            return false;
        }
    }

    parsed = ip_cidr_store_parse(store, filter_input);
    free(owned_filter_input);

    if (!parsed) {
        write_str(STDERR_FILENO, "Invalid IP/CIDR input\n");
        print_usage(program);
        return false;
    }

    return true;
}

static bool initialize_subnet_filter(const char *program,
                                     const char *subnet_input,
                                     ip_cidr_list_t *subnet_targets,
                                     bool **subnet_matched)
{
    if (subnet_input == NULL) {
        return true;
    }

    if (!ip_cidr_list_parse(subnet_targets, subnet_input) ||
        subnet_targets->count == 0) {
        write_str(STDERR_FILENO, "Invalid -s CIDR input\n");
        print_usage(program);
        ip_cidr_list_free(subnet_targets);
        return false;
    }

    *subnet_matched = calloc(subnet_targets->count,
                             sizeof(**subnet_matched));
    if (*subnet_matched == NULL) {
        write_str(STDERR_FILENO, "Unable to allocate -s CIDR state\n");
        ip_cidr_list_free(subnet_targets);
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    int fd;
    char *input_file = NULL;
    char *network_input = NULL;
    char *network_file = NULL;
    char *subnet_input = NULL;
    bool has_network_filter;
    bool has_subnet_filter;
    int use_radix = env_flag_enabled("IPGREP_USE_RADIX");
    int use_trie = env_flag_enabled("IPGREP_USE_TRIE");
    int close_input = 0;
    ip_cidr_store_t store = {0};
    ip_cidr_list_t subnet_targets = {0};
    bool *subnet_matched = NULL;
    match_context_t match_context;
    ip_matcher_t matcher;
    char buf[BUF_SIZE];
    ssize_t bytes_read;
    size_t line = 1;
    size_t position = 1;

    if (!ip_cidr_store_init(&store,
                            use_radix ? IP_CIDR_STORE_RADIX
                                      : use_trie ? IP_CIDR_STORE_TRIE
                                                 : IP_CIDR_STORE_LIST)) {
        write_str(STDERR_FILENO, "Unable to initialize CIDR store\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            network_input = argv[++i];
        } else if (strcmp(argv[i], "-nf") == 0 && i + 1 < argc) {
            network_file = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            subnet_input = argv[++i];
        } else {
            print_usage(argv[0]);
            ip_cidr_store_free(&store);
            return 1;
        }
    }

    if ((network_input != NULL && network_file != NULL) ||
        (subnet_input != NULL &&
         (network_input != NULL || network_file != NULL))) {
        print_usage(argv[0]);
        ip_cidr_store_free(&store);
        return 1;
    }

    has_network_filter = network_input != NULL || network_file != NULL;
    has_subnet_filter = subnet_input != NULL;

    if (has_network_filter &&
        !initialize_network_filter(argv[0], network_input, network_file,
                                   &store)) {
        ip_cidr_store_free(&store);
        return 1;
    }

    if (has_subnet_filter &&
        !initialize_subnet_filter(argv[0], subnet_input, &subnet_targets,
                                  &subnet_matched)) {
        ip_cidr_store_free(&store);
        return 1;
    }

    if (input_file == NULL || strcmp(input_file, "-") == 0) {
        fd = STDIN_FILENO;
    } else {
        fd = open(input_file, O_RDONLY);
        if (fd < 0) {
            dprintf(STDERR_FILENO, "%s: %s\n", input_file, strerror(errno));
            free(subnet_matched);
            ip_cidr_list_free(&subnet_targets);
            ip_cidr_store_free(&store);
            return 1;
        }
        close_input = 1;
    }

    match_context = (match_context_t){
        .address_store = &store,
        .address_filter_enabled = has_network_filter,
        .subnet_targets = &subnet_targets,
        .subnet_matched = subnet_matched,
        .subnet_filter_enabled = has_subnet_filter,
    };

    ip_matcher_init(&matcher);
    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (ip_matcher_feed(&matcher, buf[i])) {
                process_detected_match(&match_context,
                                       ip_matcher_get_match(&matcher),
                                       line,
                                       position);
            }

            if (buf[i] == '\n') {
                line++;
                position = 0;
            } 
            position++;
        }
    }

    if (bytes_read < 0) {
        dprintf(STDERR_FILENO, "read error: %s\n", strerror(errno));
        if (close_input) {
            close(fd);
        }
        free(subnet_matched);
        ip_cidr_list_free(&subnet_targets);
        ip_cidr_store_free(&store);
        return 1;
    }

    if (ip_matcher_flush(&matcher)) {
        process_detected_match(&match_context,
                               ip_matcher_get_match(&matcher),
                               line,
                               position);
    }

    if (has_subnet_filter) {
        for (size_t i = 0; i < subnet_targets.count; i++) {
            if (!subnet_matched[i]) {
                print_unmatched_cidr(&subnet_targets.items[i]);
            }
        }
    }

    if (close_input) {
        close(fd);
    }
    free(subnet_matched);
    ip_cidr_list_free(&subnet_targets);
    ip_cidr_store_free(&store);
    return 0;
}
