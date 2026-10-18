#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ip_cidr.h"
#include "ip_matcher.h"

#define BUF_SIZE 4096

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

static void print_usage(const char *program)
{
    dprintf(STDERR_FILENO,
            "Usage: %s [-f <input-file>] [-n <ip-or-cidr>[,<ip-or-cidr>...] | "
            "-nf <cidr-file>]\n",
            program);
}

static int load_filter_file(const char *filename, const char **input,
                            char **owned_input, size_t *estimated_count)
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

    /* Most IPv4/CIDR entries are around 16 bytes long. */
    *estimated_count = (size_t)(file_info.st_size / 16) + 1;

    size_t length = 0;
    size_t capacity = 4096;
    char *contents = malloc(capacity + 1);
    if (contents == NULL) {
        close(fd);
        return 0;
    }

    for (;;) {
        if (length == capacity) {
            size_t new_capacity = capacity * 2;
            char *new_contents = realloc(contents, new_capacity + 1);
            if (new_contents == NULL) {
                free(contents);
                close(fd);
                return 0;
            }
            contents = new_contents;
            capacity = new_capacity;
        }

        ssize_t count = read(fd, contents + length, capacity - length);
        if (count < 0) {
            free(contents);
            close(fd);
            return 0;
        }
        if (count == 0) {
            break;
        }
        length += (size_t)count;
    }
    contents[length] = '\0';
    close(fd);

    *input = contents;
    *owned_input = contents;
    return 1;
}

int main(int argc, char *argv[])
{
    int fd;
    char *input_file = NULL;
    char *network_input = NULL;
    char *network_file = NULL;
    const char *filter_input; // indicates the input filter.
    char *owned_filter_input = NULL; // indicates if filter is argv or allocated. 
    size_t estimated_count = 1;
    int has_filter;
    int close_input = 0;
    ip_cidr_list_t networks;
    ip_matcher_t matcher;
    char buf[BUF_SIZE];
    ssize_t bytes_read;
    size_t line = 1;
    size_t position = 1;

    ip_cidr_list_init(&networks);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            network_input = argv[++i];
        } else if (strcmp(argv[i], "-nf") == 0 && i + 1 < argc) {
            network_file = argv[++i];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if ((network_input != NULL && network_file != NULL)) {
        print_usage(argv[0]);
        ip_cidr_list_free(&networks);
        return 1;
    }

    has_filter = network_input != NULL || network_file != NULL;

    if (network_file != NULL) {
        if (!load_filter_file(network_file, &filter_input, &owned_filter_input,
                              &estimated_count)) {
            dprintf(STDERR_FILENO, "Cannot read CIDR file %s: %s\n",
                    network_file, strerror(errno));
            ip_cidr_list_free(&networks);
            return 1;
        }
    } else if (network_input != NULL) {
        filter_input = network_input;
    }

    if (has_filter &&
        !ip_cidr_list_parse_estimated(&networks, filter_input, estimated_count)) {
        write_str(STDERR_FILENO, "Invalid IP/CIDR input\n");
        print_usage(argv[0]);
        free(owned_filter_input);
        ip_cidr_list_free(&networks);
        return 1;
    }

    if (input_file == NULL || strcmp(input_file, "-") == 0) {
        fd = STDIN_FILENO;
    } else {
        fd = open(input_file, O_RDONLY);
        if (fd < 0) {
            dprintf(STDERR_FILENO, "%s: %s\n", input_file, strerror(errno));
            free(owned_filter_input);
            ip_cidr_list_free(&networks);
            return 1;
        }
        close_input = 1;
    }

    ip_matcher_init(&matcher);
    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (ip_matcher_feed(&matcher, buf[i]) &&
                (!has_filter ||
                 ip_cidr_list_contains(&networks,
                                       ip_matcher_get_match(&matcher)))) {
                const char *match = ip_matcher_get_match(&matcher);
                print_match(match, line, position - strlen(match));
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
        free(owned_filter_input);
        ip_cidr_list_free(&networks);
        return 1;
    }

    if (ip_matcher_flush(&matcher) &&
        (!has_filter ||
         ip_cidr_list_contains(&networks, ip_matcher_get_match(&matcher)))) {
        const char *match = ip_matcher_get_match(&matcher);
        print_match(match, line, position - strlen(match));
    }

    if (close_input) {
        close(fd);
    }
    free(owned_filter_input);
    ip_cidr_list_free(&networks);
    return 0;
}
