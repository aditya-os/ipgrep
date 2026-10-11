#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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
            "Usage: %s -f <filename> -n <ip-or-cidr>[,<ip-or-cidr>...]\n",
            program);
}

int main(int argc, char *argv[])
{
    int opt;
    int fd;
    char *input_file = NULL;
    char *network_input = NULL;
    ip_cidr_list_t networks;
    ip_matcher_t matcher;
    char buf[BUF_SIZE];
    ssize_t bytes_read;
    size_t line = 1;
    size_t position = 1;

    ip_cidr_list_init(&networks);
    while ((opt = getopt(argc, argv, "f:n:")) != -1) {
        switch (opt) {
        case 'f':
            input_file = optarg;
            break;
        case 'n':
            network_input = optarg;
            break;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (input_file == NULL || network_input == NULL ||
        !ip_cidr_list_parse(&networks, network_input)) {
        if (network_input != NULL) {
            write_str(STDERR_FILENO, "Invalid IP/CIDR input\n");
        }
        print_usage(argv[0]);
        ip_cidr_list_free(&networks);
        return 1;
    }

    fd = open(input_file, O_RDONLY);
    if (fd < 0) {
        dprintf(STDERR_FILENO, "%s: %s\n", input_file, strerror(errno));
        ip_cidr_list_free(&networks);
        return 1;
    }

    ip_matcher_init(&matcher);
    while ((bytes_read = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (ip_matcher_feed(&matcher, buf[i]) &&
                ip_cidr_list_contains(&networks, ip_matcher_get_match(&matcher))) {
                const char *match = ip_matcher_get_match(&matcher);
                print_match(match, line, position - strlen(match));
            }

            if (buf[i] == '\n') {
                line++;
                position = 1;
            } else {
                position++;
            }
        }
    }

    if (bytes_read < 0) {
        dprintf(STDERR_FILENO, "read error: %s\n", strerror(errno));
        close(fd);
        ip_cidr_list_free(&networks);
        return 1;
    }

    if (ip_matcher_flush(&matcher) &&
        ip_cidr_list_contains(&networks, ip_matcher_get_match(&matcher))) {
        const char *match = ip_matcher_get_match(&matcher);
        print_match(match, line, position - strlen(match));
    }

    close(fd);
    ip_cidr_list_free(&networks);
    return 0;
}
