#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include "ip_matcher.h"

#define BUF_SIZE    4096
#define LCOUNT_LEN  16

static void write_str(int fd, const char *s)
{
    write(fd, s, strlen(s));
}

static void print_match(const char *match,int lcount)
{
    char lcountinfo[LCOUNT_LEN];
    sprintf(lcountinfo,"%d:",lcount);
    write_str(1, lcountinfo);
    write_str(1, match);
    write_str(1, "\n");
}

int valid_nw_cidr(char *nw_cidr)
{
        ip_matcher_t nw_matcher;
        ip_matcher_init(&nw_matcher);
        int len = strlen(nw_cidr);
        for(int i = 0; i<len;i++){
            if(ip_matcher_feed(&nw_matcher,nw_cidr[i])){

            }
        }
        return 0;
}

int main(int argc, char *argv[])
{
    int opt;
    char *input_file = NULL;
    char *network = NULL;
    while ((opt = getopt(argc, argv, "f:n")) != -1) {
        switch (opt) {
            case 'f':
                input_file = optarg;
            break;

            case 'n':
                network = optarg;
            break;

            default:
            break;
        }
    }
    //printf("Input file %s\n",input_file);
    if (input_file == NULL ) {
        write_str(2, "Usage: ");
        write_str(2, argv[0]);
        write_str(2, "-f <filename> -n <network_cidr>\n");
        return 1;
    }
    // if(network != NULL){

    // }

    int fd = open(input_file, O_RDONLY);
    if (fd < 0) {
        write_str(2, argv[1]);
        write_str(2, ": ");
        write_str(2, strerror(errno));
        write_str(2, "\n");
        return 1;
    }

    ip_matcher_t matcher;
    ip_matcher_init(&matcher);

    char buf[BUF_SIZE];
    ssize_t n;
    int lcount = 0 ; 
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            if (ip_matcher_feed(&matcher, buf[i])) {
                print_match(ip_matcher_get_match(&matcher),lcount);
            }
            if(buf[i]=='\n'){
                lcount++;
            }
        }
    }

    if (n < 0) {
        write_str(2, "read error: ");
        write_str(2, strerror(errno));
        write_str(2, "\n");
        close(fd);
        return 1;
    }

    if (ip_matcher_flush(&matcher)) {
        print_match(ip_matcher_get_match(&matcher),lcount);
    }

    close(fd);
    return 0;
}
