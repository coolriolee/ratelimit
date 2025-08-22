#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ratelimit_user.h"

static int
ip46address_parse (ratelimit_ipaddr46_t *ipaddr46, const char *ipaddr)
{
    int retcode = 0;
    if (strstr (ipaddr, "::ffff:")) {
        ratelimit_ipaddr6_t ipaddr6 = { 0 };
        retcode = inet_pton (AF_INET6, ipaddr, &ipaddr6);
        ipaddr46->ip4.addr.s_addr = ipaddr6.addr.__in6_u.__u6_addr32[3];
    } else if (strstr (ipaddr, ".")) {
        retcode = inet_pton (AF_INET, ipaddr, &ipaddr46->ip4);
    } else if (strstr (ipaddr, ":")) {
        retcode = inet_pton (AF_INET6, ipaddr, &ipaddr46->ip6);
    }

    return retcode;
}

int
main (int argc, char *argv[])
{
    if (argc < 2)
        return EXIT_FAILURE;

    char *action = argv[1];

    if (strcmp (action, "dump") == 0) {
    } else {
        if (argc < 3)
            return EXIT_FAILURE;

        char *ipaddr = argv[2];
        ratelimit_ipaddr46_t ipaddr46 = { 0 };

        // Assume ipaddr46 is filled with the correct IPv4/IPv6 address from ipaddr
        int retcode = ip46address_parse (&ipaddr46, ipaddr);
        if (retcode < 1) {
            fprintf (stderr, "Invalid IP address format: %s [%d]\n", ipaddr, retcode);
            return EXIT_FAILURE;
        }

        if (strcmp (action, "add") == 0) {
            if (argc < 5) {
                fprintf (stderr, "Usage: %s add <ipaddr> <rxbps> <txbps>\n", argv[0]);
                return EXIT_FAILURE;
            }
            __u64 rxbps = strtoull (argv[3], NULL, 10);
            __u64 txbps = strtoull (argv[4], NULL, 10);

            ratelimit_add_limitinfo (ipaddr46, rxbps, txbps);
        } else if (strcmp (action, "del") == 0) {
            ratelimit_del_limitinfo (ipaddr46);
        } else if (strcmp (action, "show") == 0) {
            ratelimit_show_limitinfo (ipaddr46);
        }
    }

    ratelimit_fini ();

    return EXIT_SUCCESS;
}