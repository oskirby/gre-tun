/*
 * Copyright (C) 2020 Owen Kirby <oskirby@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>

#include "gre.h"

static void
usage(int argc, char **argv, FILE *fp)
{
    fprintf(fp, "Usage: %s [OPTIONS]\n", argv[0]);
    fprintf(fp, "Create a GRE-over-UDP tunnel interface\n\n");

    fprintf(fp, "   -c, --client DEST  Connect as a client to a server at DEST.\n");
    fprintf(fp, "   -s, --server       Listen as a server (default)\n");
    fprintf(fp, "   -h, --help         Display this message and exit.\n");
}

int
main(int argc, char **argv)
{
    int ret;
    int sockfd;

    /* Parsed Options. */
    const char  *server_name = NULL;
    int         dtls_enable = 0;

    /* Parse the command line options */
    const char *short_options = "hsc:d";
    const struct option long_options[] = {
        {"help",   no_argument, 0,       'h'},
        {"server", no_argument, 0,       's'},
        {"client", required_argument, 0, 'c'},
        {"dtls",   no_argument, 0,       'd'},
        {0, 0, 0, 0}
    };
    optind = 0;
    while(1) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c < 0) break;

        switch (c) {
            case 'h':
                usage(argc, argv, stderr);
                return EXIT_SUCCESS;
            
            case 'c':
                server_name = optarg;
                break;
            
            case 's':
                server_name = NULL;
                break;
            
            case 'd':
                dtls_enable = 1;
                break;
            
            case '?':
            default:
                usage(argc, argv, stderr);
                return EXIT_FAILURE;
        } /* switch */
    } /* while */

    /* If a server name is specified, resolve it into a suitable IP address. */
    if (server_name) {
        struct addrinfo         hints;
        struct addrinfo         *result;
        int                     server_family;
        struct sockaddr_storage server_addr;
        struct sockaddr_storage local_addr;
        char service[16];

        memset(&hints, 0, sizeof(hints));
        sprintf(service, "%u", GRE_PORT_UDP);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_ADDRCONFIG;
        ret = getaddrinfo(server_name, service, &hints, &result);
        if (ret != 0) {
            fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(ret));
            return EXIT_FAILURE;
        }
        server_family = result->ai_family;
        memcpy(&server_addr, result->ai_addr, result->ai_addrlen);

        /* Open the UDP socket */
        sockfd = socket(result->ai_family, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            fprintf(stderr, "socket() failed: %s\n", strerror(errno));
            freeaddrinfo(result);
            return EXIT_FAILURE;
        }

        /* Bind to our local address */
        memset(&local_addr, 0, sizeof(local_addr));
        if (result->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local_addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = 0; /* We want an ephemeral port */
            memcpy(&sin6->sin6_addr, &in6addr_any, sizeof(struct in6_addr));
        }
        else {
            struct sockaddr_in *sin = (struct sockaddr_in *)&local_addr;
            sin->sin_family = AF_INET;
            sin->sin_port = 0; /* We want an ephemeral port */
            sin->sin_addr.s_addr = htonl(INADDR_ANY);
        }
        ret = bind(sockfd, (struct sockaddr *)&local_addr, result->ai_addrlen);
        if (ret != 0) {
            fprintf(stderr, "bind() failed: %s\n", strerror(errno));
            freeaddrinfo(result);
            close(sockfd);
            return EXIT_FAILURE;
        }

        /* Connect this socket to the server */
        ret = connect(sockfd, result->ai_addr, result->ai_addrlen);
        if (ret < 0) {
            fprintf(stderr, "connect() failed: %s\n", strerror(errno));
            freeaddrinfo(result);
            close(sockfd);
            return EXIT_FAILURE;
        }
        freeaddrinfo(result);

        /* Run the client daemon */
        if (dtls_enable) {
            ret = gre_client_dtls_run(sockfd);
        } else {
            ret = gre_client_run(sockfd);
        }
    }
    /* Otherwise, create the socket for server mode. */
    else {
        struct sockaddr_in6 local_addr;

        /* I think this is a Linux-ism, but binding a socket to in6addr_any allows dual IPv4/IPv6 support */
        sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            fprintf(stderr, "socket() failed: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin6_family = AF_INET6;
        local_addr.sin6_port = htons(GRE_PORT_UDP);
        memcpy(&local_addr.sin6_addr, &in6addr_any, sizeof(struct in6_addr));

        ret = bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr));
        if (ret != 0) {
            fprintf(stderr, "bind() failed: %s\n", strerror(errno));
            close(sockfd);
            return EXIT_FAILURE;
        }

        /* Run the server daemon */
        if (dtls_enable) {
            ret = gre_server_dtls_run(sockfd);
        } else {
            ret = gre_server_run(sockfd);
        }
    }

    /* Run the tunnel interface. */
    close(sockfd);
    return ret;
} /* main */

/*---------------------------------------------*/
/* Here There Be Dragons                       */
