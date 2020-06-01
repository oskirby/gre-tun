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
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/uio.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>

#include "gre.h"

/* Tunnel connection information. */
struct gre_conn {
    struct gre_conn *next;
    struct gre_conn *prev;

    struct sockaddr_storage addr;
    int tunfd;
};

/* Tunnel server information. */
struct gre_ctx {
    int sockfd;

    struct gre_conn *head;
    struct gre_conn *tail;
};

static int
sockaddr_compare(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family) {
        return (a->ss_family - b->ss_family);
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6a = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *sin6b = (const struct sockaddr_in6 *)b;
        if (sin6a->sin6_port != sin6b->sin6_port) return (sin6a->sin6_port - sin6b->sin6_port);
        if (sin6a->sin6_scope_id != sin6b->sin6_scope_id) return (sin6a->sin6_scope_id - sin6b->sin6_scope_id);
        return memcmp(&sin6a->sin6_addr, &sin6b->sin6_addr, sizeof(struct in6_addr));
    }
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *sina = (const struct sockaddr_in *)a;
        const struct sockaddr_in *sinb = (const struct sockaddr_in *)b;
        if (sina->sin_port != sinb->sin_port) return (sina->sin_port - sinb->sin_port);
        return memcmp(&sina->sin_addr, &sinb->sin_addr, sizeof(struct in_addr));
    }
    /* Otherwise, we can't compare addresses we don't understand. */
    return 1;
} /* sockaddr_compare */

/* Lookup the connection for a given socket address. */
static struct gre_conn *
gre_lookup_conn(struct gre_ctx *ctx, const struct sockaddr_storage *sa)
{
    struct gre_conn *conn;
    for (conn = ctx->head; conn; conn = conn->next) {
        /* Compare it... */
        if (sockaddr_compare(sa, &conn->addr) != 0) continue;

        /* We found a match! */
        return conn;
    } /* for */

    return NULL;
} /* gre_lookup_conn */

static struct gre_conn *
gre_create_conn(struct gre_ctx *ctx, const struct sockaddr_storage *sa)
{
    struct gre_conn *conn = malloc(sizeof(struct gre_conn));
    if (!conn) {
        return NULL;
    }
    memcpy(&conn->addr, sa, sizeof(struct sockaddr_storage));

    conn->tunfd = gre_allocate_tun();
    if (conn->tunfd < 0) {
        free(conn);
        return NULL;
    }

    /* Insert the connection into the end of the list. */
    conn->next = NULL;
    conn->prev = ctx->tail;
    ctx->tail = conn;
    if (conn->prev) conn->prev->next = conn;
    if (!ctx->head) ctx->head = conn;

    return conn;
} /* gre_create_conn */

static int
gre_process_socket(struct gre_ctx *ctx)
{
    struct gre_conn *conn;
    struct sockaddr_storage sas;
    socklen_t addrlen = sizeof(struct sockaddr_storage);
    struct gre_header gre;
    struct tun_header tun;
    char rxbuf[IP6_MTU + sizeof(struct gre_header)];
    int pktlen;

    struct iovec iov[] = {
        {.iov_base = &tun, .iov_len = sizeof(tun)},
        {.iov_base = rxbuf + sizeof(struct gre_header), .iov_len = 0},
    };

    /* Receive a packet from the tunnel device */
    pktlen = recvfrom(ctx->sockfd, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&sas, &addrlen);
    if (pktlen < 0) {
        fprintf(stderr, "recv() failed on GRE socket: %s\n", strerror(errno));
        return -1;
    }
    if (pktlen <= sizeof(struct gre_header)) {
        fprintf(stderr, "Truncated tunnel header, dropping packet.");
        return -1;
    }
    memcpy(&gre, rxbuf, sizeof(struct gre_header));
    fprintf(stderr, "Got GRE packet of length %d\n", pktlen);
    /* TODO: Parse optional GRE header data */

    /* We only care about IPv6 packets. */
    if ((gre.proto != htons(ETH_P_IPV6)) || (pktlen < sizeof(struct ip6_hdr)+sizeof(struct gre_header))) {
        fprintf(stderr, "Foreign protocol, dropping packet.");
        return -1;
    }

    /* Lookup the connection via the packet source. */
    conn = gre_lookup_conn(ctx, &sas);
    if (!conn) {
        /* No such connection? Create one! */
        /* TODO: DTLS cookie should go here to guard against DDoS */
        conn = gre_create_conn(ctx, &sas);
        if (!conn) {
            fprintf(stderr, "Failed to create GRE Connection, dropping packet\n");
            return -1;
        }
    }

    /* TODO: Validate Me! */
    /* TODO: Update connection timeout */

    /* Pass the packet into the kernel */
    tun.flags = 0;
    tun.proto = htons(ETH_P_IPV6);
    iov[0].iov_base = &tun;
    iov[1].iov_len = sizeof(tun);
    iov[1].iov_base = rxbuf + sizeof(struct gre_header);
    iov[1].iov_len = pktlen - sizeof(struct gre_header);
    return writev(conn->tunfd, iov, 2);
}

static int
gre_process_tunnel(struct gre_ctx *ctx, struct gre_conn *conn)
{
    struct gre_header gre;
    struct tun_header tun;
    struct msghdr msg;
    struct iovec iov[2];
    char rxbuf[IP6_MTU + sizeof(struct tun_header)];
    int pktlen;

    /* Receive a packet from the tunnel device */
    pktlen = read(conn->tunfd, rxbuf, sizeof(rxbuf));
    if (pktlen < 0) {
        fprintf(stderr, "read() failed on tunnel device: %s\n", strerror(errno));
        return -1;
    }
    if (pktlen <= sizeof(struct tun_header)) {
        fprintf(stderr, "Truncated tunnel header, dropping packet.");
        return -1;
    }
    memcpy(&tun, rxbuf, sizeof(struct tun_header));
    fprintf(stderr, "Got Tun packet of length %d\n", pktlen);


    /* We only care about IPv6 packets. */
    if ((tun.proto != htons(ETH_P_IPV6)) || (pktlen < sizeof(struct ip6_hdr)+sizeof(struct tun_header))) {
        fprintf(stderr, "Foreign protocol, dropping packet.");
        return -1;
    }

    /* TODO: Update connection timeout */

    /* Send the GRE packet to the remote host. */
    memset(&gre, 0, sizeof(gre));
    gre.flags = 0;
    gre.proto = htons(ETH_P_IPV6);
    gre.cksum = 0;
    gre.reserved = 0;

    iov[0].iov_base = &gre;
    iov[0].iov_len = sizeof(gre);
    iov[1].iov_base = rxbuf + sizeof(struct tun_header);
    iov[1].iov_len = pktlen - sizeof(struct tun_header);

    msg.msg_name = &conn->addr;
    msg.msg_namelen = sizeof(struct sockaddr_in6); /* FIXME! */
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return sendmsg(ctx->sockfd, &msg, 0);
}

int
gre_server_run(int sockfd)
{
    struct gre_ctx __ctx;
    struct gre_ctx *ctx = &__ctx;

    memset(ctx, 0, sizeof(struct gre_ctx));
    ctx->sockfd = sockfd;

    while (1) {
        fd_set rfd;
        struct gre_conn *conn;
        int maxfd = ctx->sockfd;
        int ret;

        /* Prepare the list of file descriptors to check. */
        FD_ZERO(&rfd);
        FD_SET(ctx->sockfd, &rfd);
        for (conn = ctx->head; conn; conn = conn->next) {
            FD_SET(conn->tunfd, &rfd);
            if (conn->tunfd > maxfd) maxfd = conn->tunfd;
        }

        /* Wait for socket activity */
        ret = select(maxfd+1, &rfd, NULL, NULL, NULL);
        if (ret == 0) continue;
        else if (ret < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "select() failed: %s\n", strerror(errno));
            }
            break;
        }

        if (FD_ISSET(sockfd, &rfd)) {
            gre_process_socket(ctx);
        }
        for (conn = ctx->head; conn; conn = conn->next) {
            if (!FD_ISSET(conn->tunfd, &rfd)) continue;
            gre_process_tunnel(ctx, conn);
        }
    }

    return 0;
}
