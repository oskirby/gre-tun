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
#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "gre.h"

/* Why is this not defined in a header? */
struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

/* Allocate a new tunnel interface and link-local address */
int
gre_allocate_tun(void)
{
    struct in6_ifreq ifr6;
    struct ifreq ifr;
    int sock;
    int tunfd;
    int ret;
    int i;

    /* Create the tunnel device. */
    tunfd = open("/dev/net/tun", O_RDWR);
    if (tunfd < 0) {
        fprintf(stderr, "Failed to open tunnel device: %s\n", strerror(errno));
        return -1;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, "gre%d", IFNAMSIZ);
    ret = ioctl(tunfd, TUNSETIFF, (void *)&ifr);
    if (ret < 0) {
        fprintf(stderr, "Failed to configure tunnel device: %s\n", strerror(errno));
        close(tunfd);
        return -1;
    }

    /* Query the flags to determine what ifname we got. */
    ret = ioctl(tunfd, TUNGETIFF, (void *)&ifr);
    if (ret < 0) {
        fprintf(stderr, "Failed to query tunnel device: %s\n", strerror(errno));
        close(tunfd);
        return -1;
    }
    fprintf(stderr, "Created tunnel interface: %s\n", ifr.ifr_name);

    /* To bring up the interface, we need a socket */
    sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        close(tunfd);
        return -1;
    }

    /* Generate a random link-local IPv6 address. */
    /* Is this even necessary? Or will the kernel do it for us on IFF_UP? */
    ret = ioctl(sock, SIOGIFINDEX, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Failed to determine ifindex: %s\n", strerror(errno));
        close(tunfd);
        close(sock);
        return -1;
    }
    memset(&ifr6, 0, sizeof(ifr6));
    ifr6.ifr6_ifindex = ifr.ifr_ifindex;
    ifr6.ifr6_prefixlen = 64;
    ifr6.ifr6_addr.s6_addr[0] = 0xfe;
    ifr6.ifr6_addr.s6_addr[1] = 0x80;
    for (i = 8; i < sizeof(ifr6.ifr6_addr.s6_addr); i++) {
        ifr6.ifr6_addr.s6_addr[i] = rand() & 0xff;
    }
    ifr6.ifr6_addr.s6_addr[8] |= 0x02; /* flag this as an generated */
    ret = ioctl(sock, SIOCSIFADDR, &ifr6);
    if (ret < 0) {
        fprintf(stderr, "Failed to set IPv6 address: %s\n", strerror(errno));
        close(tunfd);
        close(sock);
        return -1;
    }

    /* Bring the interface up. */
    ifr.ifr_flags = IFF_UP;
    ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Failed bring interface %s up: %s\n", ifr.ifr_name, strerror(errno));
        close(tunfd);
        close(sock);
        return -1;
    }

    close(sock);
    return tunfd;
} /* gre_allocate_tun */
