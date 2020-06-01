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
#ifndef _GRE_H
#define _GRE_H

#include <stdint.h>

#define GRE_PORT_UDP    4754
#define GRE_PORT_DTLS   4755

#define GRE_FLAGS_C     (1 << 0)    /* Checksum Present */
#define GRE_FLAGS_K     (1 << 2)    /* Key Present */
#define GRE_FLAGS_S     (1 << 3)    /* Sequence Number Present */
#define GRE_FLAGS_VER   (0x7 << 13)

/* GRE Packet Header */
struct gre_header {
    uint16_t flags;     /* GRE_FLAGS_xxx */
    uint16_t proto;     /* Ethertype */
    uint16_t cksum;
    uint16_t reserved;
    /* Optional Key and Sequence numbers follow */
    uint32_t extra[];
};

#define IP6_MTU 1280

/* Linux Tun/Tap frame header. */
struct tun_header {
    uint16_t flags;     /* ??? */
    uint16_t proto;     /* Ethertype */
};

/* Run the tunnel interface. */
int gre_server_run(int sockfd);
int gre_client_run(int sockfd);
int gre_allocate_tun(void);

#endif /* _GRE_H */
