/*
 *  $Id: libsf_scan_tcp.c,v 1.2 2002/03/26 01:28:08 route Exp $
 *
 *  libsf
 *  libsf_scan_tcp.c - TCP scanning routines
 *
 *  Copyright (c) 2002 Shawn Bracken <shawn@infonexus.com>
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "libsf.h"

int
libsf_scan_tcp(libsf_t *s, u_int test_type)
{
    u_int c, d;
    u_short dest_port;
    u_char *tcp_buf, *read_buf, flags;

    if (s == NULL)
    {
        return (-1);
    }

    /* set flags and destination port based on test_type */
    switch (test_type)
    {
        case LIBSF_ACTIVE_OPTSYN:
            flags = TH_SYN;
            dest_port = s->t.port_open;
            break;
        case LIBSF_ACTIVE_OPTNULL:
            flags = 0;
            dest_port = s->t.port_open;
            break;
        case LIBSF_ACTIVE_OPTSFUP:
            flags = TH_SYN | TH_FIN | TH_URG | TH_PUSH;
            dest_port = s->t.port_open;
            break;
        case LIBSF_ACTIVE_OPENACK:
            flags = TH_ACK;
            dest_port = s->t.port_open;
            break;
        case LIBSF_ACTIVE_CLOSESYN:
            flags = TH_SYN;
            dest_port = s->t.port_closed;
            break;
        case LIBSF_ACTIVE_CLOSEACK:
            flags = TH_ACK;
            dest_port = s->t.port_closed;
            break;
        case LIBSF_ACTIVE_CLOSEFPU:
            flags = TH_FIN | TH_PUSH | TH_URG;
            dest_port = s->t.port_closed;
            break;
        default:
            sprintf(s->err_buf, "unknown test type\n");
            return (-1);
    }

    s->tcp_options = libnet_build_tcp_options(
            LIBSF_TCP_OPTSTR,                   /* option string */
            20,                                 /* option size */
            s->l,                               /* libnet handle */
            s->tcp_options);                    /* ptag */
    if (s->tcp_options == -1)
    {
        snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_scan_tcp(): %s\n", libnet_geterror(s->l));
        return (-1);
    }

    s->tcp = libnet_build_tcp(
            s->src_port,                        /* source port */
            dest_port,                          /* destination port */
            libnet_get_prand(LIBNET_PRu32),     /* sequence number */
            0,                                  /* acknowledgement number */
            flags,                              /* control */
            2048,                               /* window size */
            0,                                  /* checksum */
            0,                                  /* urgent pointer */
            LIBNET_TCP_H + 20,                  /* header + options */
            NULL,                               /* payload */
            0,                                  /* payload size */
            s->l,                               /* libnet handle */
            s->tcp);                            /* ptag */
    if (s->tcp == -1)
    {
        snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_scan_tcp(): %s\n", libnet_geterror(s->l));
        return (-1);
    }

    s->ip = libnet_build_ipv4(
            LIBNET_TCP_H + LIBNET_IPV4_H + 20,
            0,                                  /* TOS */
            libnet_get_prand(LIBNET_PRu16),     /* IP id */
            0,                                  /* frag */
            64,                                 /* TTL */
            IPPROTO_TCP,                        /* protocol */
            0,                                  /* checksum */
            s->ouraddr,                         /* source */
            s->t.addr,                          /* target */
            NULL,                               /* payload */
            0,                                  /* payload size */
            s->l,                               /* libnet handle */
            s->ip);                             /* ptag */
    if (s->ip == -1)
    {
        snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_scan_tcp(): %s\n", libnet_geterror(s->l));
        return (-1);
    }

    /* write packet to network */
    c = libnet_write(s->l);
    if (c == -1)
    {
        snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_scan_tcp(): %s\n", libnet_geterror(s->l));
        return (-1);
    }

    /* read response from target */
    d = libsf_get_response(s, s->ouraddr, s->src_port, s->t.addr, dest_port,
            &read_buf);
    if (d == -1)
    {
        /* errmsg set in libsf_get_response */
        return (-1);
    }

    /*
     *  Get the TCP header we just built.
     */
    tcp_buf = libnet_getpbuf(s->l, s->tcp);
    if (tcp_buf == NULL)
    {
        sprintf(s->err_buf, "libsf_scan_tcp(): %s\n",
                libnet_geterror(s->l));
        return (-1);
    }

    /*
     *  Check with database for signature hits and load them into osguess
     *  array in target struct.
     */
    if (libsf_db_check(s, test_type, tcp_buf, read_buf, d) == -1)
    {
        sprintf(s->err_buf, "libsf_db_check(): %s\n", strerror(errno));
        return (-1);
    }

    return (1);
}
