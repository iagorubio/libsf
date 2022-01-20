/*
 *  $Id: libsf_get_response.c,v 1.3 2002/02/18 20:01:07 route Exp $
 *
 *  libsf
 *  libsf_get_response.c - response receiving routines
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
libsf_get_response(libsf_t *s, u_long source_addr, u_short source_port,
        u_long dest_addr, u_short dest_port, u_char **packet)
{
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;
    struct pcap_pkthdr pph;
    time_t start;
    char filter[128];

    /* build filter string */
    sprintf(filter, LIBSF_ACTIVE_FILTER, libnet_addr2name4(dest_addr, 0),
            source_port, dest_port);

    /* set the filter for the packet we're expecting */
    if (libsf_set_filter(s, filter) == -1)
    {
        sprintf(s->err_buf, "libsf_get_response: can't set filter %s",
            pcap_geterr(s->p));
        return (-1);
    }

    /*
     *  Descend into our packet capturing loop, only stopping when our
     *  timeout is reached.
     *  XXX - This is broken and should have an asynchronous wake up event 
     *  otherwise we could sleep forever on a broken or quiet network.
     */
    for (start = time(NULL); (time(NULL) - start) < s->timeout; )
    {
        if ((*packet = (u_char *)pcap_next(s->p, &pph)) == NULL)
        {
            continue;
        }

        ip = (struct libnet_ipv4_hdr *)(*packet + s->offset);
        switch (ip->ip_p)
        {
            case IPPROTO_TCP:
                tcp = (struct libnet_tcp_hdr *)(*packet + s->offset +
                        (ip->ip_hl << 2));
                /* does it match our reverse four-touple? */
                if (ip->ip_src.s_addr == dest_addr && ip->ip_dst.s_addr == 
                    source_addr && ntohs(tcp->th_sport) ==
                    dest_port && ntohs(tcp->th_dport) == source_port)
                {
                    /* adjust pointer to remove eth */
                    *packet = (*packet + s->offset);
                    return (ntohs(ip->ip_len));
                }
                break;
            default:
                continue;
        }
    }
    sprintf(s->err_buf, "libsf_get_response(): timer expired");
    return (-1);
}


/* EOF */
