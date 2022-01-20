/*
 *  $Id: libsf_passive_id.c,v 1.4 2002/02/18 20:01:08 route Exp $
 *
 *  libsf
 *  libsf_passive_id.c -
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
libsf_passive_id(libsf_t *s)
{
    /* set the filter for the packet we're expecting */
    if (libsf_set_filter(s, LIBSF_PASSIVE_FILTER) == -1)
    {
        sprintf(s->err_buf, "libsf_passive_id: can't set filter %s",
            pcap_geterr(s->p));
        return (-1);
    }

    /* XXX passive detection is not implemented yet */
    for (;/* need a termination conditions here */;)
    {
        pcap_loop(s->p, 1, libsf_passive_scan, (u_char *)s);
        /* depending on what pt contains -- return some value */
    }
    return (-1);
}


void
libsf_passive_scan(u_char *libsf_handle, const struct pcap_pkthdr *ph,
        const u_char *packet)
{
    libsf_t *s;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;

    s = (libsf_t *)libsf_handle;

    ip  = (struct libnet_ipv4_hdr *)(*packet + s->offset);
    tcp = (struct libnet_tcp_hdr *)(*packet + s->offset + (ip->ip_hl << 2));

    /* we only want SYN packets */
    if (!((tcp->th_flags) & TH_SYN))
    {
        return;
    }
    if ((tcp->th_flags) & TH_ACK)
    {
        return;
    }

    /* gather state */

    /* IP TTL */
    s->pt.ip_ttl = ip->ip_ttl;

    /* IP total length */
    s->pt.ip_len = ntohs(ip->ip_len);

    /* IP DF bit */
    s->pt.ip_df  = ((ip->ip_off & 0x4000) ? 1 : 0);

    /* IP src and dst */
    s->pt.ip_src = ntohl(ip->ip_src.s_addr);
    s->pt.ip_dst = ntohl(ip->ip_dst.s_addr);

    /* TCP options */
    /* ... */
    return;
}
