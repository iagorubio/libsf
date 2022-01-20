/*
 *  $Id: libsf_init.c,v 1.5 2002/02/18 20:01:08 route Exp $
 *
 *  libsf
 *  libsf_init.c - initilization routines
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

libsf_t *
libsf_init(u_char type, char *device, char *target, u_short o_port,
            u_short c_port, u_char flags, char *errbuf)
{
    libsf_t *s;
    u_long target_ip;

    s = (libsf_t *)malloc(sizeof(libsf_t));
    if (s == NULL)
    {
        snprintf(errbuf, LIBSF_ERRBUF_SIZE, "malloc: %s\n", strerror(errno));
        goto bad;
    }
    memset(s, 0, sizeof (libsf_t));

    /* open the libsf libnet descriptor */
    s->l = libnet_init(LIBNET_RAW4, device, errbuf);
    if (s->l == NULL)
    {
        goto bad;
    }

    /* set the device */
    if ((s->device = device) == NULL)
    {
        s->device = s->l->device;
    }

    /* get IP sddress from our device */
    s->ouraddr = libnet_get_ipaddr4(s->l);

    /* control flags */
    s->flags = flags;
    if (flags & LIBSF_CTRL_VERBOSE)
    {
        fprintf(stderr, "libsf: verbose mode enabled\n");
    }
    if (flags & LIBSF_CTRL_DEBUG)
    {
        fprintf(stderr, "libsf: debug mode enabled\n");
    }

    /* open libsf recv socket via pcap */
    s->p = pcap_open_live(s->device, 164, 0, 50, errbuf);
    if (s->p == NULL)
    {
        goto bad;
    }

    /* determine layer 3 offset for our pcap descriptor */
    switch (pcap_datalink(s->p))
    {
        case DLT_EN10MB:
            s->offset = 0x0e;
            break;
        case DLT_IEEE802:
            s->offset = 0x16;
            break;
        case DLT_FDDI:
            s->offset = 0x15;
            break;
        case DLT_NULL:
            s->offset = 0x04;
            break;
        default:
            sprintf(errbuf, "unsupported datalink type\n");
            goto bad;
    }

    /* open database */
    s->db = dbopen(LIBSF_DB_PATH, O_RDONLY, 0644, DB_BTREE, NULL);
    if (s->db == NULL)
    {
        sprintf(errbuf, "can't initialize database\n");
        goto bad;
    }

    /* set type specific scan parameters */
    switch (type)
    {
        case LIBSF_ACTIVE:
            s->type = LIBSF_ACTIVE;
            /* set default timeout value for active attempts */
            s->timeout = LIBSF_ACTIVE_TIMEOUT;

            /* initialize libnet ptags */
            s->ip = LIBNET_PTAG_INITIALIZER;
            s->tcp = LIBNET_PTAG_INITIALIZER;
            s->tcp_options = LIBNET_PTAG_INITIALIZER;

            /* seed the psuedo random number generator */
            libnet_seed_prand(s->l);

            /* set the source port */
            s->src_port = libnet_get_prand(LIBNET_PRu16);

            /* figure out the target IP */
            target_ip = libnet_name2addr4(s->l, target, LIBNET_RESOLVE);
            if (target_ip == -1)
            {
                sprintf(errbuf, "target `%s`: %s\n", target,
                        libnet_geterror(s->l));
                goto bad;
            }

            /* target initialization */
            if (libsf_target_init(s, target_ip, o_port, c_port) == -1)
            {
                strncpy(errbuf, s->err_buf, LIBSF_ERRBUF_SIZE);
                goto bad;
            }

            break;
        case LIBSF_PASSIVE:
            s->type = LIBSF_PASSIVE;
            /* set default timeout value for passive fingerprinting */
            s->timeout = LIBSF_PASSIVE_TIMEOUT;
            break;
        default:
            snprintf(errbuf, LIBSF_ERRBUF_SIZE, "unsupported scan type\n");
            goto bad;
    }

    return (s);
bad:
    libsf_destroy(s);
    return (NULL);
}


int
libsf_target_init(libsf_t *s, u_long address, u_short o_port, u_short c_port)
{
    if (s->type == LIBSF_PASSIVE)
    {
        s->t.addr        = address;
        s->t.port_open   = 0;
        s->t.port_closed = 0;
        s->t.g           = NULL;
        s->t.g_hs        = 0;
        s->t.g_num       = 0;

        return (1);
    }

    s->t.addr        = address;
    s->t.port_open   = o_port;
    s->t.port_closed = c_port;
    s->t.g           = NULL;
    s->t.g_hs        = 0;
    s->t.g_num       = 0;
    
    /*   
     *  If open_port is 0 then we'll scan for an open port, if it's
     *  specified then we'll use that one.
     */
    if (s->t.port_open == 0)
    {
        if ((s->flags) & LIBSF_CTRL_VERBOSE)
        {
            fprintf(stderr,
                "Performing active portscan to find open port...\n");
        }
        if (libsf_portscan(s, LIBSF_SCAN_OPEN) == -1)
        {
            return (-1);
        }
    }

    /*
     *  If closed_port is 0 then we'll scan for a closed port, if it's
     *  specified then we'll use that one.
     */
    if (s->t.port_closed == 0)
    {
        if ((s->flags) & LIBSF_CTRL_VERBOSE)
        {
            fprintf(stderr,
                "Performing active portscan to find closed port...\n");
        }
        if (libsf_portscan(s, LIBSF_SCAN_CLOSED) == -1)
        {
            return (-1);
        }
    }
    return (1);
}


int
libsf_set_timeout(libsf_t *s, u_short timeout)
{
    if (s == NULL)
    {
        return (-1);
    }
    return (s->timeout = timeout);
}


void
libsf_destroy(libsf_t *s)
{
    libsf_osg_t *p, *q;

    if (s)
    {
        if (s->l)
        {
            /* shutdown libnet */
            libnet_destroy(s->l);
        }
        if (s->p)
        {
            /* shutdown pcap */
            pcap_close(s->p);
        }
        if (s->t.g)
        {
            /* free the OS guess list */
            for (p = s->t.g; p; p = p->next)
            {
                free(p->name);
                q = p;
                free(q);
            }
        }
        free(s);
    }
}


char *
libsf_geterror(libsf_t *s)
{
    if (s == NULL)
    {
        return (NULL);
    }

    return (s->err_buf);
}

/* EOF */
