/*
 *  $Id: libsf_active_id.c,v 1.3 2002/02/10 23:14:52 route Exp $
 *
 *  libsf
 *  libsf_active_id.c - active fingerprinting routines
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
libsf_active_id(libsf_t *s)
{
    int c;

    if (s == NULL)
    {
        return (-1);
    }

    /*
     *  TCP SYN packet to an open port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_OPTSYN);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTSYN %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTSYN succeeded\n");
        }
    }

    /*
     *  TCP "NULL" packet to an open port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_OPTNULL);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTNULL %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTNULL succeeded\n");
        }
    }

    /*
     *  TCP SYN|FIN|URG|PSH packet to an open port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_OPTSFUP);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTSFUP %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPTSFUP succeeded\n");
        }
    }

    /*
     *  TCP ACK packet to an open port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_OPENACK);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPENACK %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_OPENACK succeeded\n");
        }
    }

    /*
     *  TCP SYN packet to a closed port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_CLOSESYN);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSESYN %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSESYN succeeded\n");
        }
    }

    /*
     *  TCP ACK packet to a closed port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_CLOSEACK);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSEACK %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSEACK succeeded\n");
        }
    }

    /*
     *  TCP FIN|PSH|URG packet to a closed port with options.
     */
    c = libsf_scan_tcp(s, LIBSF_ACTIVE_CLOSEFPU);
    if ((s->flags) & LIBSF_CTRL_VERBOSE)
    {
        if (c == -1)
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSEFPU %s\n", s->err_buf);
        }
        else
        {
            fprintf(stderr, "LIBSF_ACTIVE_CLOSEFPU succeeded\n");
        }
    }

    return (1);
}

/* EOF */
