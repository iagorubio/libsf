/*
 *  $Id: libsf_portscan.c,v 1.3 2002/02/10 23:14:53 route Exp $
 *
 *  libsf
 *  libsf_portscan.c -
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
libsf_portscan(libsf_t *s, u_char scantype)
{
    int i;
    u_short scanport;
    u_short guessports[] = LIBSF_SCAN_GUESSPORTS;
    struct sockaddr_in sendaddr;

    sendaddr.sin_addr.s_addr = s->t.addr;
    sendaddr.sin_family = AF_INET;

    /* scan our "good guess" port numbers */
    for (i = 0; guessports[i] != 0; i++)
    {
        sendaddr.sin_port = htons(guessports[i]);
        if (libsf_portscan_connect(s, scantype, &sendaddr,
                sizeof(sendaddr)) == 1)
        {
            return (1);
        }
    }
    /* scan 1 - 1024 */
    for (scanport = 1; scanport < 1024; scanport++)
    {
        sendaddr.sin_port = htons(scanport);
        /* scan until we find what we're looking for */
        if (libsf_portscan_connect(s, scantype, &sendaddr, 
                sizeof(sendaddr)) == 1)
        {
            return (1);
        }
    }
    sprintf(s->err_buf, "libsf_portscan(): no open ports\n");
    return (-1);
}


int
libsf_portscan_connect(libsf_t *s, u_char scantype, struct sockaddr_in *ouraddr,
            u_int ouraddrlen)
{
    int fd, c;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
    {
        sprintf(s->err_buf, "libsf_portscan_connect(): socket %s\n",
            strerror(errno));
        return (-1);
    }

    c = connect(fd, (struct sockaddr *)ouraddr, ouraddrlen);
    close(fd);

    /* do some crafty/intelligent port info storing */
    switch (scantype)
    {
        case LIBSF_SCAN_OPEN:
            if (c == 0)
            {
                s->t.port_open = ntohs(ouraddr->sin_port);
                return (1);
            }
            else
            {
                /*
                 *  If we find a closed port while we're scanning for an open 
                 *  one, and we're going to need to search later; make a note
                 *  of it here instead.
                 */
                if (s->t.port_closed == 0)
                {
                    s->t.port_closed = ntohs(ouraddr->sin_port);
                }
            }
            break;
        case LIBSF_SCAN_CLOSED:
            if (c == -1)
            {
                s->t.port_closed = ntohs(ouraddr->sin_port);
                return (1);
            }
            break;
        default:
            return (-1);
    }
    return (-1);
}

/* EOF */
