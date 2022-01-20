/*
 *  $Id: libsf_os.c,v 1.3 2002/02/18 20:01:08 route Exp $
 *
 *  libsf
 *  libsf_os.c - OS <--> DB routines
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
libsf_os_add(libsf_t *s, char *candidate, u_short score)
{
    libsf_osg_t *p, *q;

    /* search the oslist for candidate os */
    for (p = s->t.g, q = NULL; p; q = p, p = p->next)
    {
        /* existing entry? */
        if (strcmp(p->name, candidate) == 0)
        {
            /* increment score */
            p->score += score;

            /* set high score */
            p->score > s->t.g_hs ? s->t.g_hs = p->score : 0;
            return (1);
        }
    }

    if (s->t.g == NULL)
    {
        /* otherwise create a new entry */
        s->t.g = malloc(sizeof(libsf_osg_t));
        if (s->t.g == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_os_add(): malloc %s\n", strerror(errno));
            return (-1);
        }

        s->t.g->name = strdup(candidate);
        if (s->t.g->name == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                    "libsf_os_add(): strdup %s\n", strerror(errno));
            return (-1);
        }
        s->t.g->score = score;

        /* set high score */
        s->t.g->score > s->t.g_hs ? s->t.g_hs = s->t.g->score : 0;

        s->t.g->next = NULL;
    }
    else
    {
        q->next = malloc(sizeof(libsf_osg_t));
        if (q->next == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_os_add(): malloc %s\n", strerror(errno));
            return (-1);
        }
        q = q->next;

        q->name = strdup(candidate);
        if (q->name == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                "libsf_os_add(): strdup %s\n", strerror(errno));
            return (-1);
        }
        q->score = score;

        /* set high score */
        q->score > s->t.g_hs ? s->t.g_hs = q->score : 0;

        q->next = NULL;
    }
    /* increment OS count */
    s->t.g_num++;

    return (1);
}


int
libsf_os_get_hs(libsf_t *s)
{
    if (s == NULL)
    {
        return (-1);
    }

    return (s->t.g_hs);
}


int
libsf_os_get_tm(libsf_t *s)
{
    if (s == NULL)
    {
        return (-1);
    }

    return (s->t.g_num);
}


int
libsf_os_reset_counter(libsf_t *s)
{
    if (s == NULL)
    {
        return (-1);
    }

    /* reset the last counter */
    s->t.last = 0;
    return (1);
}


char *
libsf_os_get_match(libsf_t *s, u_short score)
{
    int n;
    libsf_osg_t *p;

    if (s == NULL)
    {
        return (NULL);
    }

    for (p = s->t.g, n = 0; p && n < s->t.last; p = p->next, n++) ;

    for (; p; p = p->next, n++)
    {
        if (p->score == score)
        {
            s->t.last = ++n;
            return (p->name);
        }
    }

    /* return the os's for the score specified */
    return (NULL);
}


char *
libsf_os_get_next(libsf_t *s)
{
    int n;
    libsf_osg_t *p;

    if (s == NULL)
    {
        return (NULL);
    }

    for (p = s->t.g, n = 0; p && n < s->t.last; p = p->next, n++) ;

    if (p == NULL)
    {
        return (NULL);
    }
    else
    {
        s->t.last++;
        return (p->name);
    }
}


/* EOF */
