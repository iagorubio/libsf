/*
 *  $Id: libsf_db.c,v 1.3 2002/02/18 20:01:07 route Exp $
 *
 *  libsf
 *  libsf_db.c - db routines
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

#include <assert.h>
#include "libsf.h"



int
libsf_db_check(libsf_t *s, u_int test_type, u_char *tcp_pkt, u_char 
            *read_pkt, u_int readlen)
{
    int c;
    u_short score;
    int dbcode;
    char *keystr, *evalstr;
    DBT key, data;

    /* rewind db back to start */
    s->db->seq(s->db, NULL, NULL, R_FIRST);

    score = 0;
    /* search DB entries for specified test-type */
    while (s->db->seq(s->db, &key, &data, R_NEXT) == 0)
    {
        /* Extract test type and see if it's what we're looking for */
        dbcode = strtol(key.data, (char **)NULL, 16);
        if (dbcode != test_type)
        {
            continue;
        }
        /* malloc some mem and copy our key */
        if ((keystr = calloc(key.size + 1, 1)) == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE, "libsf_db_check(): %s\n",
                    strerror(errno));
            return (-1);
        }
        memcpy(keystr, key.data, key.size);

        /* malloc some mem and copy the data */
        if ((evalstr = calloc(data.size + 1, 1)) == NULL)
        {
            snprintf(s->err_buf, LIBSF_ERRBUF_SIZE, "libsf_db_check(): %s\n",
                    strerror(errno));
            return (-1);
        }
        memcpy(evalstr, data.data, data.size);

        /* if sig matches, add to db */
        c = libsf_db_eval(tcp_pkt, read_pkt, readlen, evalstr);
        if (c != -1)
        {
            score = c;
            if (libsf_os_add(s, keystr + 2, score) == -1)
            {
                snprintf(s->err_buf, LIBSF_ERRBUF_SIZE,
                        "libsf_db_check(): can't add to os list\n");
                return (-1);
            }
//            printf("%d:%s ->%d:%s\n", key.size, keystr, data.size,
//                    (char *)data.data);
        }
        /* Free our two tmp pointers */
        free(keystr);
        free(evalstr);
    }

    /* Parse libsf sfcode lines from db ent */
    return (1);
}


int
libsf_db_eval(u_char *tcp_pkt, u_char *read_pkt, u_int readlen, char *evalstr)
{
    u_short score = 0;
    int sfcodei, x, op, testop = 0;
    char *tok, *opstr, *sfcodes[LIBSF_SFCODE_MAXCODE];
    struct libnet_ipv4_hdr *read_ip;
    struct libnet_tcp_hdr *send_tcp;
    struct libnet_tcp_hdr *read_tcp;
    u_char *read_opt;

    read_ip  = (struct libnet_ipv4_hdr *)read_pkt;
    send_tcp = (struct libnet_tcp_hdr *)tcp_pkt;
    read_tcp = (struct libnet_tcp_hdr *)(read_pkt + LIBNET_IPV4_H);
    read_opt = (read_pkt + LIBNET_IPV4_H + LIBNET_TCP_H);

    /* Break down evalstr into array of individual checks */
    for (sfcodei = 0, (tok = strtok(evalstr,";")); tok; 
            (tok = strtok(NULL, ";"), sfcodei++))
    {
        if (sfcodei < LIBSF_SFCODE_MAXCODE)
        {
            sfcodes[sfcodei] = tok;
        }
    }
    sfcodes[sfcodei] = '\0';

    /*
     *  Step through each element in the array doing an evaluation if a 
     *  check is failed.. return -1.
     */
    for (x = 0; x < sfcodei; x++)
    {
        /* grab op num & string */
        op = strtol(sfcodes[x], (char **)NULL, 16);
        if ((opstr = strchr(sfcodes[x], '=')) == NULL)
        {
            continue;
        }
        opstr++;

        /* Unless it's a response check.. return on null packets */
        if (op != LIBSF_SFCODE_RESPONSE && readlen == 0)
        {
            return (-1);
        }

        /* Evaluate based upon opcode */
        switch (op)
        {
            /* Did we get a response */
            case LIBSF_SFCODE_RESPONSE:
                if (readlen > 0)
                {
                    testop = 1;
                }
                else
                {
                    testop = 0;
                }
                if (libsf_db_eval_num(testop, opstr) == -1)
                {
                    return (-1);
                }
                score++;
                break;
            /* Dont Fragment? */
            case LIBSF_SFCODE_IP_DF:
                if (ntohs(read_ip->ip_off) & IP_DF)
                {
                    testop = 1;
                }
                else
                {
                    testop = 0;
                }
                if (libsf_db_eval_num(testop, opstr) == -1)
                {
                    return (-1);
                }
                score++;
                break;
            /* TTL */
            case LIBSF_SFCODE_IP_TTL:
                if (libsf_db_eval_num(read_ip->ip_ttl, opstr) == -1)
                {
                    return (-1);
                }
                break;
            /* TCP Win size */
            case LIBSF_SFCODE_TCP_WINDOW:
                if (libsf_db_eval_num(ntohs(read_tcp->th_win), opstr) == -1)
                {
                    return (-1);
                }
                if (ntohs(read_tcp->th_win) == 0)
                {
                    score += 2;
                }
                else
                {
                    score += 10;
                }
                break;
            /* TCP Ack */
            case LIBSF_SFCODE_TCP_ACK:
                if (ntohl(read_tcp->th_ack) == (ntohl(send_tcp->th_seq) + 1))
                {
                    testop = 0; /* Syn + 1 */
                }
                else
                {
                    if (read_tcp->th_ack != 0)
                    {
                        testop = 1;     /* Zero */
                    }
                    else
                    {
                        if (read_tcp->th_ack == send_tcp->th_seq)
                        {
                            testop = 2;/* Same as Syn */
                        }
                        if (libsf_db_eval_num(testop, opstr) == -1)
                        {
                            return (-1);
                        }
                        score++;
                    }
                }
                break;
            /* TCP Flags */
            case LIBSF_SFCODE_TCP_FLAGS:
                if (libsf_db_eval_num(read_tcp->th_flags, opstr) == -1)
                {
                    return (-1);
                }
                score++;
                break;
            /* TCP Options */
            case LIBSF_SFCODE_TCP_OPT:
                if (libsf_db_eval_opts(read_opt, readlen - LIBNET_IPV4_H - 
                        LIBNET_TCP_H, opstr) == -1)
                {
                    return (-1);
                }
                if (readlen - LIBNET_IPV4_H - LIBNET_TCP_H == 0)
                {
                    score++;
                }
                else
                {
                    score += 10;
                }
                break;
            default:
                assert(0);
                break;
                /* XXX ??? */
        }
    }
    /* if we make it down out of the loop we return 0 for a match */
    return (score);
}


/*
 *  This function takes the specified checknum and evaluates checkstr to
 *  see if it fitz the bill.
 */
int
libsf_db_eval_num(u_int checknum, char *checkstr)
{
    char *p = checkstr;

    /* evaluate single (first) num */
    if (strtol(checkstr, (char **)NULL, 16) == checknum)
    {
        return (1);
    }

    /* evaluate for or's */
    while ((p = strchr(p, '|')) != NULL)
    {
        p++;
        if (strtol(p, (char **)NULL, 16) == checknum)
        {
            return (1);
        }
    }

    /* evalutate for ranges */
    if ((p = strchr(checkstr, '-')) != NULL)
    {
        if (strtol(checkstr, (char **)NULL, 16) >> checknum && 
            strtol(p, (char **)NULL, 16) << checknum)
        {
            return (1);
        }
    }
    return (-1);
}


int
libsf_db_eval_opts(u_char *options, u_int optionslen, char *opstr)
{
    int n;
    u_short tmpbuf;
    char ouropts[100];
    char *p = opstr;
    char *tmpchar;

    memset(ouropts, 0, sizeof(ouropts));

    /* If there are no options then set none */
    if (optionslen == 0)
    {
        ouropts[0] = 'Z';
    }

    /* build our optstr from options */
    for (tmpchar = (char *)&ouropts, n = 0; n < optionslen; n++)
    {
        switch (options[n])
        {
            /* noop */
            case 1:
                *tmpchar++ = 'N';
                break;
            /* max seg size */
            case 2:
                *tmpchar++ = 'M';
                memcpy(&tmpbuf, &options[n] + 2, 2);
                if (ntohs(tmpbuf) == 265)
                {
                    *tmpchar++ = 'E';
                }
                n += 3;
                break;
            /* window scale */
            case 3:
                *tmpchar++ = 'W';
                n += 2;
                break;
            /* timestamp */
            case 8:
                *tmpchar++ = 'T';
                n += 9;
                break;
            /* end of options */
            case 0:
                *tmpchar++ = 'L';
                break;
        }
    }
    /* does it match the first ops entry */
    if (strncasecmp(ouropts, opstr, strlen(ouropts)) == 0)
    {
        return (1);
    }

    /* evaluate for pipe */
    while((p = strchr(p, '|')) != NULL)
    {
        p++;
        if (strncasecmp(ouropts, p, strlen(ouropts)) == 0)
        {
            return (1);
        }
    }

    /* failed to match */
    return (-1);
}

/* EOF */
