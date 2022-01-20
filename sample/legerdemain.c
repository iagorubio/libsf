/*
 *  $Id: fingerprint.c,v 1.1.1.1 2001/12/27 07:39:48 route Exp $
 *
 *  libsf
 *  fingerprinting.c - simple fingerprinting application
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

#include "../include/config.h"
#include "../src/libsf.h"

void usage(char *);

int
main(int argc, char *argv[])
{
    int c;
    int dump_all_guesses;
    libsf_t *s;
    char *guess;
    char *device;
    u_char flags;
    u_short hs, tm;
    char errbuf[LIBSF_ERRBUF_SIZE];

    flags = 0;
    device = NULL;
    dump_all_guesses = 0;
    while ((c = getopt(argc, argv, "ai:v")) != EOF)
    {
        switch (c)
        {
            case 'a':
                dump_all_guesses = 1;
                break;
            case 'i':
                device = optarg;
                break;
            case 'v':
                flags = LIBSF_CTRL_VERBOSE;
                break;
            default:
                break;
        }
    }

    c = argc - optind;
    if (c != 1)
    {
        usage(argv[0]);
        return (EXIT_FAILURE);
    }

    printf("Legerdemain 1.0 [remote operating system detection tool]\n");


    /*
     *  Initialize libsf with the following options:
     *
     *  LIBSF_ACTIVE -  An active fingerprint scan
     *  device       -  Let libsf (libnet) determine a device
     *                  or the user if specified
     *  argv[optins] -  User specified target IP address
     *  0            -  Probe for an open TCP port
     *  1            -  Use 1 as a closed TCP port
     *  flags        -  User speficied flags
     *  errbuf       -  Holds any possible initialization errors
     */
    s = libsf_init(LIBSF_ACTIVE, device, argv[optind], 0, 1, flags, errbuf);
    if (s == NULL)
    {
        fprintf(stderr, "error creating libsf handle: %s\n", errbuf);
        return (EXIT_FAILURE);
    }

    printf("Host: %s, found open port: %d and closed port: %d\n",
           argv[optind], s->t.port_open, s->t.port_closed);

    printf("Performing active fingerprint scan...\n");

    if (libsf_active_id(s) == -1)
    {
        fprintf(stderr, "libsf_active_id %s\n", libsf_geterror(s));
    }
    else
    {
        /* get the total number of matches */
        tm = libsf_os_get_tm(s);

        /* get the high score */
        hs = libsf_os_get_hs(s);

        printf("%d potential matches (highest score of %d)\n", tm, hs);
        printf("Highest scored OS guesses:\n");

        /* run through the OS list, dumping string that matches score */
        while ((guess = libsf_os_get_match(s, hs)))
        {
            printf("%s\n", guess);
        }
        if (dump_all_guesses)
        {
            printf("All OS guesses:\n");
            libsf_os_reset_counter(s);
            while ((guess = libsf_os_get_next(s)))
            {
                printf("%s\n", guess);
            }
        }
    }
    libsf_destroy(s);

    return (EXIT_SUCCESS);
}

void
usage(char *name)
{
    fprintf(stderr, "usage %s [options] target\n"
                    "-a\t\tdump all guesses\n"
                    "-i device\tspecify a device\n"
                    "-v\t\tbe verbose\n", name);
}

/* EOF */
