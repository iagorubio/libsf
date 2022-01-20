/*
 *  $Id: libsf_import.c,v 1.1 2002/02/18 20:01:04 route Exp $
 *
 *  libsf
 *  libsf_import.c - db importing program
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  Copyright (c) 2002 Shawn Bracken <shawn@infonexus.com>
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

#include <getopt.h>
#include <strings.h>
#include "libsf_import.h"

int
main(int argc, char *argv[])
{
    int c, mode;
    DB *db;
    FILE *fp;

    mode = 0;
    while ((c = getopt(argc, argv, "ap")) != EOF)
    {
        switch (c)
        {
            case 'a':
                mode = ACTIVE_IMPORT;
                break;
            case 'p':
                mode = PASSIVE_IMPORT;
                break;
            default:
                break;
        }
    }

    c = argc - optind;
    if (c != 1)
    {
        usage(argv[0]);
        exit (EXIT_FAILURE);
    }

    switch (mode)
    {
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        case PASSIVE_IMPORT:
            fprintf(stderr, "Passive importing not supported yet\n");
            exit(EXIT_FAILURE);
        case ACTIVE_IMPORT:
            break;
            /* fall through */
    }

    fp = fopen(argv[optind], "r");
    if (fp == NULL)
    {
        perror("main(): error opening nmap fingerprint file"),
        exit(EXIT_FAILURE);
    }

    /* open database file descriptor */
    db = dbopen(LIBSF_DB_FILE, O_CREAT|O_RDWR, 0644, DB_BTREE, NULL);
    if (db == NULL)
    {
        perror("main(): error opening libsf db file");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr,
            "Importing signatures from `%s` this could take a while...\n",
            argv[optind]);
    fprintf(stderr, "Each '.' is 10 signatures imported.\n");
    fprintf(stderr, "Each '-' and '~' are importing / adding errors.\n");

    if ((c = db_import(fp, db)) == -1)
    {
        fprintf(stderr,
            "Grevious error in importing signatures, db may be unusable\n");
        return (EXIT_FAILURE);
    }
    fprintf(stderr, "\nCompleted, imported %d signatures\n", added);
    return (EXIT_SUCCESS);
}


int
db_import(FILE *nmap, DB *db)
{
    int l, i;
    char buf[1024], /* work buffer, holds lines from file */
    stack_tag[256]; /* device tag of IP stack fingerprint */

    /* run through file, line by line */
    for (l = 0; fgets(buf, (sizeof(buf)) - 1, nmap); l++)
    {
        /* ignore comments and blank lines */
        if (buf[0] == '#' || buf[0] == '\n')
        {
            continue;
        }
        /* did we find a fingerprint starter tag? */
        if (strncasecmp(buf, "fingerprint", 11) == 0)
        {
            /* if there's a comment in there, remove it */
            for (i = 0; buf[i]; i++)
            {
                if (buf[i] == '#')
                {
                    buf[i] = '\0'; //NULL;
                }
            }
            /* get stack tag */
            strncpy(stack_tag, buf + 12, sizeof(stack_tag) - 1);
            stack_tag[strlen(stack_tag) - 1] = '0'; //NULL;

            /* go get another line */
            continue;
        }
        /* add to db */
        if (db_add(db, stack_tag, buf) == -1)
        {
            fprintf(stderr, "-");
            return (-1);
        }
        else
        {
            added++;
            if (added % 10 == 0)
            {
                fprintf(stderr, ".");
            }
        }
    }
    return (1);
}


int
db_add(DB *dbptr, char *stack_tag, char *buf)
{
    DBT dbkey, dbdata;
    int i, test_type;
    char *p,    /* all purpose pointer */
       *token,
       *tests[LIBSF_SFCODE_MAXCODEARGS + 1],  /* sub array of test results */
       *sfcode;

    /*
     *  Start by figuring out which test this line refers to...
     */

    /* TCP sequence number test...? */
    if (strncasecmp(buf, "TSeq", 4) == 0)
    {
        /* XXX - we don't support TCP sequence number sampling yet */
        return (-2);
        /* test_type = LIBSF_ACTIVE_TSEQ; */
    }
    /* TCP test type...? */
    else if (buf[0] == 'T')
    {
        switch (atoi(buf + 1))
        {
            case 1:
                test_type = LIBSF_ACTIVE_OPTSYN;
                break;
            case 2:
                test_type = LIBSF_ACTIVE_OPTNULL;
                break;
            case 3:
                test_type = LIBSF_ACTIVE_OPTSFUP;
                break;
            case 4:
                test_type = LIBSF_ACTIVE_OPENACK;
                break;
            case 5:
                test_type = LIBSF_ACTIVE_CLOSESYN;
                break;
            case 6:
                test_type = LIBSF_ACTIVE_CLOSEACK;
                break;
            case 7:
                test_type = LIBSF_ACTIVE_CLOSEFPU;
                break;
            default:
                fprintf(stderr, "Unsupported test type: %d\n", atoi(buf + 1));
                return (-1);
        }
    }
    /* UDP test...? */
    else if (buf[0] == 'P')
    {
        /* XXX - we don't support UDP yet */
        return (-2);
    }
    /* error in file */
    else
    {
        fprintf(stderr, "Unknown line \"%s\"\n", buf);
        return (-1);        
    }

    /* strip the first parenthesis */
    if ((p = strchr(buf, '(')) == NULL)
    {
        fprintf(stderr, "Could not find opening parenthesis in: \"%s\"\n", buf);
        return (-1);
    }
    p++;

    /* strip off newline */
    p[strlen(p) - 1] = '\0';// NULL;

    for (i = 0; i < LIBSF_SFCODE_MAXCODEARGS + 1; i++)
    {
        tests[i] = NULL;
    }

    /* break p down into an array */
    for (i = 0, (token = strtok(p, "%"));
                token && i < LIBSF_SFCODE_MAXCODEARGS;
                                            (token = strtok(NULL, "%"), i++))
    {
        tests[i] = token;
    }

    /* pass off test token string to db splicer thing */
    if ((sfcode = db_splicer(tests)))
    {
        if (sfcode == NULL)
        {
            return (-1);
        }
        /* key info */
        dbkey.data = malloc(strlen(stack_tag) + 3);
        if (dbkey.data == NULL)
        {
            perror("db_add() malloc failed");
            return (-1);
        }
        memset(dbkey.data, 0, strlen(stack_tag) + 3);
        snprintf(dbkey.data, (strlen(stack_tag) + 3), "%d_%s", test_type,
                stack_tag);
        dbkey.size = strlen(dbkey.data);

        /* data info */
        dbdata.data = sfcode;
        dbdata.size = strlen(sfcode);

        /* add to db */
        if (dbptr->put(dbptr, &dbkey, &dbdata, R_NOOVERWRITE) == -1)
        {
            perror("db_add() db->put error");
            free(dbkey.data);
            return(-1);
        }
        else
        {
            dbptr->sync(dbptr, 0);
        }
#if VERBOSE
        fprintf(stderr, "Added: %d:%s -> %d:%s\n",
               dbkey.size, (char *)dbkey.data,
               dbdata.size, (char *)dbdata.data);
#endif
        free(dbkey.data);
        return (1);
    }
    else
    {
        fprintf(stderr, "~");
        return (-1);
    }
}


char *
db_splicer(char *tests[])
{
    int i, x, f, value= 0, opcode, codei, sfcodesize = 1;
    u_char flags;
    char *sfcode = NULL, *opcodeptr, *codea[LIBSF_SFCODE_MAXCODEARGS + 1];
    char *tok, tmpcode[1024], *p;

    /* interpret individual commands */
    for (i = 0; tests[i]; i++)
    {
        /* flush counter and tmpcode */
        opcode = 0;
        memset(&tmpcode, 0, sizeof(tmpcode));

        /* get opcode */
        if (strncasecmp(tests[i], "Resp=", 5) == 0)
        {
            opcode = LIBSF_SFCODE_RESPONSE;
        }
        else if(strncasecmp(tests[i], "DF=", 3) == 0)
        {
            opcode = LIBSF_SFCODE_IP_DF;
        }
        else if(strncasecmp(tests[i], "ACK=", 4) == 0)
        {
            opcode = LIBSF_SFCODE_TCP_ACK;
        }
        else if(strncasecmp(tests[i], "W=", 2) == 0)
        {
            opcode = LIBSF_SFCODE_TCP_WINDOW;
        }
        else if(strncasecmp(tests[i], "Flags=", 6) == 0)
        {
            opcode = LIBSF_SFCODE_TCP_FLAGS;
        }
        else if(strncasecmp(tests[i], "Ops=", 4) == 0)
        {
            opcode = LIBSF_SFCODE_TCP_OPT;
        }
        else if(strncasecmp(tests[i], "Class=", 4) == 0)
        {
            /* we don't care about class stuff */
            return (NULL);
        }
        else
        {
            fprintf(stderr, "db_splicer(): unknown opcode: %s\n", tests[i]);
            return (NULL);
        }

        /* get a pointer to the beginning of the args */
        if ((opcodeptr = strchr(tests[i], '=')) == NULL)
        {
            /* this should never happen */
            fprintf(stderr, "db_splicer(): unknown error!\n");
            return (NULL);
        }
        opcodeptr++;

        /* do some special stuff for the opts field */
        if (opcode == LIBSF_SFCODE_TCP_OPT)
        {
            switch (opcodeptr[0])
            {
                case ')':
                    /* hit anchor (there are no options) */
                    opcodeptr[0] = 'Z';
                    break;
                case '|':
                    /* start NULL line with 'Z' */
                    p = malloc(strlen(opcodeptr) + 1);
                    if (p == NULL)
                    {
                        perror("db_splicer(): malloc");
                        return (NULL);
                    }
                    sprintf(p, "Z%s", opcodeptr);
                    opcodeptr = p;
                    opcodeptr[strlen(opcodeptr) - 1] = '\0';//= NULL;
                    break;
                default:
                    /* strip the end paren from a normal line */
                    if ((p = strchr(opcodeptr,')')) != NULL)
                    {
                        p[0] = '\0';//= NULL;
                    }
                    break;
            }
        }

        /* break down opcodeptr into an array, we'll delimit by | */
        for (codei = 0, (tok = strtok(opcodeptr, "|"));
                    tok && codei < LIBSF_SFCODE_MAXCODEARGS;
                                    (tok = strtok(NULL, "|"), codei++))
        {
            codea[codei] = tok;
        }
        codea[codei] = NULL;

        /* 
         *  for all the |'d args
         *  XXX - should come back and fix this to not be overflowable
         */
        for (x = 0, sprintf(tmpcode, "%x=", opcode); x < codei; x++)
        {
            /*
             *  If we're past the first run.. remove the type tag from the 
             *  buffer.
             */
            if (x > 0)
            {
                memset(&tmpcode, 0, sizeof(tmpcode));
            }
            switch (opcode)
            {
                /* responds or IP DF */
                case LIBSF_SFCODE_RESPONSE:
                case LIBSF_SFCODE_IP_DF:
                    if (codea[x][0] == 'Y')
                    {
                        value = 0x1;
                    }
                    else
                    {
                        value = 0x0;
                    }
                    sprintf(tmpcode + strlen(tmpcode), "%x", value);
                    break;
                /* TCP ack */
                case LIBSF_SFCODE_TCP_ACK:
                    if (strncasecmp("S++", codea[x], 3) == 0)
                    {
                        /* S++ */
                        value = 0x0;
                    }
                    else if(codea[x][0] == '0')
                    {
                        /* Zero ack */
                        value = 0x1;
                    }
                    else if(codea[x][0] == 'S')
                    {
                        /* our syn */
                        value = 0x2;
                    }
                    sprintf(tmpcode + strlen(tmpcode), "%x", value);
                    break;
                /* TCP Win Size */
                case LIBSF_SFCODE_TCP_WINDOW:
                    sprintf(tmpcode + strlen(tmpcode), "%s", codea[x]);
                    break;
                /* TCP Flags */
                case LIBSF_SFCODE_TCP_FLAGS:
                    flags = 0;
                    for (f = 0; codea[x][f] != '\0'; f++)
                    {
                        switch (codea[x][f])
                        {
                            /* Bogus flag used in T1 */
                            case 'B':
                                flags |= 0x64;
                                break;
                            case 'A':
                                flags |= TH_ACK;
                                break;
                            case 'S':
                                flags |= TH_SYN;
                                break;
                            case 'R':
                                flags |= TH_RST;
                                break;
                            case 'F':
                                flags |= TH_FIN;
                                break;
                            case 'P':
                                flags |= TH_PUSH;
                                break;
                            case 'U':
                                flags |= TH_URG;
                                break;
                        }
                    }
                    sprintf(tmpcode + strlen(tmpcode), "%x", flags);
                    break;
                /* TCP Options */
                case LIBSF_SFCODE_TCP_OPT:
                    sprintf(tmpcode + strlen(tmpcode), "%s", codea[x]);
                    break;
            }
            /* add '|' if needed, or finish line with semi */
            if(x + 1 < codei)
            {
                strcat(tmpcode, "|");
            }
            else
            {
                strcat(tmpcode, ";");
            }
            /* Realloc and append tmpcode to sfcode */
            sfcodesize += strlen(tmpcode);
            if ((sfcode = realloc(sfcode, sfcodesize)) == NULL)
            {
                perror("db_splicer() realloc error");
                {
                    return (NULL);
                }
            }
            memcpy((sfcode + sfcodesize - strlen(tmpcode) - 1), &tmpcode, 
                strlen(tmpcode));
        }	
    }
    /* Get rid of trailing junk */
    sfcode[sfcodesize - 1] = '\0';//NULL;

    return (sfcode);
}


void
usage(char *name)
{
    fprintf(stderr, "Usage: %s [options] fingerprint file\n"
                    "-a import active database\n"
                    "-p import passive database\n", name);

}


/* EOF */
