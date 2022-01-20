/*
 *  $Id: libsf.h.in,v 1.1 2002/02/18 20:01:06 route Exp $
 *
 *  libsf
 *  libsf.h - stack fingerprinting library header file
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

#include <pcap.h>
#include <time.h>
#include <libnet.h>
//#include <db.h>
#include <db_185.h>
#include <sys/types.h>

#define LIBSF_VERSION          "0.1"

/* fingerprint types */
#define LIBSF_ACTIVE            0x01
#define LIBSF_PASSIVE           0x02

/* active method defines */
#define	LIBSF_ACTIVE_TSEQ       0x00
#define	LIBSF_ACTIVE_OPTSYN     0x01
#define	LIBSF_ACTIVE_OPTNULL    0x02
#define	LIBSF_ACTIVE_OPTSFUP    0x03
#define	LIBSF_ACTIVE_OPENACK    0x04
#define	LIBSF_ACTIVE_CLOSESYN   0x05
#define	LIBSF_ACTIVE_CLOSEACK   0x06
#define	LIBSF_ACTIVE_CLOSEFPU   0x07

/* active defines */
#define	LIBSF_ACTIVE_TIMEOUT    0x03    /*  3 second timeout per scan */
#define	LIBSF_PASSIVE_TIMEOUT   0x14    /* 20 second timeout per instance */

/* sfcode defines */
#define	LIBSF_SFCODE_RESPONSE   0x01

#define LIBSF_SFCODE_IP_DF      0x100   /* IP don't fragment */
#define LIBSF_SFCODE_IP_TTL     0x101   /* IP time to live */
#define	LIBSF_SFCODE_TCP_WINDOW 0x200   /* TCP window */
#define	LIBSF_SFCODE_TCP_ACK    0x201   /* TCP acknowledgement */
#define	LIBSF_SFCODE_TCP_FLAGS  0x202   /* TCP control flags */
#define	LIBSF_SFCODE_TCP_OPT    0x203   /* TCP options */

#define	LIBSF_SFCODE_MAXCODE    0x20
#define LIBSF_SFCODE_MAXCODEARGS 0x0a

/* scan type defines */
#define	LIBSF_SCAN_OPEN	        0x00    /* scan for an open port */
#define	LIBSF_SCAN_CLOSED       0x01    /* scan for a closed port */
#define LIBSF_SCAN_GUESSPORTS   { 80, 139, 22, 25, 53, 113, 443, 6667, 0 }

/* misc defines */
#define	LIBSF_DB_PATH           "/usr/local/share/libsf/libsf.db"
#define LIBSF_DB_FILE           "./libsf.db"
#define	LIBSF_TCP_OPTSTR        "\x03\x03\x0a\x01\x02\x04\x01\x09\x08\x0a\x3f\x3f\x3f\x3f\x00\x00\x00\x00\x00\x00"
#define	LIBSF_TCP_OPTSTRSIZE    0x14
#define LIBSF_ERRBUF_SIZE       0x100

/* pcap format string templates */
#define LIBSF_ACTIVE_FILTER     "ip host %s and tcp port (%d or %d)"
#define LIBSF_PASSIVE_FILTER    "ip proto tcp"

/*
 *  linked list of possible OS's, every time an OS is flagged it's added
 *  to the list.  If it's already in there, its score is incremented.
 */
struct libsf_osguess
{
    char *name;                 /* OS name */
    u_short score;              /* score */
    struct libsf_osguess *next; /* next in list */
};
typedef struct libsf_osguess libsf_osg_t;


/*
 *  Struct that holds target information including IP, open and closed 
 *  port info.
 */
struct libsf_target
{
    u_long addr;                /* target IP */
    u_short port_open;          /* open port */
    u_short port_closed;        /* closed port */
    u_int g_num;                /* total number of OS guesses */
    u_int last;                 /* last OS looked at, for os_get_next */
    u_short g_hs;               /* highest scored OS */
    libsf_osg_t *g;             /* OS guesses for this target */
};
typedef struct libsf_target libsf_target_t;


/*
 *  Passive parameters kept here.
 */
struct libsf_passive_tests
{   
    u_short ip_ttl;             /* IP time to live */
    u_short ip_len;             /* IP length */
    u_char  ip_df;              /* IP don't fragment */
    u_long ip_src;              /* IP source */
    u_long ip_dst;              /* IP destination */
    u_short tcp_sp;             /* TCP source port */
    u_short tcp_dp;             /* TCP destination port */
    u_short tcp_win;            /* TCP window */
};
typedef struct libsf_passive_tests libsf_passive_t;

/*
 *  Main monolithic struct that holds all communication handles.
 */
struct libsf_handle
{
    u_char type;                /* type of scan */
    u_char flags;               /* control flags */
#define LIBSF_CTRL_VERBOSE      0x1
#define LIBSF_CTRL_DEBUG        0x2
    u_short src_port;           /* XXX - should not need to keep this here */
    char *device;               /* NIC */
    u_short timeout;            /* active timeout value */
    libnet_t *l;                /* libnet descriptor */
    libnet_ptag_t ip;           /* ip ptag */
    libnet_ptag_t tcp;          /* tcp ptag */
    libnet_ptag_t tcp_options;  /* tcp ptag */
    pcap_t *p;                  /* pcap descriptor */
    u_int  offset;              /* layer 3 (IP) offset */
    u_long ouraddr;             /* our IP Address */
    char err_buf[LIBSF_ERRBUF_SIZE];/* error buffer */
    libsf_target_t t;           /* target information */
    libsf_passive_t pt;         /* passive test state */
    DB *db;                     /* database handle */
};
typedef struct libsf_handle libsf_t;


/*
 *  Data structure used to hold database responses. These are referenced in 
 *  the database by their test type/number.
 */
struct libsf_database
{
    char entry_name[50];
    char *entry_data;
    u_int entry_datalen;
};
typedef struct libsf_database libsf_db_t;


/*
 *  Functions.
 */

libsf_t *               /* libsf_t decscriptor on success; NULL on failure */
libsf_init(
    u_char,             /* type */
    char *,             /* device */
    char *,             /* target IP address */
    u_short,            /* open port to use or 0 */
    u_short,            /* closed port to use or 0 */
    u_char,             /* flags */
    char *              /* errbuf */
    );


int                     /* 1 on success; -1 on error */
libsf_target_init(
    libsf_t *,          /* libsf handle */
    u_long,             /* IP address */
    u_short,            /* open port */
    u_short             /* closed port */
    );


int                     /* 1 on success; -1 on error */
libsf_active_id(
    libsf_t *           /* libsf handle */
    );


int                     /* 1 on success; -1 on error */
libsf_passive_id(
    libsf_t *           /* libsf handle */
    );


void
libsf_passive_scan(
    u_char *,           /* user supplied data (libsf_t *s) */
    const struct pcap_pkthdr *,/* pcap packet header */
    const u_char *      /* packet data */
    );


int                     /* 1 on success; -1 on error */
libsf_set_timeout(
    libsf_t *,          /* libsf handle */
    u_short             /* timeout in seconds */
    );


int                     /* 1 on success; -1 on error */
libsf_scan_tcp(
    libsf_t *,          /* libsf handle */
    u_int               /* scan type */
    );


int                     /* 1 on success; -1 on error */
libsf_os_add(
    libsf_t *,          /* libsf handle */
    char *,             /* operating system string to add */
    u_short             /* score */
    );

int                     /* 1 on success; -1 on error */
libsf_db_check(
    libsf_t *,          /* libsf handle */
    u_int,
    u_char *,
    u_char *,
    u_int
    );


int                     /* 1 on success; -1 on error */
libsf_db_eval(
    u_char *,
    u_char *,
    u_int,
    char *
);


int                     /* 1 on success; -1 on error */
libsf_db_eval_num(
    u_int,
    char *
    );

int                     /* 1 on success; -1 on error */
libsf_db_eval_opts(
    u_char *,
    u_int,
    char *
    );


int                     /* 1 on success; -1 on error */
libsf_get_response(
    libsf_t *,          /* libsf handle */
    u_long,
    u_short,
    u_long,
    u_short,
    u_char **
    );

int                     /* 1 on success; -1 on error */
libsf_set_filter(
    libsf_t *,          /* libsf handle */
    char *              /* filter string */
    );


int                     /* 1 on success; -1 on error */
libsf_portscan(
    libsf_t *,          /* libsf handle */
    u_char              /* scan type */
    );


int                     /* 1 on success; -1 on error */
libsf_portscan_connect(
    libsf_t *,          /* libsf handle */
    u_char,             /* scantype */
    struct sockaddr_in *,/* socket addr in */
    u_int               /* address length */
    );


void
libsf_destroy(
    libsf_t *           /* libsf handle */
    );


char *
libsf_geterror(
    libsf_t *           /* libsf handle */
    );

int                     /* 1 on success; -1 on error */
libsf_os_get_hs(
    libsf_t *           /* libsf handle */
    );

int                     /* 1 on success; -1 on error */
libsf_os_get_tm(
    libsf_t *           /* libsf handle */
    );

int                     /* 1 on success; -1 on error */
libsf_os_reset_counter(
    libsf_t *           /* libsf handle */
    );

char *
libsf_os_get_next(
    libsf_t *           /* libsf handle */
    );

char *
libsf_os_get_match(
    libsf_t *,          /* libsf handle */
    u_short             /* score to match */
    );


/* EOF */
