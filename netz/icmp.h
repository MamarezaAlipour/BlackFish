#ifndef _NETZ_ICMP_H_
#define _NETZ_ICMP_H_

/*
 * Structure of an ICMP header.
 */

#include "ip.h"

#pragma pack(1)

/*
 * ICMP Header
 */

struct s_icmp_header
{
    byte type;
    byte code;
    word cksum;
};

#define ICMP_HEADER_LEN sizeof(s_icmp_header)

/*
 * ICMP Message - Generic (header and this message creates generic ICMP packet)
 */

struct s_icmp_mesage_generic
{
    dword unused;
};

/*
 * ICMP Message - Echo Reply (RFC 792)
 */

#define ICMP_ECHOREPLY 0         /* type */
#define ICMP_ECHOREPLY_LEN 4     /* length */
#define ICMP_ECHOREPLY_DATALEN 1 /* length of data chunk */

struct s_icmp_message_echoreply
{
    word id;
    word seqnumber;
    byte data[65536];
};

/*
 * ICMP Message - Destination Unreachable (RFC 792)
 */

#define ICMP_UNREACH 3               /* type */
#define ICMP_UNREACH_LEN 32          /* length */
#define ICMP_UNREACH_NET 0           /* bad net */
#define ICMP_UNREACH_HOST 1          /* bad host */
#define ICMP_UNREACH_PROTOCOL 2      /* bad protocol */
#define ICMP_UNREACH_PORT 3          /* bad port */
#define ICMP_UNREACH_NEEDFRAG 4      /* IP_DF caused drop */
#define ICMP_UNREACH_SRCFAIL 5       /* src route failed */
#define ICMP_UNREACH_NETUNK 6        /* unknown net */
#define ICMP_UNREACH_HOSTUNK 7       /* unknown host */
#define ICMP_UNREACH_ISOLATED 8      /* src host isolated */
#define ICMP_UNREACH_NETPROHIB 9     /* for crypto devs */
#define ICMP_UNREACH_HOSTPROHIB 10   /* ditto */
#define ICMP_UNREACH_TOSNET 11       /* bad tos for net */
#define ICMP_UNREACH_TOSHOST 12      /* bad tos for host */
#define ICMP_UNREACH_FILTERPROHIB 13 /* prohibited access */
#define ICMP_UNREACH_HOSTPREC 14     /* precedence violation */
#define ICMP_UNREACH_PRECCUTOFF 15   /* precedence cutoff */

struct s_icmp_message_unreach
{
    dword unused;
    s_ip_header ipheader;
    byte ipdata[8];
};

/*
 * ICMP Message - Source Quench (RFC 792)
 */

#define ICMP_SOURCEQUENCH 4      /* type */
#define ICMP_SOURCEQUENCH_LEN 32 /* length */

struct s_icmp_message_sourcequench
{
    dword unused;
    s_ip_header ipheader;
    byte ipdata[8];
};

/*
 * ICMP Message - Redirection, shorter route (RFC 792)
 */

#define ICMP_REDIRECT 5         /* type */
#define ICMP_REDIRECT_LEN 32    /* length */
#define ICMP_REDIRECT_NET 0     /* for network */
#define ICMP_REDIRECT_HOST 1    /* for host */
#define ICMP_REDIRECT_TOSNET 2  /* for tos and net */
#define ICMP_REDIRECT_TOSHOST 3 /* for tos and host */

struct s_icmp_message_redirect
{
    dword gateway;
    s_ip_header ipheader;
    byte ipdata[8];
};

/*
 * ICMP Message - Alternate Host Address
 */

#define ICMP_ALTHOSTADDR 6 /* type */

/*
 * ICMP Message - Echo (RFC 792)
 */

#define ICMP_ECHOREQUEST 8         /* type */
#define ICMP_ECHOREQUEST_LEN 4     /* length */
#define ICMP_ECHOREQUEST_DATALEN 1 /* length of data chunk */

struct s_icmp_message_echorequest
{
    word id;
    word seqnumber;
    byte data[65536];
};

/*
 * ICMP Message - Router Advertisement (RFC 1256)
 */

#define ICMP_ROUTERADVERT 9         /* type */
#define ICMP_ROUTERADVERT_LEN 4     /* length */
#define ICMP_ROUTERADVERT_DATALEN 8 /* length of data chunk */

struct s_icmp_message_routeradvert
{
    byte addrnumber;
    byte addrentrysize;
    word lifetime;

    struct
    {
        dword address;
        dword plevel;
    } router[256];
};

/*
 * ICMP Message - Router Solicitation (RFC 1256)
 */

#define ICMP_ROUTERSOLICIT 10    /* type */
#define ICMP_ROUTERSOLICIT_LEN 4 /* length */

struct s_icmp_message_routersolicit
{
    dword unused;
};

/*
 * ICMP Message - Time Exceeded (RFC 792)
 */

#define ICMP_TIMEXCEED 11        /* type */
#define ICMP_TIMEXCEED_LEN 32    /* length */
#define ICMP_TIMEXCEED_INTRANS 0 /* ttl==0 in transit */
#define ICMP_TIMEXCEED_REASS 1   /* ttl==0 in reass */

struct s_icmp_message_timexceed
{
    dword unused;
    s_ip_header ipheader;
    byte ipdata[8];
};

/*
 * ICMP Message - Parameter Problem, ip header bad (RFC 792)
 */

#define ICMP_PARAMPROB 12          /* type */
#define ICMP_PARAMPROB_LEN 32      /* length */
#define ICMP_PARAMPROB_ERRATPTR 0  /* req. opt. absent */
#define ICMP_PARAMPROB_OPTABSENT 1 /* req. opt. absent */
#define ICMP_PARAMPROB_LENGTH 2    /* bad length */

struct s_icmp_message_paramprob
{
    byte pointer;
    byte unused[3];
    s_ip_header ipheader;
    byte ipdata[8];
};

/*
 * ICMP Message - Timestamp Request (RFC 792)
 */

#define ICMP_TSREQUEST 13     /* type */
#define ICMP_TSREQUEST_LEN 16 /* length */

struct s_icmp_message_tsrequest
{
    word id;
    word seqnumber;
    dword originate;
    dword receive;
    dword transmit;
};

/*
 * ICMP Message - Timestamp Reply (RFC 792)
 */

#define ICMP_TSREPLY 14     /* type */
#define ICMP_TSREPLY_LEN 16 /* length */

struct s_icmp_message_tsreply
{
    word id;
    word seqnumber;
    dword originate;
    dword receive;
    dword transmit;
};

/*
 * ICMP Message - Information Request (RFC 792)
 */

#define ICMP_INFOREQUEST 15    /* type */
#define ICMP_INFOREQUEST_LEN 4 /* length */

struct s_icmp_message_inforequest
{
    word id;
    word seqnumber;
};

/*
 * ICMP Message - Information Reply (RFC 792)
 */

#define ICMP_INFOREPLY 16    /* type */
#define ICMP_INFOREPLY_LEN 4 /* length */

struct s_icmp_message_inforeply
{
    word id;
    word seqnumber;
};

/*
 * ICMP Message - Mask Request (RFC 950)
 */

#define ICMP_MASKREQUEST 17    /* type */
#define ICMP_MASKREQUEST_LEN 8 /* length */

struct s_icmp_message_maskrequest
{
    word id;
    word seqnumber;
    dword mask;
};

/*
 * ICMP Message - Mask Reply (RFC 950)
 */

#define ICMP_MASKREPLY 18    /* type */
#define ICMP_MASKREPLY_LEN 8 /* length */

struct s_icmp_message_maskreply
{
    word id;
    word seqnumber;
    dword mask;
};

/*
 * ICMP Messages reserved for robustness experiment
 */

#define ICMP_RESERVED19 19 /* type */
#define ICMP_RESERVED20 20 /* type */
#define ICMP_RESERVED21 21 /* type */
#define ICMP_RESERVED22 22 /* type */
#define ICMP_RESERVED23 23 /* type */
#define ICMP_RESERVED24 24 /* type */
#define ICMP_RESERVED25 25 /* type */
#define ICMP_RESERVED26 26 /* type */
#define ICMP_RESERVED27 27 /* type */
#define ICMP_RESERVED28 28 /* type */
#define ICMP_RESERVED29 29 /* type */

/*
 * ICMP Message - Traceroute
 */

#define ICMP_TRACEROUTE 30     /* type */
#define ICMP_TRACEROUTE_LEN 16 /* length */

struct s_icmp_message_traceroute
{
    word id;
    word unused;
    word outhopcount;
    word rethopcount;
    dword outlinkspeed;
    dword outlinkmtu;
};

/*
 * ICMP Message - Conversion Error (RFC 1457)
 */

#define ICMP_CONVERR 31             /* type */
#define ICMP_CONVERR_LEN 4          /* length */
#define ICMP_CONVERR_UNKERR 0       /* unknown error */
#define ICMP_CONVERR_DONTCONV 1     /* don't convert option present */
#define ICMP_CONVERR_UNKMANOPT 2    /* unknown mandatory opt. present */
#define ICMP_CONVERR_UNSUPPOPT 3    /* known unsupported option present */
#define ICMP_CONVERR_UNSUPPPROTO 4  /* unsupported transport protocol */
#define ICMP_CONVERR_LENEXCEED 5    /* overall length exceeded */
#define ICMP_CONVERR_IPHLENEXCEED 6 /* IP header length exceeded */
#define ICMP_CONVERR_BADPROTONUM 7  /* transport protocol > 255 */
#define ICMP_CONVERR_PORTRANGE 8    /* port conversion out of range */
#define ICMP_CONVERR_TRHLENEXCEED 9 /* transport header length exceeded */
#define ICMP_CONVERR_ROLLMISS 10    /* 32 bit Rollover missing, ACK set */
#define ICMP_CONVERR_UNKMANTROPT 11 /* unk. man. transport option present */

struct s_icmp_message_converr
{
    dword pointer;
    byte badpacket[65536];
};

/*
 * ICMP Message - Mobile Host Redirect
 */

#define ICMP_MOBHRED 32 /* type */

/*
 * ICMP Message - IPv6 Where Are You
 */

#define ICMP_WHEREAREYOU 33 /* type */

/*
 * ICMP Message - IPv6 I Am Here
 */

#define ICMP_IAMHERE 34 /* type */

/*
 * ICMP Message - Mobile Registration Request
 */

#define ICMP_MOBREGREQ 35 /* type */

/*
 * ICMP Message - Mobile Registration Reply
 */

#define ICMP_MOBREGREP 36 /* type */

/*
 * ICMP Message - Domain Name Request (RFC 1788)
 */

#define ICMP_DNAMEREQUEST 37    /* type */
#define ICMP_DNAMEREQUEST_LEN 4 /* length */

struct s_icmp_message_dnamerequest
{
    word id;
    word seqnumber;
};

/*
 * ICMP Message - Domain Name Reply (RFC 1788)
 */

#define ICMP_DNAMEREPLY 38    /* type */
#define ICMP_DNAMEREPLY_LEN 8 /* length */

struct s_icmp_message_dnamereply
{
    word id;
    word seqnumber;
    dword ttl;
    byte names[65536];
};

/*
 * ICMP Message - Skip
 */

#define ICMP_SKIP 39 /* type */

/*
 * ICMP Message - Security (RFC 2521)
 */

#define ICMP_SECURITY 40           /* type */
#define ICMP_SECURITY_LEN 32       /* length */
#define ICMP_SECURITY_BADSPI 0     /* bad SPI */
#define ICMP_SECURITY_AUTHENFAIL 1 /* authentication failed */
#define ICMP_SECURITY_DECOMPFAIL 2 /* decompression failed */
#define ICMP_SECURITY_DECRYPFAIL 3 /* decryption failed */
#define ICMP_SECURITY_NEEDAUTHEN 4 /* need authentication */
#define ICMP_SECURITY_NEEDAUTHOR 5 /* need authorization */

struct s_icmp_message_security
{
    word unused;
    word pointer;
    s_ip_header ipheader;
    byte ipdata[8];
};

#pragma pack(4)

#endif /* _NETZ_ICMP_H_ */
