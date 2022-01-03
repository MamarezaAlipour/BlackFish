#ifndef _NETZ_IP_H_
#define _NETZ_IP_H_

#include "types.h"

/*
 * Structure of an IP header (RFC 791)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ip_header
{
    byte vl;    /* header version and length */
    byte tos;   /* type of service */
    word len;   /* total length of IP packet */
    word id;    /* identification */
    word frag;  /* fragment flags and offset */
    byte ttl;   /* time to live */
    byte proto; /* protocol */
    word cksum; /* checksum */
    dword src;  /* source address */
    dword dst;  /* source address */
};

#define IP_HEADER_LEN sizeof(s_ip_header)

/*
 * Masks for header length and version
 */

#define IP_VL_HLEN_MASK 0x0F
#define IP_VL_VER_MASK 0xF0

/*
 * Definitions of protocols (ip_proto)
 */

#include "ip_proto.h" /* definitions and print function */

/*
 * Definitions for fragment flags (ip_off) (RFC 791)
 */

#define IP_FRAG_RF_MASK 0x8000  /* reserved */
#define IP_FRAG_DF_MASK 0x4000  /* don't fragment flag */
#define IP_FRAG_MF_MASK 0x2000  /* more fragments flag */
#define IP_FRAG_OFF_MASK 0x1FFF /* fragment offset */

/*
 * Definitions for IP type of service (ip_tos) (RFC 791)
 */

#define IP_TOS_DELAY_MASK 0x10       /* delay */
#define IP_TOS_THROUGHPUT_MASK 0x08  /* throughput */
#define IP_TOS_RELIABILITY_MASK 0x04 /* reliability */
#define IP_TOS_ECTCAP_MASK 0x02      /* ECN-capable transport */
#define IP_TOS_CONGESTION_MASK 0x01  /* congestion experienced */

/*
 * Definitions for IP precedence (ip_tos & 0xE0) (RFC 791)
 */

#define IP_TOS_PREC_MASK 0xE0            /* precendence field mask */
#define IP_TOS_PREC_NETCONTROL 0x07      /* network control */
#define IP_TOS_PREC_INTERNETCONTROL 0x06 /* internetwork control */
#define IP_TOS_PREC_CRITICECP 0x05       /* CRITIC/ECP */
#define IP_TOS_PREC_FLASHOVERRIDE 0x04   /* flash overide */
#define IP_TOS_PREC_FLASH 0x03           /* flash */
#define IP_TOS_PREC_IMMEDIATE 0x02       /* immediate */
#define IP_TOS_PREC_PRIORITY 0x01        /* priority */
#define IP_TOS_PREC_ROUTINE 0x00         /* routine */

/*
 * Definitions of IP options.
 */

#pragma pack(1)

/*
 * Generic IP option
 */

#define IPOPT_GENERIC_LEN 2

struct s_ipopt_generic
{
    byte code;
    byte len;
    byte data[44];
};

/*
 * EOL - end of option list (RFC 791)
 */

#define IPOPT_EOL 0
#define IPOPT_EOL_LEN 1

struct s_ipopt_eol
{
    byte code;
};

/*
 * NOP - no operation (RFC 791)
 */

#define IPOPT_NOP 1
#define IPOPT_NOP_LEN 1

struct s_ipopt_nop
{
    byte code;
};

/*
 * RR - record route (RFC 791)
 */

#define IPOPT_RR 7
#define IPOPT_RR_LEN 3
#define IPOPT_RR_DATALEN 4

struct s_ipopt_rr
{
    byte code;
    byte len;
    byte ptr;
    dword ip[9];
};

/*
 * PMTU - probe mtu (RFC 1063)
 */

#define IPOPT_PMTU 11
#define IPOPT_PMTU_LEN 4

struct s_ipopt_pmtu
{
    byte code;
    byte len;
    word mtu;
};

/*
 * RMTU - mtu reply (RFC 1063)
 */

#define IPOPT_RMTU 12
#define IPOPT_RMTU_LEN 4

struct s_ipopt_rmtu
{
    byte code;
    byte len;
    word mtu;
};

/*
 * TS - timestamp (RFC 791)
 */

#define IPOPT_TS 68
#define IPOPT_TS_LEN 4               /* main part length */
#define IPOPT_TS_TSONLY_DATALEN 4    /* tsonly data length*/
#define IPOPT_TS_TSANDADDR_DATALEN 8 /* tsandaddr data length*/
#define IPOPT_TS_PRESPEC_DATALEN 8   /* prespec data length */
#define IPOPT_TS_TSONLY 0            /* timestamps only */
#define IPOPT_TS_TSANDADDR 1         /* timestamps and addresses */
#define IPOPT_TS_PRESPEC 3           /* specified modules only */

#define IPOPT_TS_OVFL_OVFLOW_MASK 0xF0
#define IPOPT_TS_OVFL_FLAGS_MASK 0x0F

struct s_ipopt_ts /* timestamp */
{
    byte code;
    byte len;
    byte ptr;  /* pointer */
    byte ovfl; /* overflow and flags */

    union
    {
        struct /* timestamp only */
        {
            dword timestamp; /* timestamp */
        } tsonly[9];

        struct /* timestamp and address */
        {
            dword ip;        /* ip address */
            dword timestamp; /* timestamp */
        } tsandaddr[4];

        struct /* prespecified */
        {
            dword ip;        /* ip address */
            dword timestamp; /* timestamp */
        } prespec[4];
    };
};

/*
 *  TR - traceroute
 */

#define IPOPT_TR 82
#define IPOPT_TR_LEN 12

struct s_ipopt_tr
{
    byte code;
    byte len;
    word id;          /* identifier */
    word ohcount;     /* outbound hop count */
    word rhcount;     /* return_hop_count */
    dword originator; /* originator */
};

/*
 *  SEC - security (RFC 791)
 */

#define IPOPT_SEC 130
#define IPOPT_SEC_LEN 3     /* main part length */
#define IPOPT_SEC_DATALEN 1 /* data length */

struct s_ipopt_sec
{
    byte code;
    byte len;
    byte cl;        /* cl */
    byte flags[44]; /* flags */
};

/*
 * LSRR - loose source route (RFC 791)
 */

#define IPOPT_LSRR 131
#define IPOPT_LSRR_LEN 3     /* main part length */
#define IPOPT_LSRR_DATALEN 4 /* data length */

struct s_ipopt_lsrr
{
    byte code;
    byte len;
    byte ptr;
    dword ip[9];
};

/*
 * XSEC - extended security
 */

#define IPOPT_XSEC 133
#define IPOPT_XSEC_LEN 3     /* main part length */
#define IPOPT_XSEC_DATALEN 1 /* data length */

struct s_ipopt_xsec /* extended security */
{
    byte code;
    byte len;
    byte asiac;     /* asiac */
    byte flags[44]; /* extended security flags */
};

/*
 * SATID -  satnet id (RFC 791)
 */

#define IPOPT_SATID 136
#define IPOPT_SATID_LEN 4

struct s_ipopt_satid
{
    byte code;
    byte len;
    word id; /* stream id */
};

/*
 * SSRR - strict source route (RFC 791)
 */

#define IPOPT_SSRR 137
#define IPOPT_SSRR_LEN 3     /* main part length */
#define IPOPT_SSRR_DATALEN 4 /* data length */

struct s_ipopt_ssrr
{
    byte code;
    byte len;
    byte ptr;
    dword ip[9];
};

#pragma pack(4)

/*
 * Pseudo header used to compute tcp/udp checksums
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      zero     |    Protocol   |           TCP Length          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ipp_header
{
    dword src;  /* source internet address */
    dword dst;  /* destination internet address */
    byte pad;   /* pad, must be zero */
    byte proto; /* protocol */
    word len;   /* protocol length */
};

#define IPP_HEADER_LEN sizeof(ipp_header)

#endif /* _NETZ_IP_H_ */
