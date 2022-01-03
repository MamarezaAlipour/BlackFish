#ifndef _NETZ_TCP_H_
#define _NETZ_TCP_H_

#include "types.h"

/*
 * TCP header (RFC 793)
 */

struct s_tcp_header
{
    word sport; /* source port */
    word dport; /* destination port */
    dword seq;  /* sequence number */
    dword ack;  /* acknowledgement number */
    byte hlen;  /* header length */
    byte flags; /* tcp flags */
    word win;   /* window */
    word cksum; /* checksum */
    word urp;   /* urgent pointer */
};

#define TCP_HEADER_LEN sizeof(s_tcp_header)

/*
 * header lenght mask
 */

#define TCP_HLEN_MASK 0xF0

/*
 * TCP Flags definitions
 */

#define TCP_FLAG_FIN_MASK 0x01
#define TCP_FLAG_SYN_MASK 0x02
#define TCP_FLAG_RST_MASK 0x04
#define TCP_FLAG_PSH_MASK 0x08
#define TCP_FLAG_ACK_MASK 0x10
#define TCP_FLAG_URG_MASK 0x20
#define TCP_FLAG_X_MASK 0x40
#define TCP_FLAG_Y_MASK 0x80

/*
 * TCP Options definitions
 */

#pragma pack(1)

/*
 * Generic TCP Option
 */

#define TCPOPT_GENERIC_LEN 2

struct s_tcpopt_generic
{
    byte code;
    byte len;
    byte data[44];
};

/*
 * EOL - end of list (RFC 793)
 */

#define TCPOPT_EOL 0
#define TCPOPT_EOL_LEN 1

struct s_tcpopt_eol
{
    byte code;
};

/*
 * NOP - no operation (RFC 793)
 */

#define TCPOPT_NOP 1
#define TCPOPT_NOP_LEN 1

struct s_tcpopt_nop
{
    byte code;
};

/*
 * MSS - max segment size (RFC 793)
 */

#define TCPOPT_MSS 2
#define TCPOPT_MSS_LEN 4

struct s_tcpopt_mss
{
    byte code;
    byte len;
    word size;
};

/*
 * WSCALE - window scale (RFC 1323)
 */

#define TCPOPT_WSCALE 3
#define TCPOPT_WSCALE_LEN 3

struct s_tcpopt_wscale
{
    byte code;
    byte len;
    byte scale;
};

/*
 * SACKPERM - selective ack permited (RFC 2018)
 */

#define TCPOPT_SACKPERM 4
#define TCPOPT_SACKPERM_LEN 2

struct s_tcpopt_sackperm
{
    byte code;
    byte len;
};

/*
 * SACK - selective ack (RFC 2018)
 */

#define TCPOPT_SACK 5
#define TCPOPT_SACK_LEN 2     /* main part length*/
#define TCPOPT_SACK_DATALEN 8 /* data length*/

struct s_tcpopt_sack
{
    byte code;
    byte len;

    struct
    {
        dword ledge;
        dword redge;
    } block[4];
};

/*
 * ECHO - echo request (RFC 1072)
 */

#define TCPOPT_ECHO 6
#define TCPOPT_ECHO_LEN 6

struct s_tcpopt_echo
{
    byte code;
    byte len;
    dword info;
};

/*
 * ECHOREPLY - echo reply (RFC 1072)
 */

#define TCPOPT_ECHOREPLY 7
#define TCPOPT_ECHOREPLY_LEN 6

struct s_tcpopt_echoreply
{
    byte code;
    byte len;
    dword info;
};

/*
 * TIMESTAMP - timestamp (RFC 1323)
 */

#define TCPOPT_TIMESTAMP 8
#define TCPOPT_TIMESTAMP_LEN 10

struct s_tcpopt_timestamp
{
    byte code;
    byte len;
    dword tsval;
    dword tsecr;
};

/*
 * POCPERM - poc permited (RFC 1693)
 */

#define TCPOPT_POCPERM 9
#define TCPOPT_POCPERM_LEN 2

struct s_tcpopt_pocperm
{
    byte code;
    byte len;
};

/*
 * POCSPROF - poc service profile (RFC 1693)
 */

#define TCPOPT_POCSPROF 10
#define TCPOPT_POCSPROF_LEN 3

#define IPOPT_POCSPROF_ES_EFLAG_MASK 0x02
#define IPOPT_POCSPROF_ES_SFLAG_MASK 0x01

struct s_tcpopt_pocsprof
{
    byte code;
    byte len;
    byte es;
};

/*
 * CC - cc (Braden)
 */

#define TCPOPT_CC 11
#define TCPOPT_CC_LEN 6

struct s_tcpopt_cc
{
    byte code;
    byte len;
    word segment;
};

/*
 * CCNEW - ccnew (Braden)
 */

#define TCPOPT_CCNEW 12
#define TCPOPT_CCNEW_LEN 6

struct s_tcpopt_ccnew
{
    byte code;
    byte len;
    word segment;
};

/*
 * CCECHO - ccecho (Braden)
 */

#define TCPOPT_CCECHO 13
#define TCPOPT_CCECHO_LEN 6

struct s_tcpopt_ccecho
{
    byte code;
    byte len;
    word segment;
};

/*
 * ALTCSR - alternative checksum request (RFC 1146)
 */

#define TCPOPT_ALTCSR 14
#define TCPOPT_ALTCSR_LEN 4

struct s_tcpopt_altcsr
{
    byte code;
    byte len;
    word cksum;
};

/*
 * ALTCSD - alternative checksum data (RFC 1146)
 */

#define TCPOPT_ALTCSD 15
#define TCPOPT_ALTCSD_LEN 2     /* main part len */
#define TCPOPT_ALTCSD_DATALEN 1 /* data len */

struct s_tcpopt_altcsd
{
    byte code;
    byte len;
    byte data[38];
};

/*
 * SIGNATURE - MD5 signature (RFC 2385)
 */

#define TCPOPT_SIGNATURE 19
#define TCPOPT_SIGNATURE_LEN 18

struct s_tcpopt_signature
{
    byte code;
    byte len;
    string signature[16];
};

#pragma pack(4)

#endif /* _NETZ_TCP_H_ */
