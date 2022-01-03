#ifndef _NETZ_EIGRP_H_
#define _NETZ_EIGRP_H_

#include "types.h"

/*
 * Structure of an EIGRP header (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Version   |     Opcode    |             Cksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Flags                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Acknowledge Number                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Autonomous System Number                    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_eigrp_header
{
        byte ver;    /* version */
        byte opcode; /* opcode */
        word cksum;  /* cksum */
        dword flags; /* flags */
        dword seq;   /* sequence number */
        dword ack;   /* acknowledge number */
        dword as;    /* autonomous system number */
};

#define EIGRP_HEADER_LEN sizeof(s_eigrp_header)

/*
 * Flags
 */

#define EIGRP_FLAG_INIT_MASK 0x00000001
#define EIGRP_FLAG_CR_MASK 0x00000002

/*
 * Opcodes
 */

#define EIGRP_OPCODE_UPDATE 1
#define EIGRP_OPCODE_QUERY 3
#define EIGRP_OPCODE_REPLY 4
#define EIGRP_OPCODE_HELLO 5
#define EIGRP_OPCODE_IPXSAP 6
#define EIGRP_OPCODE_SIA_QUERY 10
#define EIGRP_OPCODE_SIA_REPLY 11

/*
 * Structure of a generic EIGRP TLV field (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                           Variable                            ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_eigrp_tlv
{
        word type; /* type */
        word len;  /* length */
};

/*
 * TLV Types
 */

#define EIGRP_TLV_TYPE_PARAMETERS 0x0001
#define EIGRP_TLV_TYPE_SEQUENCE 0x0003
#define EIGRP_TLV_TYPE_SOFTWARE_VERSION 0x0004
#define EIGRP_TLV_TYPE_NEXT_MULTICAST_SEQUENCE 0x0005
#define EIGRP_TLV_TYPE_IP_INTERNAL_ROUTE 0x0102
#define EIGRP_TLV_TYPE_IP_EXTERNAL_ROUTE 0x0103
#define EIGRP_TLV_TYPE_APPLETALK_INTENAL_ROUTE 0x0202
#define EIGRP_TLV_TYPE_APPLETALK_EXTERNAL_ROUTE 0x0203
#define EIGRP_TLV_TYPE_APPLETALK_CABLE_CONFIG 0x0204
#define EIGRP_TLV_TYPE_IPX_INTERNAL_ROUTE 0x0302
#define EIGRP_TLV_TYPE_IPX_EXTERNAL_ROUTE 0x0303

/*
 * Structure of an EIGRP Parameters TLV field (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type (0x0001)        |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       K1      |       K2      |       K3      |       K4      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       K5      |    Reserved   |           Hold time           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_eigrp_tlv_parameters
{
        word type;     /* type */
        word len;      /* length */
        byte k1;       /* k1 variable */
        byte k2;       /* k2 variable */
        byte k3;       /* k3 variable */
        byte k4;       /* k4 variable */
        byte k5;       /* k5 variable */
        byte reserved; /* reserved */
        word holdtime; /* hold time */
};

/*
 * Structure of an EIGRP Software Version TLV field (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type (0x0001)        |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Software Version                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_eigrp_tlv_softver
{
        word type;   /* type */
        word len;    /* length */
        byte ver[4]; /* version */
};

/*
 * Structure of an EIGRP IP internal route update TLV (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type (0x0102)        |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Next hop                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Delay                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Bandwidth                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              MTU                              |    Hopcount   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reliability         |      Load     |    Reserveed  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Prefix length |   Destination  (2 - 4 octets + opt pad)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                 ~         Optional pad                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#pragma pack(1)

struct s_eigrp_tlv_ipintup
{
        word type;           /* type */
        word len;            /* length */
        dword nexthop;       /* next hop */
        dword delay;         /* delay */
        dword bandwidth;     /* bandwidth */
        byte mtu[3];         /* mtu */
        byte hopcount;       /* hop_count */
        word reliability;    /* reliability */
        byte load;           /* load */
        byte reserved;       /* reserved */
        byte prefixlen;      /* prefix length */
        byte destination[4]; /* destination */
};

#pragma pack(4)

/*
 * Structure of an EIGRP IP external route update (Cisco)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Type (0x0103)        |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Next hop                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Originating router                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Originating Autonomous System                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Arbitrary tag                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    External protocol metric                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Reserved           | Ext proto ID  |     Flags     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Delay                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Bandwidth                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              MTU                              |    Hopcount   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reliability         |      Load     |    Reserveed  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Prefix length |   Destination  (2 - 4 octets + opt pad)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                 ~         Optional pad                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#pragma pack(1)

struct s_eigrp_tlv_ipextup
{
        word type;           /* type */
        word len;            /* length */
        dword nexthop;       /* next hop */
        dword orouter;       /* originating router */
        dword oas;           /* originating autonomous system */
        dword atag;          /* arbitrary tag */
        dword epmetric;      /* external protocol metric */
        word reserved_1;     /* reserved */
        byte epid;           /* external protocol id */
        byte flags;          /* flags */
        dword delay;         /* delay */
        dword bandwidth;     /* bandwidth */
        byte mtu[3];         /* mtu */
        byte hopcount;       /* hop_count */
        word reliability;    /* reliability */
        byte load;           /* load */
        byte reserved_2;     /* reserved */
        byte prefixlen;      /* prefix length */
        byte destination[4]; /* destination */
};

#pragma pack(4)

/*
 * External protocol ID
 */

#define EIGRP_TLV_IEU_EPID_IGRP 0x01
#define EIGRP_TLV_IEU_EPID_EIGRP 0x02
#define EIGRP_TLV_IEU_EPID_STATIC 0x03
#define EIGRP_TLV_IEU_EPID_RIP 0x04
#define EIGRP_TLV_IEU_EPID_HELLO 0x05
#define EIGRP_TLV_IEU_EPID_OSPF 0x06
#define EIGRP_TLV_IEU_EPID_ISIS 0x07
#define EIGRP_TLV_IEU_EPID_EGP 0x08
#define EIGRP_TLV_IEU_EPID_BGP 0x09
#define EIGRP_TLV_IEU_EPID_IDRP 0x0A
#define EIGRP_TLV_IEU_EPID_CONNECTED 0x0B

#endif /* _NETZ_EIGRP_H_ */
