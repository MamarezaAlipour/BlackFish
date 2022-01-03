#ifndef _NETZ_OSPF_H_
#define _NETZ_OSPF_H_

#include "types.h"

/*
 * Structure of an OSPF header (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |    Version    |     Type      |         Packet length         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          Router ID                            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                           Area ID                             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           Checksum            |            AuthType           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Authentication                        |
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 * Structure of crypto field for password authentication
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      Plain Text Password                      |
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Structure of crypto field for crypto authentication
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |              0                |    Key ID     | Auth Data Len |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                 Cryptographic sequence number                 |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct s_ospf_header
{
        byte ver;       /* version */
        byte type;      /* type */
        word plen;      /* packet length of standard packet, not including options */
        dword routerid; /* router id */
        dword areaid;   /* area id */
        word cksum;     /* checksum */
        word authtype;  /* authentication type */

        union
        {
                byte null[8];     /* generic authentication data */
                char password[8]; /* password authentication */
                struct
                { /* crypto authentication */
                        word null;
                        byte keyid;
                        byte adlen;
                        dword cryptoseq;
                } authdata;
        };
};

#define OSPF_HEADER_LEN sizeof(s_ospf_header)

/*
 * OSPF LLS block header
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |             Cksum             |        LLS data lenght        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct s_ospf_lls
{
        word cksum; /* checksum of entire LLS block */
        word dlen;  /* LLS block lenght in 32 bit words, includes block header and TLVs */
};

#define OSPF_LLS_LEN sizeof(s_ospf_lls)

/*
 * Structure of a generic OSPF LLS TLV field
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                           Variable                            ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lls_tlv
{
        word type; /* type */
        word vlen; /* length of the variable field */
};

#define OSPF_LLS_TLV_LEN sizeof(s_ospf_lls_tlv)

/*
 * LLS TLV Types
 */

#define OSPF_LLS_TLV_TYPE_EXTOPT 1
#define OSPF_LLS_TLV_TYPE_CAUTH 2

/*
 * Structure of a Extended Options OSPF LLS TLV field
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Flags                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lls_tlv_extopt
{
        word type; /* type */
        word vlen; /* length of the flags field */
        dword flags;
};

#define OSPF_LLS_TLV_EXTOPT_FLAG_LR_MASK 0x00000001 /* LSDB Resynchronization */
#define OSPF_LLS_TLV_EXTOPT_FLAG_RS_MASK 0x00000002 /* Restart Signal */

/*
 * Structure of a Cryptographic Authentication OSPF LLS TLV field
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Type             |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Sequence                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                              MD5                              |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lls_tlv_cauth
{
        word type;       /* type */
        word vlen;       /* length of the flags field */
        dword cryptoseq; /* crypto sequence number */
        byte authdata[16];
};

/*
 * OSPF type field
 */

#define OSPF_TYPE_HELLO_PACKET 1
#define OSPF_TYPE_DD_PACKET 2
#define OSPF_TYPE_LSR_PACKET 3
#define OSPF_TYPE_LSU_PACKET 4
#define OSPF_TYPE_LSA_PACKET 5

/*
 * OSPF authtype field
 */

#define OSPF_AUTHTYPE_NULL 0
#define OSPF_AUTHTYPE_PASSWORD 1
#define OSPF_AUTHTYPE_CRYPTO 2

/*
 * OSPF Hello packet (RFC 2328 + draft-nguyen-ospf-lls-05.txt)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                        Network Mask                           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |         HelloInterval         |    Options    |    Rtr Pri    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     RouterDeadInterval                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      Designated Router                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                   Backup Designated Router                    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~                          Neighbor 0                           ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~                                                               ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~                          Neighbor n                           ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_hello_packet
{
        dword netmask;      /* network mask */
        word hellointerval; /* type */
        byte options;       /* options */
        byte priority;      /* router priority */
        dword deadinterval; /* router dead interval */
        dword dr;           /* designated router */
        dword bdr;          /* backup designated router */
        dword neighbor[1];  /* neighbor, it is optional and variable */
};

#define OSPF_HELLO_PACKET_LEN (sizeof(s_ospf_hello_packet) - 4)

/*
 * OSPF Hello packet options
 */

#define OSPF_HELLO_PACKET_OPTION_DC_MASK 0x20
#define OSPF_HELLO_PACKET_OPTION_L_MASK 0x10
#define OSPF_HELLO_PACKET_OPTION_NP_MASK 0x08
#define OSPF_HELLO_PACKET_OPTION_MC_MASK 0x04
#define OSPF_HELLO_PACKET_OPTION_E_MASK 0x02

/*
 * OSPF DD (Database Descrition) packet (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |         Interface MTU         |            Options            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     DD sequence number                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     |                                                               |
 *     |                         An LSA Header                         |
 *     |                                                               |
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                              ...                              |
 */

struct s_ospf_dd_packet
{
        word mtu;     /* inerface MTU */
        word options; /* options */
        dword seq;    /* equence number */
};

#define OSPF_DD_PACKET_LEN sizeof(s_ospf_dd_packet)

/*
 * OSPF DD packet options
 */

#define OSPF_DD_PACKET_OPTION_MS_MASK 0x0001
#define OSPF_DD_PACKET_OPTION_M_MASK 0x0002
#define OSPF_DD_PACKET_OPTION_I_MASK 0x0004

/*
 * OSPF LSR (Link State Request) packet (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          LS type                              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       Link State ID                           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     Advertising Router                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                              ...                              |
 */

struct s_ospf_lsr_packet
{
        dword type;   /* LS type */
        dword id;     /* LS ID */
        dword advrtr; /* advertising router */
};

#define OSPF_LSR_PACKET_LEN sizeof(s_ospf_lsr_packet)

/*
 * OSPF LSU (Link State Update) packet (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                            # LSAs                             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     +-                                                            +-+
 *     |                             LSAs                              |
 *     +-                                                            +-+
 *     |                              ...                              |
 */

struct s_ospf_lsu_packet
{
        dword lcount; /* number of LSAs included */
};

#define OSPF_LSU_PACKET_LEN sizeof(s_ospf_lsu_packet)

/*
 * OSPF LSA (Link State Acknowledgement) packet (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     +-                                                            +-+
 *     |                             LSAs                              |
 *     +-                                                            +-+
 *     |                              ...                              |
 */

/*
 * OSPF LSA header (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            LS age             |    Options    |    LS type    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                        Link State ID                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     Advertising Router                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     LS sequence number                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |         LS checksum           |             length            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_header
{
        word age;     /* LS age */
        byte options; /* options */
        byte type;    /* LS type */
        dword id;     /* link state ID */
        dword advrtr; /* advertising router */
        dword seq;    /* LS sequence number */
        word cksum;   /* checksum */
        word len;     /* length */
};

#define OSPF_LSA_HEADER_LEN sizeof(s_ospf_lsa_header)

/*
 * Definitions of options
 */

#define OSPF_LSA_HEADER_OPTION_DC_MASK 0x20
#define OSPF_LSA_HEADER_OPTION_L_MASK 0x10
#define OSPF_LSA_HEADER_OPTION_NP_MASK 0x08
#define OSPF_LSA_HEADER_OPTION_MC_MASK 0x04
#define OSPF_LSA_HEADER_OPTION_E_MASK 0x02

/*
 * Definitions of LS types
 */

#define OSPF_LSA_HEADER_TYPE_1 1
#define OSPF_LSA_HEADER_TYPE_2 2
#define OSPF_LSA_HEADER_TYPE_3 3
#define OSPF_LSA_HEADER_TYPE_4 4
#define OSPF_LSA_HEADER_TYPE_5 5
#define OSPF_LSA_HEADER_TYPE_7 7

/*
 * OSPF LSA 1 body (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |     Flags     |        0      |            # links            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_1_body
{
        byte flags;  /* flags */
        byte unused; /* unused */
        word lcount; /* number of links */
};

#define OSPF_LSA_1_BODY_LEN sizeof(s_ospf_lsa_1_body)

/*
 * Definitions of LSA 1 body flags
 */

#define OSPF_LSA_1_BODY_FLAG_B_MASK 0x01
#define OSPF_LSA_1_BODY_FLAG_E_MASK 0x02
#define OSPF_LSA_1_BODY_FLAG_V_MASK 0x04
#define OSPF_LSA_1_BODY_FLAG_W_MASK 0x08
#define OSPF_LSA_1_BODY_FLAG_NT_MASK 0x0F

/*
 * OSPF LSA 1 link (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                          Link ID                              |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Link Data                             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |     Type      |     # TOS     |            metric             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_1_link
{
        dword id;    /* link id */
        dword data;  /* linkdata */
        byte type;   /* type */
        byte tcount; /* tos count */
        word metric; /* metric */
};

#define OSPF_LSA_1_LINK_LEN sizeof(s_ospf_lsa_1_link)

/*
 * Definitions of LSA 1 link types
 */

#define OSPF_LSA_1_LINK_TYPE_P2P 1
#define OSPF_LSA_1_LINK_TYPE_TRANSIT 2
#define OSPF_LSA_1_LINK_TYPE_STUB 3
#define OSPF_LSA_1_LINK_TYPE_VIRTUAL 4

/*
 * OSPF LSA 1 link TOS field (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      TOS      |        0      |          TOS  metric          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_1_link_tos
{
        byte tos;    /* TOS */
        byte unused; /* unused */
        word metric; /* tos metric */
};

#define OSPF_LSA_1_LINK_TOS_LEN sizeof(s_ospf_lsa_1_link_tos)

/*
 * OSPF LSA 2 link (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Network Mask                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                        Attached Router                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_2_link
{
        dword netmask; /* network mask */
        dword attrtr;  /* attached router */
};

#define OSPF_LSA_2_LINK_LEN sizeof(s_ospf_lsa_2_link)

/*
 * OSPF LSA 3 body (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Network Mask                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      0        |                  metric                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_3_body
{
        dword netmask; /* network mask */
        byte unused;
        byte metric[3];  /* metric */
        byte tos;        /* tos */
        byte tmetric[3]; /* tos metric */
};

#define OSPF_LSA_3_BODY_LEN sizeof(s_ospf_lsa_3_body)

/*
 * OSPF LSA 4 body (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Network Mask = 0                      |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      0        |                  metric                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_4_body
{
        dword netmask; /* network mask, always 0 */
        byte unused;
        byte metric[3]; /* metric */
};

#define OSPF_LSA_4_BODY_LEN sizeof(s_ospf_lsa_4_body)

/*
 * OSPF LSA 5 body (RFC 2328)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Network Mask                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |E|     0       |                  Metric                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      Forwarding address                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      External Route Tag                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_5_body
{
        dword netmask;  /* netmask */
        byte type;      /* metric type */
        byte metric[3]; /* metric */
        dword fwdaddr;  /* forwarding address */
        dword tag;      /* tag */
};

#define OSPF_LSA_5_BODY_LEN sizeof(s_ospf_lsa_5_body)

#define OSPF_LSA_5_BODY_TYPE_MASK 0xF0

/*
 * OSPF LSA 7 body (RFC 3101)
 *
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Network Mask                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |E|     0       |                  Metric                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      Forwarding address                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                      External Route Tag                       |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ospf_lsa_7_body
{
        dword netmask;  /* netmask */
        byte type;      /* metric type */
        byte metric[3]; /* metric */
        dword fwdaddr;  /* forwarding address */
        dword tag;      /* tag */
};

#define OSPF_LSA_7_BODY_LEN sizeof(s_ospf_lsa_7_body)

#define OSPF_LSA_7_BODY_TYPE_MASK 0xF0

#endif /* _NETZ_OSPF_H_ */
