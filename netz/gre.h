#ifndef _NETZ_GRE_H_
#define _NETZ_GRE_H_

/*
 * Structure of an GRE packet (RFC 1701)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |C|R|K|S|s|Recur|   Res   | Ver |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Checksum (optional)      |       Offset (optional)       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Key (optional)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sequence Number (optional)                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                         Routing (optional)                    ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "types.h"

struct s_gre_header
{
        word frrv; /* flags, recur, reserved, version */
        word type; /* protocol type - ethernet protocol type*/
};

#define GRE_HEADER_LEN sizeof(s_gre_header) /* just the first 4 octets, */
                                            /* the rest is optional */

#define GRE_CKSUM_LEN 2
#define GRE_OFFSET_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQ_LEN 4
#define GRE_ROUTING_LEN 4

#define GRE_FRRV_FLAG_CKSUM_MASK 0x8000
#define GRE_FRRV_FLAG_ROUTING_MASK 0x4000
#define GRE_FRRV_FLAG_KEY_MASK 0x2000
#define GRE_FRRV_FLAG_SEQ_MASK 0x1000
#define GRE_FRRV_FLAG_SSR_MASK 0x0800
#define GRE_FRRV_RECUR_MASK 0x0700
#define GRE_FRRV_RESERVED_MASK 0x00F8
#define GRE_FRRV_VER_MASK 0x0007

/*
 * SRE - Source route entry
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       Address Family          |  SRE Offset   |  SRE Length   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                        Routing Information ...                ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_gre_sre
{
        word af;     /* address family */
        byte offset; /* SRE offset */
        byte len;    /* SRE length */
};

#endif /* _NETZ_GRE_H_ */
