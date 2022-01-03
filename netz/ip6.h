#ifndef _NETZ_IP6_H_
#define _NETZ_IP6_H_

#include "types.h"

#define IP6_ADDR_LEN 16 /* length of IPv6 address */

/*
 * Structure of an IPv6 header.
 *
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Traffic Class |           Flow Label                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload Length        |  Next Header  |   Hop Limit   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ip6_header
{
    dword vcf;              /* version, class and flow label */
    word plen;              /* payload length */
    byte next;              /* next header type */
    byte hlimit;            /* hops limit */
    byte src[IP6_ADDR_LEN]; /* source IPv6 address */
    byte dst[IP6_ADDR_LEN]; /* destination IPv6 address */
};

#define IP6_HEADER_LEN sizeof(s_ip6_header)

/*
 * version, class and flow label masks
 */

#define IP6_VERSION_MASK 0xF0000000 /* version mask */
#define IP6_TCLASS_MASK 0x0FF00000  /* class mask */
#define IP6_FLABEL_MASK 0x000FFFFF  /* flow label mask */

/*
 * Definitions of protocols (ip6_next)
 */

#include "ip_proto.h" /* definitions and print function */

/*
 * Pseudo header used to compute tcp/udp/icmp6 checksums
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                   Upper-Layer Packet Length                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      zero                     |  Next Header  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ip6p_header
{
    byte src[IP6_ADDR_LEN]; /* source IPv6 address */
    byte dst[IP6_ADDR_LEN]; /* destination IPv6 addres */
    dword plen;             /* payload length */
    byte pad[3];            /* pad bytes, must be zero */
    byte next;              /* next header type */
};

#define IP6P_HEADER_LEN sizeof(s_ip6p_header)

#endif /* _NETZ_IP6_H_ */
