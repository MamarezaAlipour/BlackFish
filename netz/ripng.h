#ifndef _NETZ_RIPNG_H_
#define _NETZ_RIPNG_H_

#include "types.h"

#define IP6_ADDR_LEN 16

/*
 * Structure of an RIPng header ()
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Command    |    Version    |              Pad              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ripng_header
{
	byte cmd; /* command */
	byte ver; /* version */
	word pad; /* not used, must be set to 0 */
};

#define RIPNG_HEADER_LEN sizeof(s_ripng_header)

/*
 * RIPng commands
 */

#define RIPNG_CMD_REQUEST 1
#define RIPNG_CMD_RESPONSE 2

/*
 * Structure of RIPng route entry ()
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         IPv6 Prefix                           +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Route tag         |  Prefix length  |    Metric     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ripng_route_entry
{
	byte prefix[IP6_ADDR_LEN]; /* IPv6 Prefix */
	word tag;				   /* route tag */
	byte prefix_len;		   /* prefix length */
	byte metric;			   /* metric */
};

#define RIPNG_ENTRY_LEN sizeof(s_ripng_route_entry)

/*
 * Structure of RIPng next hop entry ()
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                          Next hop                             +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             0x0000          |       0x00      |      0xFF     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_ripng_next_hop_entry
{
	byte next_hop[IP6_ADDR_LEN]; /* IPv6 Prefix */
	word pad1;					 /* always set to 0x0000 */
	byte pad2;					 /* always set to 0x00 */
	byte metric;				 /* always set to 0xFF */
};

#define RIPNG_NEXT_HOP_ENTRY_ID 0xFF

#endif /* _NETZ_RIPNG_H_ */
