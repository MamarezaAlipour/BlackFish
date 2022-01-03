#ifndef _NETZ_RIP_H_
#define _NETZ_RIP_H_

#include "types.h"

/*
 * Structure of an RIP/RIPv2 header (RFC 2453)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Command    |    Version    |              Pad              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_rip_header
{
	byte cmd; /* command */
	byte ver; /* version */
	word pad; /* not used, must be set to 0 */
};

#define RIP_HEADER_LEN sizeof(s_rip_header)

/*
 * RIP commands
 */

#define RIP_CMD_REQUEST 1
#define RIP_CMD_RESPONSE 2

/*
 * Structure of an RIP/RIPv2 entry (RFC 2453)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Address Family Identifier   |           Route Tag           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          IP Address                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Subnet Mask                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Next Hop                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                            Metric                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_rip_entry
{
	word afi;	   /* address family identifier */
	word tag;	   /* route tag (RIPv2) */
	dword ip;	   /* ip address */
	dword mask;	   /* subnet mask (RIPv2) */
	dword nexthop; /* next hop (RIPv2) */
	dword metric;  /* metric */
};

#define RIP_ENTRY_LEN sizeof(s_rip_entry)

/*
 * Structure of an RIPv2 authentication entry (RFC 2453)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            0xFFFF             |       Authentication Type     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                      Authentication Key                       |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_rip_authentry
{
	word id;   /* entry id, must be set to 0xFFFF */
	word type; /* authentication type */

	union
	{
		byte key[16]; /* key for simple authentication */

		struct
		{				/* fields for md5 authentication */
			word len;	/* RIPv2 packet length */
			byte keyid; /* key ID */
			byte adlen; /* authentication data length */
			dword seq;	/* sequence number */
			dword pad[2];
		} md5;
	};
};

#define RIP_AUTHENTRY_LEN sizeof(s_rip_authentry)

#define RIP_AUTHENTRY_ID 0xFFFF

/*
 * RIP authentication types
 */

#define RIP_AUTHTYPE_SIMPLE 2
#define RIP_AUTHTYPE_MD5 3

/*
 * Structure of an RIPv2 MD5 authentication entry (RFC 2453)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            0xFFFF             |            0x0001             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     MD5 Authentication Key                    |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_rip_md5entry
{
	word id1;
	word id2;
	byte key[16];
};

#define RIP_MD5ENTRY_LEN sizeof(s_rip_md5entry)

#define RIP_MD5ENTRY_ID1 0xFFFF
#define RIP_MD5ENTRY_ID2 0x0001

#endif /* _NETZ_RIP_H_ */
