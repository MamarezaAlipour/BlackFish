#ifndef _NETZ_CDP_H_
#define _NETZ_CDP_H_

#include "types.h"

/*
 * Structure of a CDP header (Cisco proprietary)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Version    |      TTL      |            Checksum           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

/*
 *
 * Structure of CDP data field
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |             Length            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                     Value (variable length)                   ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_cdp_header
{
	byte ver;	/* version */
	byte ttl;	/* time to live */
	word cksum; /* cksum */
};

struct s_cdp_dheader
{
	word type; /* type */
	word len;  /* length */
};

#define CDP_HEADER_LEN sizeof(s_cdp_header)

#define CDP_DHEADER_LEN sizeof(s_cdp_header)

#define CDP_DHEADER_TYPE_DEVICE_ID 0x0001
#define CDP_DHEADER_TYPE_ADDRESS 0x0002
#define CDP_DHEADER_TYPE_PORT_ID 0x0003
#define CDP_DHEADER_TYPE_CAPABILITIES 0x0004
#define CDP_DHEADER_TYPE_VERSION 0x0005
#define CDP_DHEADER_TYPE_PLATFORM 0x0006
#define CDP_DHEADER_TYPE_IP_PREFIX 0x0007

#endif /* _NETZ_CDP_H_ */
