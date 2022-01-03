#ifndef _NETZ_UDP_H_
#define _NETZ_UDP_H_

#include "types.h"

/*
 * Structure of an UDP header (RFC 768)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |        Destination Port       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |            Checksum           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_udp_header
{
	word sport; /* source port */
	word dport; /* destination port */
	word len;	/* length */
	word cksum; /* checksum */
};

#define UDP_HEADER_LEN sizeof(s_udp_header)

/*
 * Well known UPD ports
 */

#define UDP_PORT_DHCP_SERVER 67 /* DHCP Server */
#define UDP_PORT_DHCP_CLIENT 68 /* DHCP Client */
#define UDP_PORT_RIP 520		/* RIP and RIPv2 routing protocols */
#define UDP_PORT_RIPNG 521		/* RIPng routing protocol */

#endif /* _NETZ_UDP_H_ */
