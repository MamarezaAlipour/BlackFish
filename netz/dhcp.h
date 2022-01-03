#ifndef _NETZ_DHCP_H_
#define _NETZ_DHCP_H_

#include "types.h"

/*
 * Structure of an DHCP header (RFC 2131)
 *
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       op      |     hrtype    |     hrlen     |      hops     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               xid                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              secs             |              flags            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             ciaddr                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             yiaddr                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             siaddr                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             giaddr                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                             chaddr                            |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                             sname                             |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                             file                              |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                            options                            ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

struct s_dhcp_header
{
        byte op;         /* message op code */
        byte hrtype;     /* hardware address type */
        byte hrlen;      /* hardware address length */
        byte hops;       /* hops */
        dword xid;       /* transaction id */
        word secs;       /* seconds elapsed */
        word flags;      /* flags */
        dword ciaddr;    /* client ip address (already owned) */
        dword yiaddr;    /* your (client) ip address */
        dword siaddr;    /* ip of tne next server to use in bootstrap */
        dword giaddr;    /* relay agent ip address */
        byte chaddr[16]; /* client hardware address */
        byte sname[8];   /* server hostname, null terminated string */
        byte file[8];    /* boot filename, null terminated */
};

#define DHCP_HEADER_LEN sizeof(s_dhcp_header)

/*
 * DHCP Op codes
 */

#define DHCP_OP_BOOTREQUEST 1
#define DHCP_OP_BOOTREPLY 2

/*
 * DHCP Flags definitions
 */

#define DHCP_FLAG_B_MASK 0x8000

#endif /* _NETZ_DHCP_H_ */
