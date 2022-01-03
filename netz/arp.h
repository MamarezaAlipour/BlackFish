#ifndef _NETZ_ARP_H_
#define _NETZ_ARP_H_

#include "types.h"

struct s_arp_header
{
	word hrtype;	/* type of hardware address */
	word prtype;	/* type of protocol address */
	byte hrlen;		/* length of hardware address */
	byte prlen;		/* length of protocol address */
	word operation; /* operation type */

	/*
	 * The remaining fields are variable in size,
	 * according to the sizes above.
	 */

#ifdef COMMENT_ONLY
	byte sha[hrlen]; /* sender hardware address */
	byte spa[prlen]; /* sender protocol address */
	byte tha[hrlen]; /* target hardware address */
	byte tpa[prlen]; /* target protocol address */
#endif
};

#define ARP_HEADER_LEN sizeof(s_arp_header);

/*
 * Definitions of hardware type addresses and lenghts (hraddr and hrlen)
 */

#include "hr_type.h" /* definitions */

/*
 * Definitions of protocol type addresses (prtype)
 */

#include "ether_type.h" /* definitions */

#define ARP_PRTYPE_IP ETHER_TYPE_IP
#define ARP_PRTYPE_IP6 ETHER_TYPE_IP6

/*
 * Definitions of protocol type address lengths (prlen)
 */

#define ARP_PRLEN_IP 4
#define ARP_PRLEN_IP6 16

/*
 * Operation (operation)
 */

#define ARP_OP_REQUEST 1	/* request to resolve address */
#define ARP_OP_REPLY 2		/* response to previous request */
#define ARP_OP_REVREQUEST 3 /* request protocol address given hardware */
#define ARP_OP_REVREPLY 4	/* response giving protocol address */
#define ARP_OP_INVREQUEST 8 /* request to identify peer */
#define ARP_OP_INVREPLY 9	/* response identifying peer */

#endif /* _NETZ_ARP_H_ */
