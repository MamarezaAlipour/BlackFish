#ifndef _NETZ_ETHER_VLAN_H_
#define _NETZ_ETHER_VLAN_H_

#include "types.h"

#define ETHER_VLAN_ADDR_LEN 6

/*
 * ETHERNET frame headder + IEEE 802.1Q VLAN tagging
 */

struct s_ether_vlan_header
{
    byte dst[ETHER_VLAN_ADDR_LEN]; /* destination host address */
    byte src[ETHER_VLAN_ADDR_LEN]; /* source host address */
    word tpid;                     /* tag protocol identifier */
    word tci;                      /* tag control information */
    word type;                     /* type of carried protocol */
};

#define ETHER_VLAN_HEADER_LEN sizeof(s_ether_vlan_header)

/*
 * Etherenet Vlan tpid field value
 */

#define ETHER_VLAN_TPID 0x8100 /* vlan tpid value */

/*
 * Masks for tci field
 */

#define ETHER_VLAN_TCI_PRIORITY_MASK 0xE000 /* mask of priority bits */
#define ETHER_VLAN_TCI_VID_MASK 0x0FFF      /* mask of VLAN identifier */

/*
 * Definitions of protocols (type)
 */

#include "ether_type.h" /* definitions and print function */

#endif /* _NETZ_ETHER_VLAN_H_ */
