#ifndef _NETZ_SNAP_H_
#define _NETZ_SNAP_H_

#include "types.h"

/*
 * IEEE 802.3 SNAP (SubNetwork Attachement Protocol) header
 */

#pragma pack(1)

struct s_snap_header
{
    byte oui[3]; /* Organizational Unique Identifier */
    word type;   /* the same as ether_type in Ethernet frame */
};

#pragma pack(4)

#define SNAP_HEADER_LEN sizeof(s_snap_header)

/*
 * Definitions of OUIs (oui)
 */

#define OUI_CISCO 0x00000C /* cisco systems */

/*
 * Definitions of protocols (snap_type)
 */

#include "ether_type.h" /* definitions of ether types */

#endif /* _NETZ_SNAP_H_ */
