#ifndef _NETZ_HR_TYPE_H_
#define _NETZ_HR_TYPE_H_

#include "types.h"

/*
 * Hardware address types used by ARP and DHCP
 */

#define ARP_HRTYPE_ETHER 1   /* ethernet hardware format */
#define ARP_HRTYPE_IEEE802 6 /* IEEE 802 hardware format */
#define ARP_HRTYPE_FRELAY 15 /* frame relay hardware format */

/*
 * Length of hardware address types used by ARP and DHCP
 */

#define ARP_HRLEN_ETHER 6   /* ethernet hardware format */
#define ARP_HRLEN_IEEE802 6 /* IEEE 802 hardware format */

#endif /* _NETZ_HR_TYPE_H_ */
