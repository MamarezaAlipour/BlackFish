#ifndef _NETZ_IEEE8023_H_
#define _NETZ_IEEE8023_H_

#include "types.h"

#define IEEE8023_ADDR_LEN 6

/*
 * IEEE 802.3 frame header
 */

struct s_ieee8023_header
{
    byte dst[IEEE8023_ADDR_LEN]; /* destination host address */
    byte src[IEEE8023_ADDR_LEN]; /* source host destination */
    word dlen;                   /* length of the data part */
};

#define IEEE8023_HEADER_LEN sizeof(s_ieee8023_header)

#endif /* _NETZ_IEEE8023_H_ */
