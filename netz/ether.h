#ifndef _NETZ_ETHER_H_
#define _NETZ_ETHER_H_

#include "types.h"

#define ETHER_ADDR_LEN 6

/*
 * Ethernet frame header
 */

struct s_ether_header
{
    byte dst[ETHER_ADDR_LEN]; /* destination host address */
    byte src[ETHER_ADDR_LEN]; /* source host destination */
    word type;                /* type of carried protocol */
};

#define ETHER_HEADER_LEN sizeof(s_ether_header)

/*
 * Definitions of protocols (type)
 */

#include "ether_type.h" /* definitions and print function */

#endif /* _NETZ_ETHER_H_ */
