#ifndef _NETZ_RAW8023_H_
#define _NETZ_RAW8023_H_


#include "types.h"


#define RAW8023_ADDR_LEN 6

/*
 * RAW 802.3 frame header
 */

struct s_raw8023_header
{
    byte dst[RAW8023_ADDR_LEN];		/* destination host address */
    byte src[RAW8023_ADDR_LEN];		/* source host destination */
    word dlen;			        /* length of the data part */
};


#define RAW8023_HEADER_LEN sizeof(s_raw8023_header)


/*
 * Identifier of Novell proprietary frame                                     
 */ 

#define NOVELL_RAW_802_3            0xFFFF 


#endif /* _NETZ_RAW8023_H_ */

