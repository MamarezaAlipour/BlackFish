#ifndef _NETZ_AH_H_
#define _NETZ_AH_H_

/*
 * Structure of an AH packet (RFC 2402)
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Next Header   |  Payload Len  |          RESERVED             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Security Parameters Index (SPI)               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Sequence Number Field                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                Authentication Data (variable)                 |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
 *
 */

#include "types.h"


struct s_ah_header {
        byte proto;		/* next header */
	byte hlen;		/* AH payload (header) length in 32 bit words*/
        word reserved;		/* reserved */
	dword spi;		/* SPI */
	dword seq;		/* sequence number */
};


#define AH_HEADER_LEN sizeof(s_ah_header)


#endif /* _NETZ_AH_H_ */

