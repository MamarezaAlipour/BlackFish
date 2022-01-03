#ifndef _NETZ_ETHLOOP_H_
#define _NETZ_ETHLOOP_H_

#include "types.h"

/*
 * Etherenet loopback contains 46 of null bytes
 */

struct s_ethloop_header
{
	byte data[46];
};

#define ETHLOOP_HEADER_LEN sizeof(s_ethloop_header)

#endif /* _NETZ_ETHLOOP_H_ */
