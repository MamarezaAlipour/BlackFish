#ifndef _NETZ_LOOP_H_
#define _NETZ_LOOP_H_

#include "types.h"

/*
 * PCAP LOOP  frame header
 */

struct s_loop_header
{
    dword af;
};

#define LOOP_HEADER_LEN sizeof(s_loop_header)

/*
 * Definitions of address family field
 */

#define LOOP_AF_INET 2
#define LOOP_AF_INET6 24

#endif /* _NETZ_LOOP_H_ */
