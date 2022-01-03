#ifndef _NETZ_GIF_H_
#define _NETZ_GIF_H_

#include "types.h"

/*
 * GIF interface frame header
 */

struct s_gif_header
{
    dword af;
};

#define GIF_HEADER_LEN sizeof(s_gif_header)

/*
 * Definitions of address family field
 */

#define GIF_AF_INET 33554432
#define GIF_AF_INET6 402653184

#endif /* _NETZ_GIF_H_ */
