#ifndef _NETZ_ENC_H_
#define _NETZ_ENC_H_

#include "types.h"

/*
 * ENC interface frame header
 */

struct s_enc_header
{
    dword af;
    dword spi;
    dword flags;
};

#define ENC_HEADER_LEN sizeof(s_enc_header)

/*
 * Definitions of address family field
 */

#define ENC_AF_INET 33554432
#define ENC_AF_INET6 402653184

#endif /* _NETZ_ENC_H_ */
