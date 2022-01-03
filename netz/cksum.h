#ifndef _NETZ_CKSUM_H_
#define _NETZ_CKSUM_H_

#include "types.h"

enum e_pseudo_header_type
{
    PSEUDO_HEADER_TYPE_IP,
    PSEUDO_HEADER_TYPE_IP6
};

class c_pseudo_header
{
public:
    e_pseudo_header_type header_type;
    u_int header_len;
    byte header[64];
};

word cksum(byte *, u_int);
word cksum(byte *, u_int, c_pseudo_header);

#endif /* _NETZ_CKSUM_H_ */
