#ifndef _NETZ_ETHLOOP_SUPPORT_H_
#define _NETZ_ETHLOOP_SUPPORT_H_

#include "ethloop.h"

/*
 * Ethernet Loopback support class.
 */

class c_ethloop_header
{

protected:
    s_ethloop_header *header;

public:
    c_ethloop_header(byte *);
    c_ethloop_header(s_ethloop_header *);

    byte get_data(u_int);
};

#endif /* _NETZ_ETHLOOP_SUPPORT_H_ */
