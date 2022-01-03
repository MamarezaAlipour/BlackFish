#ifndef _NETZ_UDP_SUPPORT_H_
#define _NETZ_UDP_SUPPORT_H_

#include "udp.h"

/*
 * Udp protocol support class.
 */

class c_udp_header
{

protected:
    s_udp_header *header;

public:
    c_udp_header(byte *);
    c_udp_header(s_udp_header *);

    word get_sport();
    word get_dport();
    word get_len();
    word get_cksum();

    void set_sport(word);
    void set_dport(word);
    void set_len(word = sizeof(s_udp_header));
    void set_cksum(word = 0);
};

#endif /* _NETZ_UDP_SUPPORT_H_ */
