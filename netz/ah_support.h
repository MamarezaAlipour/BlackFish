#ifndef _NETZ_AH_SUPPORT_H_
#define _NETZ_AH_SUPPORT_H_

#include "ah.h"

/*
 * AH protocol support class.
 */

class c_ah_header
{

protected:
    s_ah_header *header;

public:
    c_ah_header(byte *);
    c_ah_header(s_ah_header *);

    byte get_proto();
    byte get_hlen();
    word get_reserved();
    dword get_spi();
    dword get_seq();

    void set_proto(byte);
    void set_hlen(byte);
    void set_reserved(word);
    void set_spi(dword);
    void set_seq(dword);
};

#endif /* _NETZ_AH_SUPPORT_H_ */
