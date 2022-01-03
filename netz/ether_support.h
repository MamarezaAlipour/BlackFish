#ifndef _NETZ_ETHER_SUPPORT_H_
#define _NETZ_ETHER_SUPPORT_H_

#include "ether.h"

class c_ether_header
{
private:
    s_ether_header *header;

public:
    c_ether_header(byte *);
    c_ether_header(s_ether_header *);

    byte *get_raw();

    byte *get_dst();
    byte *get_src();
    word get_type();

    void set_dst(byte *);
    void set_src(byte *);
    void set_type(word);
};

#endif /* _NETZ_ETHER_SUPPORT_H_ */
