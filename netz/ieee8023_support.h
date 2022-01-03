#ifndef _NETZ_IEEE8023_SUPPORT_H_
#define _NETZ_IEEE8023_SUPPORT_H_

#include "ieee8023.h"

class c_ieee8023_header
{
private:
    s_ieee8023_header *header;

public:
    c_ieee8023_header(byte *);
    c_ieee8023_header(s_ieee8023_header *);

    byte *get_raw();

    byte *get_dst();
    byte *get_src();
    word get_dlen();

    void set_dst(byte *);
    void set_src(byte *);
    void set_dlen(word);
};

#endif /* _NETZ_IEEE_8023_SUPPORT_H_ */
