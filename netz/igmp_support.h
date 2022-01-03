#ifndef _NETZ_IGMP_SUPPORT_H_
#define _NETZ_IGMP_SUPPORT_H_

#include "igmp.h"

class c_igmp_header
{
protected:
    s_igmp_header *header;

public:
    c_igmp_header(byte *);

    s_igmp_header *get_header();

    byte get_type();
    byte get_code();
    word get_cksum();
    dword get_group();

    void set_type(byte);
    void set_code(byte);
    void set_cksum(word);
    void set_group(dword);
};

#endif /* _NETZ_IGMP_SUPPORT_H_ */
