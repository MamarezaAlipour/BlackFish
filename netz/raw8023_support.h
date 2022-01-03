#ifndef _NETZ_RAW8023_SUPPORT_H_
#define _NETZ_RAW8023_SUPPORT_H_


#include "raw8023.h"


class c_raw8023_header
{
private:
    s_raw8023_header* header;

public:
    c_raw8023_header(byte*);
    c_raw8023_header(s_raw8023_header*);

    byte* get_raw();

    byte* get_dst();
    byte* get_src();
    word get_dlen();

    void set_dst(byte*);
    void set_src(byte*);
    void set_dlen(word);
};


#endif /* _NETZ_RAW_8023_SUPPORT_H_ */

