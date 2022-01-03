#ifndef _NETZ_GRE_SUPPORT_H_
#define _NETZ_GRE_SUPPORT_H_

#include "gre.h"

/*
 * GRE protocol support class.
 */

class c_gre_header
{

protected:
    s_gre_header *header;

    word *cksum;
    word *offset;
    dword *key;
    dword *seq;
    void *routing;

    word get_frrv();

public:
    c_gre_header(byte *);
    c_gre_header(s_gre_header *);

    u_int get_len();

    byte get_flag_cksum();
    byte get_flag_routing();
    byte get_flag_key();
    byte get_flag_seq();
    byte get_flag_ssr();
    byte get_recur();
    byte get_ver();
    word get_type();

    word get_cksum();
    word get_offset();
    dword get_key();
    dword get_seq();
};

#endif /* _NETZ_GRE_SUPPORT_H_ */
