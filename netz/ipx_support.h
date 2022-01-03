#ifndef _NETZ_IPX_SUPPORT_H_
#define _NETZ_IPX_SUPPORT_H_

#include "ipx.h"

/*
 * IPX protocol supoort class
 */

class c_ipx_header
{
protected:
    s_ipx_header *header;

public:
    c_ipx_header(byte *);
    c_ipx_header(s_ipx_header *);

    word get_cksum();
    word get_len();
    byte get_tcontrol();
    byte get_ptype();
    dword get_dnet();
    byte *get_dnode();
    word get_dsock();
    dword get_snet();
    byte *get_snode();
    word get_ssock();

    void set_cksum(word);
    void set_len(word);
    void set_tcontrol(byte);
    void set_ptype(byte);
    void set_dnet(dword);
    void set_dnode(byte *);
    void set_dsock(word);
    void set_snet(dword);
    void set_snode(byte *);
    void set_ssock(word);
};

#endif /* _NETZ_IPX_SUPPORT_H_ */
