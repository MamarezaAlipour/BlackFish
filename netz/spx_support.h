#ifndef _NETZ_SPX_SUPPORT_H_
#define _NETZ_SPX_SUPPORT_H_

#include "spx.h"

/*
 * SPX protocol supoort class
 */

class c_spx_header
{
protected:
    s_spx_header *header;

public:
    c_spx_header(byte *);
    c_spx_header(s_spx_header *);

    byte get_ccflags();
    byte get_dtype();
    word get_srcid();
    word get_dstid();
    word get_seq();
    word get_ack();
    word get_alloc();

    void set_ccflags(byte);
    void set_dtype(byte);
    void set_srcid(word);
    void set_dstid(word);
    void set_seq(word);
    void set_ack(word);
    void set_alloc(word);

    byte get_ccflag_eom();
    byte get_ccflag_ack();
    byte get_ccflag_sys();

    void set_ccflag_eom(byte);
    void set_ccflag_ack(byte);
    void set_ccflag_sys(byte);
};

#endif /* _NETZ_IPX_SUPPORT_H_ */
