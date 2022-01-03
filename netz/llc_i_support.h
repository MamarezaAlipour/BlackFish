#ifndef _NETZ_LLC_I_SUPPORT_H_
#define _NETZ_LLC_I_SUPPORT_H_

#include "llc_i.h"

class c_llc_i_header
{
protected:
    s_llc_i_header *header;

public:
    c_llc_i_header(byte *);
    c_llc_i_header(s_llc_i_header *);

    byte get_dsap();
    byte get_dsap_ig();
    byte get_dsap_addr();
    byte get_ssap();
    byte get_ssap_cr();
    byte get_ssap_addr();
    word get_ctrl();
    byte get_ctrl_ns();
    byte get_ctrl_nr();
    byte get_ctrl_pf();

    void set_dsap(byte);
    void set_dsap_ig(byte);
    void set_dsap_addr(byte);
    void set_ssap(byte);
    void set_ssap_cr(byte);
    void set_ssap_addr(byte);
    void set_ctrl(word = 0x0000);
    void set_ctrl_ns(byte);
    void set_ctrl_nr(byte);
    void set_ctrl_pf(byte);
};

#endif /* _NETZ_LLC_I_SUPPORT_H_ */
