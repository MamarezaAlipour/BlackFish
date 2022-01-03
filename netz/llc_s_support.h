#ifndef _NETZ_LLC_S_SUPPORT_H_
#define _NETZ_LLC_S_SUPPORT_H_

#include "llc_s.h"

class c_llc_s_header
{
protected:
    s_llc_s_header *header;

public:
    c_llc_s_header(byte *);
    c_llc_s_header(s_llc_s_header *);

    byte get_dsap();
    byte get_dsap_ig();
    byte get_dsap_addr();
    byte get_ssap();
    byte get_ssap_cr();
    byte get_ssap_addr();
    word get_ctrl();
    byte get_ctrl_s();
    byte get_ctrl_nr();
    byte get_ctrl_pf();

    void set_dsap(byte);
    void set_dsap_ig(byte);
    void set_dsap_addr(byte);
    void set_ssap(byte);
    void set_ssap_cr(byte);
    void set_ssap_addr(byte);
    void set_ctrl(word = 0x0100);
    void set_ctrl_s(byte);
    void set_ctrl_nr(byte);
    void set_ctrl_pf(byte);
};

#endif /* _NETZ_LLC_S_SUPPORT_H_ */
