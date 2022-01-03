#ifndef _NETZ_LLC_U_SUPPORT_H_
#define _NETZ_LLC_U_SUPPORT_H_

#include "llc_u.h"

class c_llc_u_header
{
protected:
    s_llc_u_header *header;

public:
    c_llc_u_header(byte *);
    c_llc_u_header(s_llc_u_header *);

    byte get_dsap();
    byte get_dsap_ig();
    byte get_dsap_addr();
    byte get_ssap();
    byte get_ssap_cr();
    byte get_ssap_addr();
    byte get_ctrl();
    byte get_ctrl_m();
    byte get_ctrl_pf();

    void set_dsap(byte);
    void set_dsap_ig(byte);
    void set_dsap_addr(byte);
    void set_ssap(byte);
    void set_ssap_cr(byte);
    void set_ssap_addr(byte);
    void set_ctrl(byte = 0x03);
    void set_ctrl_m(byte);
    void set_ctrl_pf(byte);
};

#endif /* _NETZ_LLC_U_SUPPORT_H_ */
