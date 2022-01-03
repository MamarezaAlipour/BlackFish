#ifndef _NETZ_DHCP_SUPPORT_H_
#define _NETZ_DHCP_SUPPORT_H_

#include "dhcp.h"

/*
 * DHCP protocol support class.
 */

class c_dhcp_header
{

protected:
    s_dhcp_header *header;

public:
    c_dhcp_header(byte *);
    c_dhcp_header(s_dhcp_header *);

    byte get_op();
    byte get_hrtype();
    byte get_hrlen();
    byte get_hops();
    dword get_xid();
    word get_secs();
    word get_flags();
    byte get_flag_b();
    dword get_ciaddr();
    dword get_yiaddr();
    dword get_siaddr();
    dword get_giaddr();
    byte *get_chaddr();
    byte *get_sname();
    byte *get_file();
};

#endif /* _NETZ_DHCP_SUPPORT_H_ */
