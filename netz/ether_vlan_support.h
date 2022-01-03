#ifndef _NETZ_ETHER_VLAN_SUPPORT_H_
#define _NETZ_ETHER_VLAN_SUPPORT_H_

#include "ether_vlan.h"

class c_ether_vlan_header
{
private:
    s_ether_vlan_header *header;

public:
    c_ether_vlan_header(byte *);

    byte *get_raw();

    byte *get_dst();
    byte *get_src();
    word get_tpid();
    word get_tci();
    byte get_priority();
    word get_vid();
    word get_type();

    void set_dst(byte *);
    void set_src(byte *);
    void set_tpid(word = ETHER_VLAN_TPID);
    void set_tci(word);
    void set_priority(byte);
    void set_vid(word);
    void set_type(word);
};

#endif /* _NETZ_ETHER_VLAN_SUPPORT_H_ */
