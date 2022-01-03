#ifndef _NETZ_IGRP_SUPPORT_H_
#define _NETZ_IGRP_SUPPORT_H_

#include "igrp.h"

/*
 * IGRP protocol support class.
 */

class c_igrp_header
{

protected:
    s_igrp_header *header;

public:
    c_igrp_header(byte *);
    c_igrp_header(s_igrp_header *);

    byte get_ver();
    byte get_opcode();
    byte get_edition();
    word get_as();
    word get_interior();
    word get_system();
    word get_exterior();
    word get_cksum();

    void set_ver(byte);
    void set_opcode(byte);
    void set_edition(byte);
    void set_as(word);
    void set_interior(word);
    void set_system(word);
    void set_exterior(word);
    void set_cksum(word = 0);
};

class c_igrp_update
{

protected:
    s_igrp_update *update;

public:
    c_igrp_update(byte *);
    c_igrp_update(s_igrp_update *);

    dword get_net();
    dword get_intnet();
    dword get_delay();
    dword get_bandwidth();
    word get_mtu();
    byte get_reliability();
    byte get_load();
    byte get_hopcount();

    void set_net(dword);
    void set_intnet(dword);
    void set_delay(dword);
    void set_bandwidth(dword);
    void set_mtu(word);
    void set_reliability(byte);
    void set_load(byte);
    void set_hopcount(byte);
};

#endif /* _NETZ_IGRP_SUPPORT_H_ */
