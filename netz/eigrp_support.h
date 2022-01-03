#ifndef _NETZ_EIGRP_SUPPORT_H_
#define _NETZ_EIGRP_SUPPORT_H_

#include "eigrp.h"

/*
 * EIGRP protocol support class.
 */

class c_eigrp_header
{

protected:
    s_eigrp_header *header;

public:
    c_eigrp_header(byte *);
    c_eigrp_header(s_eigrp_header *);

    byte get_ver();
    byte get_opcode();
    word get_cksum();
    dword get_flags();
    byte get_flag_init();
    byte get_flag_cr();
    dword get_seq();
    dword get_ack();
    dword get_as();
};

class c_eigrp_tlv
{

protected:
    s_eigrp_tlv *tlv;

public:
    c_eigrp_tlv(byte *);
    c_eigrp_tlv(s_eigrp_tlv *);

    word get_type();
    word get_len();
};

class c_eigrp_tlv_parameters
{

protected:
    s_eigrp_tlv_parameters *tlv_parameters;

public:
    c_eigrp_tlv_parameters(byte *);
    c_eigrp_tlv_parameters(s_eigrp_tlv_parameters *);

    word get_type();
    word get_len();
    byte get_k1();
    byte get_k2();
    byte get_k3();
    byte get_k4();
    byte get_k5();
    word get_holdtime();
};

class c_eigrp_tlv_softver
{

protected:
    s_eigrp_tlv_softver *tlv_softver;

public:
    c_eigrp_tlv_softver(byte *);
    c_eigrp_tlv_softver(s_eigrp_tlv_softver *);

    word get_type();
    word get_len();
    byte get_ver(u_int);
};

class c_eigrp_tlv_ipintup
{

protected:
    s_eigrp_tlv_ipintup *tlv_ipintup;

public:
    c_eigrp_tlv_ipintup(byte *);
    c_eigrp_tlv_ipintup(s_eigrp_tlv_ipintup *);

    word get_type();
    word get_len();
    dword get_nexthop();
    dword get_delay();
    dword get_bandwidth();
    dword get_mtu();
    byte get_hopcount();
    word get_reliability();
    byte get_load();
    byte get_prefixlen();
    dword get_destination();
};

class c_eigrp_tlv_ipextup
{

protected:
    s_eigrp_tlv_ipextup *tlv_ipextup;

public:
    c_eigrp_tlv_ipextup(byte *);
    c_eigrp_tlv_ipextup(s_eigrp_tlv_ipextup *);

    word get_type();
    word get_len();
    dword get_nexthop();
    dword get_orouter();
    dword get_oas();
    dword get_atag();
    dword get_epmetric();
    byte get_epid();
    byte get_flags();
    dword get_delay();
    dword get_bandwidth();
    dword get_mtu();
    byte get_hopcount();
    word get_reliability();
    byte get_load();
    byte get_prefixlen();
    dword get_destination();
};

#endif /* _NETZ_IGRP_SUPPORT_H_ */
