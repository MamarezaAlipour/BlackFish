#include "eigrp_support.h"
#include "support.h"

c_eigrp_header::c_eigrp_header(byte *eigrp_header)
{
    header = (s_eigrp_header *)eigrp_header;
}

c_eigrp_header::c_eigrp_header(s_eigrp_header *eigrp_header)
{
    header = eigrp_header;
}

byte c_eigrp_header::get_ver()
{
    return ntoh(header->ver);
}

byte c_eigrp_header::get_opcode()
{
    return ntoh(header->opcode);
}

word c_eigrp_header::get_cksum()
{
    return ntoh(header->cksum);
}

dword c_eigrp_header::get_flags()
{
    return ntoh(header->flags);
}

byte c_eigrp_header::get_flag_init()
{
    return bits(get_flags(), EIGRP_FLAG_INIT_MASK);
}

byte c_eigrp_header::get_flag_cr()
{
    return bits(get_flags(), EIGRP_FLAG_CR_MASK);
}

dword c_eigrp_header::get_seq()
{
    return ntoh(header->seq);
}

dword c_eigrp_header::get_ack()
{
    return ntoh(header->ack);
}

dword c_eigrp_header::get_as()
{
    return ntoh(header->as);
}

c_eigrp_tlv::c_eigrp_tlv(byte *eigrp_tlv)
{
    tlv = (s_eigrp_tlv *)eigrp_tlv;
}

c_eigrp_tlv::c_eigrp_tlv(s_eigrp_tlv *eigrp_tlv)
{
    tlv = eigrp_tlv;
}

word c_eigrp_tlv::get_type()
{
    return ntoh(tlv->type);
}

word c_eigrp_tlv::get_len()
{
    return ntoh(tlv->len);
}

c_eigrp_tlv_parameters::c_eigrp_tlv_parameters(byte *eigrp_tlv_parameters)
{
    tlv_parameters = (s_eigrp_tlv_parameters *)eigrp_tlv_parameters;
}

c_eigrp_tlv_parameters::c_eigrp_tlv_parameters(s_eigrp_tlv_parameters *eigrp_tlv_parameters)
{
    tlv_parameters = eigrp_tlv_parameters;
}

word c_eigrp_tlv_parameters::get_type()
{
    return ntoh(tlv_parameters->type);
}

word c_eigrp_tlv_parameters::get_len()
{
    return ntoh(tlv_parameters->len);
}

byte c_eigrp_tlv_parameters::get_k1()
{
    return ntoh(tlv_parameters->k1);
}

byte c_eigrp_tlv_parameters::get_k2()
{
    return ntoh(tlv_parameters->k2);
}

byte c_eigrp_tlv_parameters::get_k3()
{
    return ntoh(tlv_parameters->k3);
}

byte c_eigrp_tlv_parameters::get_k4()
{
    return ntoh(tlv_parameters->k4);
}

byte c_eigrp_tlv_parameters::get_k5()
{
    return ntoh(tlv_parameters->k5);
}

word c_eigrp_tlv_parameters::get_holdtime()
{
    return ntoh(tlv_parameters->holdtime);
}

c_eigrp_tlv_softver::c_eigrp_tlv_softver(byte *eigrp_tlv_softver)
{
    tlv_softver = (s_eigrp_tlv_softver *)eigrp_tlv_softver;
}

c_eigrp_tlv_softver::c_eigrp_tlv_softver(s_eigrp_tlv_softver *eigrp_tlv_softver)
{
    tlv_softver = eigrp_tlv_softver;
}

word c_eigrp_tlv_softver::get_type()
{
    return ntoh(tlv_softver->type);
}

word c_eigrp_tlv_softver::get_len()
{
    return ntoh(tlv_softver->len);
}

byte c_eigrp_tlv_softver::get_ver(u_int n)
{
    return ntoh(tlv_softver->ver[n]);
}

c_eigrp_tlv_ipintup::c_eigrp_tlv_ipintup(byte *eigrp_tlv_ipintup)
{
    tlv_ipintup = (s_eigrp_tlv_ipintup *)eigrp_tlv_ipintup;
}

c_eigrp_tlv_ipintup::c_eigrp_tlv_ipintup(s_eigrp_tlv_ipintup *eigrp_tlv_ipintup)
{
    tlv_ipintup = eigrp_tlv_ipintup;
}

word c_eigrp_tlv_ipintup::get_type()
{
    return ntoh(tlv_ipintup->type);
}

word c_eigrp_tlv_ipintup::get_len()
{
    return ntoh(tlv_ipintup->len);
}

dword c_eigrp_tlv_ipintup::get_nexthop()
{
    return ntoh(tlv_ipintup->nexthop);
}

dword c_eigrp_tlv_ipintup::get_delay()
{
    return ntoh(tlv_ipintup->delay);
}

dword c_eigrp_tlv_ipintup::get_bandwidth()
{
    return ntoh(tlv_ipintup->bandwidth);
}

dword c_eigrp_tlv_ipintup::get_mtu()
{
    dword mtu;

    *((byte *)&mtu + 0) = 0;
    *((byte *)&mtu + 1) = ntoh(tlv_ipintup->mtu[0]);
    *((byte *)&mtu + 2) = ntoh(tlv_ipintup->mtu[1]);
    *((byte *)&mtu + 3) = ntoh(tlv_ipintup->mtu[2]);

    return ntoh(mtu);
}

byte c_eigrp_tlv_ipintup::get_hopcount()
{
    return ntoh(tlv_ipintup->hopcount);
}

word c_eigrp_tlv_ipintup::get_reliability()
{
    return ntoh(tlv_ipintup->reliability);
}

byte c_eigrp_tlv_ipintup::get_load()
{
    return ntoh(tlv_ipintup->load);
}

byte c_eigrp_tlv_ipintup::get_prefixlen()
{
    return ntoh(tlv_ipintup->prefixlen);
}

dword c_eigrp_tlv_ipintup::get_destination()
{
    dword destination = 0;

    if (get_prefixlen() > 0)
        *((byte *)&destination + 3) = ntoh(tlv_ipintup->destination[0]);

    if (get_prefixlen() > 8)
        *((byte *)&destination + 2) = ntoh(tlv_ipintup->destination[1]);

    if (get_prefixlen() > 16)
        *((byte *)&destination + 1) = ntoh(tlv_ipintup->destination[2]);

    if (get_prefixlen() > 24)
        *((byte *)&destination + 0) = ntoh(tlv_ipintup->destination[3]);

    return ntoh(destination);
}

c_eigrp_tlv_ipextup::c_eigrp_tlv_ipextup(byte *eigrp_tlv_ipextup)
{
    tlv_ipextup = (s_eigrp_tlv_ipextup *)eigrp_tlv_ipextup;
}

c_eigrp_tlv_ipextup::c_eigrp_tlv_ipextup(s_eigrp_tlv_ipextup *eigrp_tlv_ipextup)
{
    tlv_ipextup = eigrp_tlv_ipextup;
}

word c_eigrp_tlv_ipextup::get_type()
{
    return ntoh(tlv_ipextup->type);
}

word c_eigrp_tlv_ipextup::get_len()
{
    return ntoh(tlv_ipextup->len);
}

dword c_eigrp_tlv_ipextup::get_nexthop()
{
    return ntoh(tlv_ipextup->nexthop);
}

dword c_eigrp_tlv_ipextup::get_orouter()
{
    return ntoh(tlv_ipextup->orouter);
}

dword c_eigrp_tlv_ipextup::get_oas()
{
    return ntoh(tlv_ipextup->oas);
}

dword c_eigrp_tlv_ipextup::get_atag()
{
    return ntoh(tlv_ipextup->atag);
}

dword c_eigrp_tlv_ipextup::get_epmetric()
{
    return ntoh(tlv_ipextup->epmetric);
}

byte c_eigrp_tlv_ipextup::get_epid()
{
    return ntoh(tlv_ipextup->epid);
}

byte c_eigrp_tlv_ipextup::get_flags()
{
    return ntoh(tlv_ipextup->flags);
}

dword c_eigrp_tlv_ipextup::get_delay()
{
    return ntoh(tlv_ipextup->delay);
}

dword c_eigrp_tlv_ipextup::get_bandwidth()
{
    return ntoh(tlv_ipextup->bandwidth);
}

dword c_eigrp_tlv_ipextup::get_mtu()
{
    dword mtu;

    *((byte *)&mtu + 0) = 0;
    *((byte *)&mtu + 1) = ntoh(tlv_ipextup->mtu[0]);
    *((byte *)&mtu + 2) = ntoh(tlv_ipextup->mtu[1]);
    *((byte *)&mtu + 3) = ntoh(tlv_ipextup->mtu[2]);

    return ntoh(mtu);
}

byte c_eigrp_tlv_ipextup::get_hopcount()
{
    return ntoh(tlv_ipextup->hopcount);
}

word c_eigrp_tlv_ipextup::get_reliability()
{
    return ntoh(tlv_ipextup->reliability);
}

byte c_eigrp_tlv_ipextup::get_load()
{
    return ntoh(tlv_ipextup->load);
}

byte c_eigrp_tlv_ipextup::get_prefixlen()
{
    return ntoh(tlv_ipextup->prefixlen);
}

dword c_eigrp_tlv_ipextup::get_destination()
{
    dword destination = 0;

    if (get_prefixlen() > 0)
        *((byte *)&destination + 3) = ntoh(tlv_ipextup->destination[0]);

    if (get_prefixlen() > 8)
        *((byte *)&destination + 2) = ntoh(tlv_ipextup->destination[1]);

    if (get_prefixlen() > 16)
        *((byte *)&destination + 1) = ntoh(tlv_ipextup->destination[2]);

    if (get_prefixlen() > 24)
        *((byte *)&destination + 0) = ntoh(tlv_ipextup->destination[3]);

    return ntoh(destination);
}
