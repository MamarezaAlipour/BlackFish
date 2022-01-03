#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "ether_vlan_support.h"
#include "support.h"

c_ether_vlan_header::c_ether_vlan_header(byte *buffer)
{
    header = (s_ether_vlan_header *)buffer;
}

byte *c_ether_vlan_header::get_raw()
{
    return (byte *)header;
}

byte *c_ether_vlan_header::get_dst()
{
    return header->dst;
}

void c_ether_vlan_header::set_dst(byte *dst)
{
    memcpy(header->dst, dst, ETHER_VLAN_ADDR_LEN);
}

byte *c_ether_vlan_header::get_src()
{
    return header->src;
}

void c_ether_vlan_header::set_src(byte *src)
{
    memcpy(header->src, src, ETHER_VLAN_ADDR_LEN);
}

word c_ether_vlan_header::get_tpid()
{
    return ntoh(header->tpid);
}

void c_ether_vlan_header::set_tpid(word tpid)
{
    header->tpid = hton(tpid);
}

word c_ether_vlan_header::get_tci()
{
    return ntoh(header->tci);
}

void c_ether_vlan_header::set_tci(word tci)
{
    header->tci = hton(tci);
}

byte c_ether_vlan_header::get_priority()
{
    return bits(ntoh(header->tci), ETHER_VLAN_TCI_PRIORITY_MASK);
}

void c_ether_vlan_header::set_priority(byte priority)
{
    header->tci = hton(bits(ntoh(header->tci), ETHER_VLAN_TCI_PRIORITY_MASK,
                            priority));
}

word c_ether_vlan_header::get_vid()
{
    return bits(ntoh(header->tci), ETHER_VLAN_TCI_VID_MASK);
}

void c_ether_vlan_header::set_vid(word vid)
{
    header->tci = hton(bits(ntoh(header->tci), ETHER_VLAN_TCI_VID_MASK, vid));
}

word c_ether_vlan_header::get_type()
{
    return ntoh(header->type);
}

void c_ether_vlan_header::set_type(word type)
{
    header->type = hton(type);
}
