#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "ipx_support.h"

c_ipx_header::c_ipx_header(byte *ipx_header)
{
    header = (s_ipx_header *)ipx_header;
}

c_ipx_header::c_ipx_header(s_ipx_header *ipx_header)
{
    header = ipx_header;
}

word c_ipx_header::get_cksum()
{
    return ntoh(header->cksum);
}

void c_ipx_header::set_cksum(word cksum)
{
    header->cksum = cksum;
}

word c_ipx_header::get_len()
{
    return ntoh(header->len);
}

void c_ipx_header::set_len(word len)
{
    header->len = hton(len);
}

byte c_ipx_header::get_tcontrol()
{
    return ntoh(header->tcontrol);
}

void c_ipx_header::set_tcontrol(byte tcontrol)
{
    header->tcontrol = hton(tcontrol);
}

byte c_ipx_header::get_ptype()
{
    return ntoh(header->ptype);
}

void c_ipx_header::set_ptype(byte ptype)
{
    header->ptype = hton(ptype);
}

dword c_ipx_header::get_dnet()
{
    return ntoh(header->dnet);
}

void c_ipx_header::set_dnet(dword dnet)
{
    header->ptype = hton(dnet);
}

byte *c_ipx_header::get_dnode()
{
    return header->dnode;
}

void c_ipx_header::set_dnode(byte *dnode)
{
    memcpy(header->dnode, dnode, sizeof(header->dnode));
}

word c_ipx_header::get_dsock()
{
    return ntoh(header->dsock);
}

void c_ipx_header::set_dsock(word dsock)
{
    header->dsock = hton(dsock);
}

dword c_ipx_header::get_snet()
{
    return ntoh(header->snet);
}

void c_ipx_header::set_snet(dword snet)
{
    header->snet = hton(snet);
}

byte *c_ipx_header::get_snode()
{
    return header->snode;
}

void c_ipx_header::set_snode(byte *snode)
{
    memcpy(header->dnode, snode, sizeof(header->snode));
}

word c_ipx_header::get_ssock()
{
    return ntoh(header->ssock);
}

void c_ipx_header::set_ssock(word ssock)
{
    header->ssock = hton(ssock);
}
