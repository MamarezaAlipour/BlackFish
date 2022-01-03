#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "arp_support.h"
#include "support.h"

c_arp_header::c_arp_header(byte *arp_header)
{
    header = (s_arp_header *)arp_header;

    sha = arp_header + ARP_HEADER_LEN;
    spa = sha + get_hrlen();
    tha = spa + get_prlen();
    tpa = tha + get_hrlen();
}

c_arp_header::c_arp_header(s_arp_header *arp_header)
{
    header = arp_header;

    sha = ((byte *)arp_header) + ARP_HEADER_LEN;
    spa = sha + get_hrlen();
    tha = spa + get_prlen();
    tpa = tha + get_hrlen();
}

word c_arp_header::get_hrtype()
{
    return ntoh(header->hrtype);
}

void c_arp_header::set_hrtype(word hrtype)
{
    header->hrtype = hton(hrtype);
}

word c_arp_header::get_prtype()
{
    return ntoh(header->prtype);
}

void c_arp_header::set_prtype(word prtype)
{
    header->prtype = hton(prtype);
}

byte c_arp_header::get_hrlen()
{
    return ntoh(header->hrlen);
}

void c_arp_header::set_hrlen(byte hrlen)
{
    header->hrlen = hton(hrlen);

    sha = ((byte *)header) + ARP_HEADER_LEN;
    spa = sha + get_hrlen();
    tha = spa + get_prlen();
    tpa = tha + get_hrlen();
}

byte c_arp_header::get_prlen()
{
    return ntoh(header->prlen);
}

void c_arp_header::set_prlen(byte prlen)
{
    header->prlen = hton(prlen);

    sha = ((byte *)header) + ARP_HEADER_LEN;
    spa = sha + get_hrlen();
    tha = spa + get_prlen();
    tpa = tha + get_hrlen();
}

word c_arp_header::get_operation()
{
    return ntoh(header->operation);
}

void c_arp_header::set_operation(word operation)
{
    header->operation = hton(operation);
}

byte *c_arp_header::get_sha()
{
    return sha;
}

void c_arp_header::set_sha(byte *sha, u_int len)
{
    if (len == 0)
    {
        len = get_hrlen();
    }

    memcpy(c_arp_header::sha, sha, len);
}

byte *c_arp_header::get_spa()
{
    return spa;
}

void c_arp_header::set_spa(byte *spa, u_int len)
{
    if (len == 0)
    {
        len = get_hrlen();
    }

    memcpy(c_arp_header::spa, spa, len);
}

byte *c_arp_header::get_tha()
{
    return tha;
}

void c_arp_header::set_tha(byte *tha, u_int len)
{
    if (len == 0)
    {
        len = get_hrlen();
    }

    memcpy(c_arp_header::tha, tha, len);
}

byte *c_arp_header::get_tpa()
{
    return tpa;
}

void c_arp_header::set_tpa(byte *tpa, u_int len)
{
    if (len == 0)
    {
        len = get_hrlen();
    }

    memcpy(c_arp_header::tpa, tpa, len);
}
