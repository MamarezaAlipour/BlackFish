#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "ether_support.h"
#include "support.h"

c_ether_header::c_ether_header(byte *ether_header)
{
    header = (s_ether_header *)ether_header;
}

c_ether_header::c_ether_header(s_ether_header *ether_header)
{
    header = ether_header;
}

byte *c_ether_header::get_raw()
{
    return (byte *)header;
}

byte *c_ether_header::get_dst()
{
    return header->dst;
}

void c_ether_header::set_dst(byte *dst)
{
    memcpy(header->dst, dst, ETHER_ADDR_LEN);
}

byte *c_ether_header::get_src()
{
    return header->src;
}

void c_ether_header::set_src(byte *src)
{
    memcpy(header->src, src, ETHER_ADDR_LEN);
}

word c_ether_header::get_type()
{
    return ntoh(header->type);
}

void c_ether_header::set_type(word type)
{
    header->type = hton(type);
}
