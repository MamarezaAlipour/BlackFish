#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "ieee8023_support.h"
#include "support.h"

c_ieee8023_header::c_ieee8023_header(byte *ieee8023_header)
{
    header = (s_ieee8023_header *)ieee8023_header;
}

c_ieee8023_header::c_ieee8023_header(s_ieee8023_header *ieee8023_header)
{
    header = ieee8023_header;
}

byte *c_ieee8023_header::get_raw()
{
    return (byte *)header;
}

byte *c_ieee8023_header::get_dst()
{
    return header->dst;
}

void c_ieee8023_header::set_dst(byte *dst)
{
    memcpy(header->dst, dst, IEEE8023_ADDR_LEN);
}

byte *c_ieee8023_header::get_src()
{
    return header->src;
}

void c_ieee8023_header::set_src(byte *src)
{
    memcpy(header->src, src, IEEE8023_ADDR_LEN);
}

word c_ieee8023_header::get_dlen()
{
    return ntoh(header->dlen);
}

void c_ieee8023_header::set_dlen(word dlen)
{
    header->dlen = hton(dlen);
}
