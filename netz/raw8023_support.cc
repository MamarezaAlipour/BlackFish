#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "raw8023_support.h"
#include "support.h"

c_raw8023_header::c_raw8023_header(byte *raw8023_header)
{
    header = (s_raw8023_header *)raw8023_header;
}

c_raw8023_header::c_raw8023_header(s_raw8023_header *raw8023_header)
{
    header = raw8023_header;
}

byte *c_raw8023_header::get_raw()
{
    return (byte *)header;
}

byte *c_raw8023_header::get_dst()
{
    return header->dst;
}

void c_raw8023_header::set_dst(byte *dst)
{
    memcpy(header->dst, dst, RAW8023_ADDR_LEN);
}

byte *c_raw8023_header::get_src()
{
    return header->src;
}

void c_raw8023_header::set_src(byte *src)
{
    memcpy(header->src, src, RAW8023_ADDR_LEN);
}

word c_raw8023_header::get_dlen()
{
    return ntoh(header->dlen);
}

void c_raw8023_header::set_dlen(word dlen)
{
    header->dlen = hton(dlen);
}
