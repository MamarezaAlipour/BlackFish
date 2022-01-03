#include "igmp_support.h"
#include "support.h"

c_igmp_header::c_igmp_header(byte *igmp_header)
{
    header = (s_igmp_header *)igmp_header;
}

s_igmp_header *c_igmp_header::get_header()
{
    return header;
}

byte c_igmp_header::get_type()
{
    return ntoh(header->type);
}

void c_igmp_header::set_type(byte type)
{
    header->type = hton(type);
}

byte c_igmp_header::get_code()
{
    return ntoh(header->code);
}

void c_igmp_header::set_code(byte code)
{
    header->code = hton(code);
}

word c_igmp_header::get_cksum()
{
    return ntoh(header->cksum);
}

void c_igmp_header::set_cksum(word cksum)
{
    header->cksum = hton(cksum);
}

dword c_igmp_header::get_group()
{
    return header->group;
}

void c_igmp_header::set_group(dword group)
{
    header->group = group;
}
