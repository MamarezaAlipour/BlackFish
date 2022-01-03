#include "ah_support.h"
#include "support.h"

c_ah_header::c_ah_header(byte *ah_header)
{
    header = (s_ah_header *)ah_header;
}

c_ah_header::c_ah_header(s_ah_header *ah_header)
{
    header = ah_header;
}

byte c_ah_header::get_proto()
{
    return ntoh(header->proto);
}

void c_ah_header::set_proto(byte proto)
{
    header->proto = hton(proto);
}

byte c_ah_header::get_hlen()
{
    return (ntoh(header->hlen) + 2) << 2;
}

void c_ah_header::set_hlen(byte hlen)
{
    header->hlen = hton(byte((hlen >> 2) - 2));
}

word c_ah_header::get_reserved()
{
    return ntoh(header->reserved);
}

void c_ah_header::set_reserved(word reserved)
{
    header->reserved = hton(reserved);
}

dword c_ah_header::get_spi()
{
    return ntoh(header->spi);
}

void c_ah_header::set_spi(dword spi)
{
    header->spi = hton(spi);
}

dword c_ah_header::get_seq()
{
    return ntoh(header->seq);
}

void c_ah_header::set_seq(dword seq)
{
    header->seq = hton(seq);
}
