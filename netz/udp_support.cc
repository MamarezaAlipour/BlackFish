#include "udp_support.h"
#include "support.h"

c_udp_header::c_udp_header(byte *udp_header)
{
    header = (s_udp_header *)udp_header;
}

c_udp_header::c_udp_header(s_udp_header *udp_header)
{
    header = udp_header;
}

word c_udp_header::get_sport()
{
    return ntoh(header->sport);
}

void c_udp_header::set_sport(word sport)
{
    header->sport = hton(sport);
}

word c_udp_header::get_dport()
{
    return ntoh(header->dport);
}

void c_udp_header::set_dport(word dport)
{
    header->dport = hton(dport);
}

word c_udp_header::get_len()
{
    return ntoh(header->len);
}

void c_udp_header::set_len(word len)
{
    header->len = hton(len);
}

word c_udp_header::get_cksum()
{
    return header->cksum;
}

void c_udp_header::set_cksum(word cksum)
{
    header->cksum = cksum;
}
