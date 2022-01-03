#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "udp_advsupp.h"
#include "ip_support.h"
#include "ip6_support.h"
#include "cksum.h"

c_udp_packet::c_udp_packet(word sport, word dport)
{
    c_udp_header header(packet);

    header.set_sport(sport);
    header.set_dport(dport);
    header.set_len();
    header.set_cksum(0);

    header_len = UDP_HEADER_LEN;
    packet_len = header_len;
}

void c_udp_packet::add_data(byte *data, u_int data_len)
{
    memcpy(packet + header_len, data, data_len);

    packet_len = header_len + data_len;
}

void c_udp_packet::verify()
{
    c_udp_header header(packet);

    header.set_len(packet_len);

    header.set_cksum();
}

void c_udp_packet::verify(c_pseudo_header pseudo_header)
{
    c_udp_header header(packet);

    header.set_len(packet_len);

    header.set_cksum();
    header.set_cksum(cksum(packet, packet_len, pseudo_header));
}
