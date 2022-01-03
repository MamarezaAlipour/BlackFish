#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string udp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_udp_header header(packet_info.packet);

    output_string.add((char *)"UDP\t");
    output_string.add((char *)"SPORT %u  DPORT %u  CKSUM %u ",
                      header.get_sport(),
                      header.get_dport(),
                      header.get_cksum());

    c_pseudo_header pseudo_header;

    if (packet_info.previous_packet_type == PACKET_TYPE_IP)
    {
        c_ipp_header ipp_header(c_ip_header(packet_info.previous_packet));
        pseudo_header = ipp_header.get_pseudo_header();
    }

    if (packet_info.previous_packet_type == PACKET_TYPE_IP6)
    {
        c_ip6p_header ip6p_header(c_ip6_header(packet_info.previous_packet));
        pseudo_header = ip6p_header.get_pseudo_header();
    }

    if (header.get_cksum() == 0)
    {
        output_string.add((char *)"(NONE)");
    }
    else
    {
        if (!cksum(packet_info.packet, packet_info.packet_len, pseudo_header))
        {
            output_string.add((char *)"(OK)");
        }
        else
        {
            output_string.add((char *)"(BAD)");
        }
    }

    output_string.add((char *)"\n");

    output_string.add((char *)"\tHLEN %u  PLEN %u  DLEN %u\n",
                      UDP_HEADER_LEN,
                      header.get_len(),
                      header.get_len() - UDP_HEADER_LEN);

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
