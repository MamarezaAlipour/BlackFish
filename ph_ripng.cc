#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string ripng_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_rip_header header(packet_info.packet);

    output_string.add((char *)"RIPng\t");
    output_string.add((char *)"CMD %u (",
                      header.get_cmd());

    switch (header.get_cmd())
    {
    case RIP_CMD_REQUEST:
        output_string.add((char *)"REQUEST");
        break;

    case RIP_CMD_RESPONSE:
        output_string.add((char *)"RESPONSE");
        break;

    default:
        output_string.add((char *)"UNKNOWN");
    }

    output_string.add((char *)")  VER %u\n",
                      header.get_ver());

    for (u_int i = 0; i < (packet_info.packet_len - RIPNG_HEADER_LEN) / RIPNG_ENTRY_LEN; i++)
    {
        switch (header.get_ver())
        {
        case 1:
        {
            c_ripng_route_entry route_entry(packet_info.packet + RIPNG_HEADER_LEN + i * RIPNG_ENTRY_LEN);

            if (route_entry.get_metric() != 0xFF)
            {
                output_string.add((char *)"\n[ROUTE]\t");

                string prefix_string[40];

                output_string.add((char *)"PREFIX %s/%u  TAG %u  HOP %u",
                                  conv_ip6_str(prefix_string, route_entry.get_prefix()),
                                  route_entry.get_prefix_len(),
                                  route_entry.get_tag(),
                                  route_entry.get_metric());
            }
            else
            {
                c_ripng_next_hop_entry next_hop_entry(packet_info.packet + RIPNG_HEADER_LEN + i * RIPNG_ENTRY_LEN);

                output_string.add((char *)"\n[NHOP]\t");

                string prefix_string[40];

                output_string.add((char *)"NHOP %s",
                                  conv_ip6_str(prefix_string, next_hop_entry.get_next_hop()));
            }

            break;
        }
        }

        output_string.add((char *)"\n");
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
