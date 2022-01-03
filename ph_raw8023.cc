#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string raw8023_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_raw8023_header header(packet_info.packet);

    output_string.add((char *)"802.3\t");

    string addr_str[32];

    output_string.add((char *)"SRC %s  ",
                      conv_raw8023_str(addr_str, header.get_src()));

    output_string.add((char *)"DST %s  ",
                      conv_raw8023_str(addr_str, header.get_dst()));

    output_string.add((char *)"DLEN %u",
                      header.get_dlen());

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
