#include <netz.h>

#include "ether_type.h"
#include "support.h"
#include "ph_packet.h"

c_string ether_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ether_header header(packet_info.packet);

    output_string.add((char *)"ETHER\t");

    string addr_str[32];

    output_string.add((char *)"SRC %s  ",
                      conv_ether_str(addr_str, header.get_src()));

    output_string.add((char *)"DST %s  ",
                      conv_ether_str(addr_str, header.get_dst()));

    output_string.add_hex((char *)"TYPE 0x%02X%02X (",
                          header.get_type());

    output_string += print_ether_type(header.get_type());

    output_string.add((char *)")\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
