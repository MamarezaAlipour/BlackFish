#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string unknown_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    output_string.add((char *)"UNKNOWN\tPLEN %u\n",
                      packet_info.packet_len);

    //    output_string += print_hex_data(packet_info.packet,
    //        packet_info.packet_len, true, "\t");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
