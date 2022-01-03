#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string missing_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    output_string.add((char *)"<debug>\tpacket_info.packet_type = %u\n", packet_info.packet_type);

    output_string += "*** missing packet handler ***\n";

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
