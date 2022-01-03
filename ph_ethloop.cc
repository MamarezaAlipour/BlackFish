#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string ethloop_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    output_string.add((char *)"ETHLOOP\t\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
