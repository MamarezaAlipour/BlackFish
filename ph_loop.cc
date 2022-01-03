#include <sys/types.h>
#include <sys/socket.h>

#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string loop_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_loop_header header(packet_info.packet);

    output_string.add((char *)"LOOP\t");

    output_string.add((char *)"AF 0x%08X (",
                      header.get_af());

    switch (header.get_af())
    {
    case LOOP_AF_INET:
        output_string.add((char *)"IP");
        break;

    case LOOP_AF_INET6:
        output_string.add((char *)"IPv6");
        break;

    default:
        output_string.add((char *)"UNKNOWN");
    }

    output_string.add((char *)")");

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
