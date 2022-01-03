#include <sys/types.h>
#include <sys/socket.h>

#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string enc_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_enc_header header(packet_info.packet);

    output_string.add((char *)"ENC\t");

    output_string.add((char *)"AF 0x%08X (",
                      header.get_af());

    switch (header.get_af())
    {
    case ENC_AF_INET:
        output_string.add((char *)"INET");
        break;

    case ENC_AF_INET6:
        output_string.add((char *)"INET6");
        break;

    default:
        output_string.add((char *)"UNKNOWN");
    }

    output_string.add((char *)")  SPI 0x%08X  FLAGS 0x%08X\n",
                      header.get_spi(), header.get_flags());

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
