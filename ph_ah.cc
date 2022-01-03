#include <netz.h>

#include "support.h"
#include "ph_packet.h"
#include "ip_proto.h"

c_string ah_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ah_header header(packet_info.packet);

    output_string.add((char *)"AH\tPROTO %u (");
    output_string += print_ip_proto(header.get_proto());
    output_string.add((char *)")  HLEN %u  ALEN %u  HASH ",
                      header.get_hlen(),
                      packet_info.ah_authdata_len);

    switch (packet_info.ah_authdata_len)
    {
    case 12:
        output_string += "MD5";
        break;
    case 16:
        output_string += "SHA";
        break;
    default:
        output_string += "???";
    }

    output_string.add((char *)"  SPI %u  SEQ %u",
                      header.get_spi(),
                      header.get_seq());

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
