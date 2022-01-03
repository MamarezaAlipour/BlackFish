#include <netz.h>

#include "ether_type.h"
#include "support.h"
#include "ph_packet.h"

c_string snap_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_snap_header header(packet_info.packet);

    output_string.add((char *)"SNAP\t");

    output_string.add((char *)"OUI ");

    output_string.add_hex((char *)"0x%02X",
                          header.get_oui(0));

    output_string.add_hex((char *)"%02X",
                          header.get_oui(1));

    output_string.add_hex((char *)"%02X (",
                          header.get_oui(2));

    switch (header.get_oui())
    {
    case OUI_CISCO:
        output_string.add((char *)"Cisco");
        break;

    default:
        output_string.add((char *)"Unknown");
    }

    output_string.add_hex((char *)")  TYPE 0x%02X%02X (",
                          header.get_type());

    output_string += print_ether_type(header.get_type());

    output_string.add((char *)")\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
