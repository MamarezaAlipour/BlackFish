#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include <netz.h>

#include "ip_proto.h"
#include "ph_packet.h"
#include "support.h"

c_string ip6_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ip6_header header(packet_info.packet);

    output_string.add((char *)"IPv6\t");

    string addr_string[40];

    output_string.add((char *)"SRC %s\n", conv_ip6_str(addr_string,
                                                       header.get_src()));

    output_string.add((char *)"\t");

    output_string.add((char *)"DST %s\n", conv_ip6_str(addr_string,
                                                       header.get_dst()));

    output_string.add(
        (char *)"\tVER %u  TCLASS %u  FLABEL %u  PLEN %u  NEXT 0x%02X (",
        header.get_ver(),
        header.get_tclass(),
        header.get_flabel(),
        header.get_plen(),
        header.get_next());

    output_string += print_ip_proto(header.get_next());

    output_string.add((char *)")  HLIMIT %u\n",
                      header.get_hlimit());

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
