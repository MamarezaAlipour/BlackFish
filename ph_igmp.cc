#include <netz.h>

#include "ph_packet.h"
#include "support.h"

c_string print_igmp_info(u_int);

c_string igmp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_igmp_header header(packet_info.packet);

    output_string.add((char *)"IGMP\t");
    output_string.add((char *)"TYPE %u  CODE %u ",
                      header.get_type(),
                      header.get_code());

    output_string += print_igmp_info(header.get_type());

    string igmp_group_string[16];

    conv_ip_str(igmp_group_string, header.get_group());

    output_string.add((char *)"  GROUP %s  CKSUM %u ",
                      igmp_group_string,
                      header.get_cksum());

    if (!cksum((byte *)header.get_header(), sizeof(s_igmp_header)))
    {
        output_string.add((char *)"(OK)");
    }
    else
    {
        output_string.add((char *)"(BAD)");
    }

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_igmp_info(u_int type)
{
    switch (type)
    {
    case IGMP_HOST_MEMBERSHIP_QUERY:
        return c_string((char *)"membership querry");

    case IGMP_V1_HOST_MEMBERSHIP_REPORT:
        return c_string((char *)"v1 membership report");

    case IGMP_DVMRP:
        return c_string((char *)"DVMRP routing message");

    case IGMP_PIM:
        return c_string((char *)"PIM routing message");

    case IGMP_V2_HOST_MEMBERSHIP_REPORT:
        return c_string((char *)"v2 membersip report");

    case IGMP_HOST_LEAVE_MESSAGE:
        return c_string((char *)"leave-group message");

    case IGMP_MTRACE_REPLY:
        return c_string((char *)"traceroute reply");

    case IGMP_MTRACE_QUERY:
        return c_string((char *)"traceroute query");

    default:
        return c_string((char *)"unknown");
    }
}
