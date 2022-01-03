#include <netz.h>

#include "ether_type.h"
#include "hr_type.h"
#include "ph_packet.h"
#include "support.h"

c_string print_arp_operation(word);

c_string arp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_arp_header header(packet_info.packet);

    output_string.add((char *)"ARP  \t");

    output_string.add_hex((char *)"HRTYPE 0x%02X%02X (",
                          header.get_hrtype());

    output_string += print_arp_hrtype(header.get_hrtype());

    output_string.add((char *)")  ");

    output_string.add_hex((char *)"PRTYPE 0x%02X%02X (",
                          header.get_prtype());

    output_string += print_ether_type(header.get_prtype());

    output_string.add((char *)")  ");

    output_string.add((char *)"\n\t");

    output_string.add((char *)"HRLEN %u  ",
                      header.get_hrlen());

    output_string.add((char *)"PRLEN %u  ",
                      header.get_prlen());

    output_string.add_hex((char *)"OPER 0x%02X%02X (",
                          header.get_operation());

    output_string += print_arp_operation(header.get_operation());

    output_string.add((char *)")");

    string addr_string[64];

    output_string.add((char *)"\n\t");

    output_string.add((char *)"SHA ");

    switch (header.get_hrtype())
    {
    case ARP_HRTYPE_ETHER:
    case ARP_HRTYPE_IEEE802:

        string addr_str[32];

        output_string.add((char *)"%s  ",
                          conv_ether_str(addr_str, header.get_sha()));

        break;

    default:
        output_string.add((char *)"<not supported>  ");
    }

    output_string.add((char *)"SPA ");

    switch (header.get_prtype())
    {
    case ARP_PRTYPE_IP:
        output_string.add((char *)"%s  ",
                          conv_ip_str(addr_string, header.get_spa()));
        break;

    case ARP_PRTYPE_IP6:
        output_string.add((char *)"%s  ", conv_ip6_str(addr_string,
                                                       header.get_spa()));
        break;

    default:
        output_string.add((char *)"<not supported>");
    }

    output_string.add((char *)"\n\t");

    output_string.add((char *)"THA ");

    switch (header.get_hrtype())
    {
    case ARP_HRTYPE_ETHER:
    case ARP_HRTYPE_IEEE802:

        string addr_str[32];

        output_string.add((char *)"%s  ",
                          conv_ether_str(addr_str, header.get_tha()));

        break;

    default:
        output_string.add((char *)"<not supported>  ");
    }

    output_string.add((char *)"TPA ");

    switch (header.get_prtype())
    {
    case ARP_PRTYPE_IP:
        output_string.add((char *)"%s  ",
                          conv_ip_str(addr_string, header.get_tpa()));
        break;

    case ARP_PRTYPE_IP6:
        output_string.add((char *)"%s  ", conv_ip6_str(addr_string,
                                                       header.get_tpa()));
        break;

    default:
        output_string.add((char *)"<not supported>");
    }

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_arp_operation(word operation)
{
    switch (operation)
    {
    case ARP_OP_REQUEST:
        return c_string((char *)"Request");

    case ARP_OP_REPLY:
        return c_string((char *)"Reply");

    case ARP_OP_REVREQUEST:
        return c_string((char *)"Reverse Request");

    case ARP_OP_REVREPLY:
        return c_string((char *)"Reverse Reply");

    case ARP_OP_INVREQUEST:
        return c_string((char *)"Inverse Request");

    case ARP_OP_INVREPLY:
        return c_string((char *)"Inverse Reply");

    default:
        return c_string((char *)"Unknown");
    }
}
