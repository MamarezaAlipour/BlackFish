#include <netz.h>

#include "hr_type.h"
#include "support.h"
#include "ph_packet.h"

c_string dhcp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_dhcp_header header(packet_info.packet);

    output_string.add((char *)"DHCP\tOP %u (",
                      header.get_op());

    switch (header.get_op())
    {
    case DHCP_OP_BOOTREQUEST:
        output_string.add((char *)"Boot Request");
        break;

    case DHCP_OP_BOOTREPLY:
        output_string.add((char *)"Boot Reply");
        break;

    default:
        output_string.add((char *)"Unknown");
        break;
    }

    output_string.add((char *)")  ");

    output_string.add_hex((char *)"HRTYPE 0x%02X%02X (",
                          (word)header.get_hrtype());

    output_string += print_arp_hrtype(header.get_hrtype());

    output_string.add((char *)")  ");

    output_string.add((char *)"HRLEN %u  HOPS %u\n",
                      header.get_hrlen(),
                      header.get_hops());

    output_string.add((char *)"\tXID %u  SECS %u",
                      header.get_xid(),
                      header.get_secs());

    output_string.add_hex((char *)"\tFLAGS 0x%02X%02X |",
                          header.get_flags());

    if (header.get_flag_b())
    {
        output_string.add((char *)"B|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    output_string.add((char *)"\n");

    string ciaddr_string[16];
    string yiaddr_string[16];
    string siaddr_string[16];
    string giaddr_string[16];

    conv_ip_str(ciaddr_string, header.get_ciaddr());
    conv_ip_str(yiaddr_string, header.get_yiaddr());
    conv_ip_str(siaddr_string, header.get_siaddr());
    conv_ip_str(giaddr_string, header.get_giaddr());

    output_string.add((char *)"\tCLIENT IP ADDR %s  YOUR IP ADDR %s\n"
                              "\tSERVER IP ADDR %s  GATEWAY IP ADDR %s\n",
                      ciaddr_string,
                      yiaddr_string,
                      siaddr_string,
                      giaddr_string);

    switch (header.get_hrtype())
    {
    case ARP_HRTYPE_ETHER:
        string mac_addr_str[32];
        output_string.add((char *)"\tCLIENT MAC ADDR %s",
                          conv_ether_str(mac_addr_str, header.get_chaddr()));
        break;

    default:
        output_string.add((char *)"\t*** CLIENT HARDWARE ADDRESS NOT SUPPORTED ***");
    }

    output_string.add((char *)"\n");

    if (header.get_sname()[0])
    {
        output_string.add((char *)"\tSNAME %s\n",
                          header.get_sname());
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
