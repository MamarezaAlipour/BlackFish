#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>

#include <netz.h>

#include "support.h"
#include "ph_packet.h"

extern bool debug_mode;
extern bool file_output;
extern bool screen_output;
extern int output_file;
extern bool hide_ether_loopback;
extern bool hide_cisco_cdp;
extern bool hide_eigrp_hello;
extern bool hide_ospf_hello;

void packet_handler(byte *linklayer, struct pcap_pkthdr *pkthdr, byte *packet)
{
    bool hide_packet = false;

    c_string output_string;

    c_packet_info captured_packet_info;

    captured_packet_info.next_packet = packet;
    captured_packet_info.next_packet_len = pkthdr->caplen;

    switch (*((int *)linklayer))
    {
    case DLT_EN10MB:
        captured_packet_info.next_packet_type = get_ether_type(packet);
        break;

#ifdef OS_OPENBSD
    case DLT_LOOP:
        captured_packet_info.next_packet_type = PACKET_TYPE_LOOP;
        break;

    case DLT_ENC:
        captured_packet_info.next_packet_type = PACKET_TYPE_ENC;
        break;
#endif

    case DLT_NULL:
        captured_packet_info.next_packet_type = PACKET_TYPE_GIF;
        break;

    default:
        captured_packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    c_packet_handler packet_handler(captured_packet_info);

    u_int i = 0;

    c_packet_info packet_info;

    output_string.add(print_line());

    do
    {
        packet_info = packet_handler.get_packet_info(i++);

        switch (packet_info.packet_type)
        {
        case PACKET_TYPE_ARP:
            output_string += arp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_ETHER:
        {
            output_string += ether_packet_handler(packet_info);

            c_ether_header header(packet_info.packet);

            if (hide_ether_loopback &&
                (header.get_type() == ETHER_TYPE_LOOPBACK))
            {
                hide_packet = true;
            }

            break;
        }

        case PACKET_TYPE_ETHER_VLAN:
            output_string += ether_vlan_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IEEE8023:
            output_string += ieee8023_packet_handler(packet_info);
            break;

        case PACKET_TYPE_RAW8023:
            output_string += ieee8023_packet_handler(packet_info);
            break;

        case PACKET_TYPE_ICMP:
            output_string += icmp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_ICMP6:
            output_string += icmp6_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IGMP:
            output_string += igmp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IP:
            output_string += ip_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IP6:
            output_string += ip6_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IPX:
            output_string += ipx_packet_handler(packet_info);
            break;

        case PACKET_TYPE_LLC_I:
            output_string += llc_i_packet_handler(packet_info);
            break;

        case PACKET_TYPE_LLC_S:
            output_string += llc_s_packet_handler(packet_info);
            break;

        case PACKET_TYPE_LLC_U:
            output_string += llc_u_packet_handler(packet_info);
            break;

        case PACKET_TYPE_GIF:
            output_string += gif_packet_handler(packet_info);
            break;

        case PACKET_TYPE_LOOP:
            output_string += loop_packet_handler(packet_info);
            break;

        case PACKET_TYPE_ENC:
            output_string += enc_packet_handler(packet_info);
            break;

        case PACKET_TYPE_SNAP:
        {
            output_string += snap_packet_handler(packet_info);

            c_snap_header header(packet_info.packet);

            if (hide_cisco_cdp && (header.get_oui() == OUI_CISCO) &&
                (header.get_type() == SNAP_TYPE_CDP))
            {
                hide_packet = true;
            }

            break;
        }

        case PACKET_TYPE_TCP:
            output_string += tcp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_UDP:
            output_string += udp_packet_handler(packet_info);
            break;

            /* case PACKET_TYPE_SPX:
                output_string += spx_packet_handler(packet_info);
                break; */

        case PACKET_TYPE_RIP:
            output_string += rip_packet_handler(packet_info);
            break;

        case PACKET_TYPE_RIPNG:
            output_string += ripng_packet_handler(packet_info);
            break;

        case PACKET_TYPE_CDP:
            output_string += cdp_packet_handler(packet_info);
            break;

            //            case PACKET_TYPE_ESP:
            //                output_string += esp_packet_handler(packet_info);
            //                break;

        case PACKET_TYPE_AH:
            output_string += ah_packet_handler(packet_info);
            break;

            /*            case PACKET_TYPE_ISAKMP:
                            output_string += isakmp_packet_handler(packet_info);
                            break;
            */
        case PACKET_TYPE_GRE:
            output_string += gre_packet_handler(packet_info);
            break;

        case PACKET_TYPE_ETHLOOP:
            output_string += ethloop_packet_handler(packet_info);
            break;

        case PACKET_TYPE_IGRP:
            output_string += igrp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_EIGRP:
        {
            output_string += eigrp_packet_handler(packet_info);

            c_eigrp_header header(packet_info.packet);

            if (hide_eigrp_hello && (header.get_opcode() == EIGRP_OPCODE_HELLO))
            {
                hide_packet = true;
            }

            break;
        }

        case PACKET_TYPE_OSPF:
        {
            output_string += ospf_packet_handler(packet_info);

            c_ospf_header header(packet_info.packet);

            if (hide_ospf_hello && (header.get_type() == OSPF_TYPE_HELLO_PACKET))
            {
                hide_packet = true;
            }

            break;
        }

        case PACKET_TYPE_DHCP:
            output_string += dhcp_packet_handler(packet_info);
            break;

        case PACKET_TYPE_UNKNOWN:
            output_string += unknown_packet_handler(packet_info);
            break;

        default:
            output_string += missing_packet_handler(packet_info);
        }
    } while (packet_info.next_packet_type != PACKET_TYPE_NONE);

    if (screen_output && !hide_packet)
    {
        write(1, output_string.get_data(), output_string.get_len());
    }

    if (file_output && !hide_packet)
    {
        write(output_file, output_string.get_data(), output_string.get_len());
    }
}

c_string print_hex_data(byte *data, u_int data_len, bool newline, c_string head)
{
    c_string output_string;

    if (data_len)
    {

        c_string ascii_string;

        if (newline)
        {
            output_string.add((char *)"\n");
        }

        for (u_int i = 0; i < data_len; i++)
        {
            if ((i == 0) && newline)
            {
                output_string.add(head);
            }
            else if ((!(i & 15)) && newline)
            {
                output_string.add((char *)"    \t");
            }

            output_string.add((char *)"%02X ", *(data + i));

            if ((*(data + i) < 32) || (*(data + i) > 126))
            {
                ascii_string.add((char *)".");
            }
            else
            {
                ascii_string.add(char(*(data + i)));
            }

            if ((!((i + 1) & 15)) && (i + 1) < data_len)
            {
                output_string.add((char *)"   |");
                output_string.add(ascii_string);
                output_string.add((char *)"|");
                ascii_string.clear();

                output_string.add((char *)"\n");
            }
        }

        for (int i = 0; i < int((16 - data_len) & 15); i++)
        {
            output_string.add((char *)"   ");
        }

        output_string.add((char *)"   |");
        output_string.add(ascii_string);
        ascii_string.clear();

        for (int i = 0; i < int((16 - data_len) & 15); i++)
        {
            output_string.add((char *)" ");
        }

        output_string.add((char *)"|");

        if (newline)
        {
            output_string.add((char *)"\n");
        }
    }

    return output_string;
}

c_string debug(c_packet_info packet_info)
{
    c_string output_string;

    if (debug_mode)
    {
        output_string.add((char *)"\n");

        output_string.add((char *)"<debug>\tpacket_info.packet_len = %u\n",
                          packet_info.packet_len);

        output_string.add((char *)"\tpacket_info.next_packet_len = %u\n",
                          packet_info.next_packet_len);

        output_string += print_hex_data(packet_info.packet,
                                        packet_info.packet_len, true, (char *)"\t");
    }

    return output_string;
}
