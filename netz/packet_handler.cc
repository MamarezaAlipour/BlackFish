#include "support.h"
#include "ether_support.h"
#include "ether_vlan_support.h"
#include "ieee8023_support.h"
#include "raw8023_support.h"
#include "gif_support.h"
#include "loop_support.h"
#include "enc_support.h"
#include "llc_i_support.h"
#include "llc_s_support.h"
#include "llc_u_support.h"
#include "snap_support.h"
#include "ip_support.h"
#include "arp_support.h"
#include "icmp_support.h"
#include "icmp6_support.h"
#include "ip6_support.h"
#include "udp_support.h"
#include "tcp_support.h"
#include "ipx_support.h"
#include "spx_support.h"
#include "rip_support.h"
#include "ripng_support.h"
#include "igmp_support.h"
#include "cdp_support.h"
#include "esp_support.h"
#include "ah_support.h"
//#include "isakmp_support.h"
#include "gre_support.h"
#include "ethloop_support.h"
#include "igrp_support.h"
#include "eigrp_support.h"
#include "ospf_support.h"
#include "dhcp_support.h"
#include "cksum.h"
#include "packet_handler.h"

void write_packet_type(e_packet_type packet_type)
{
    switch (packet_type)
    {
    case PACKET_TYPE_ARP:
        message((char *)"arp ");
        break;
    case PACKET_TYPE_ETHER:
        message((char *)"ether ");
        break;
    case PACKET_TYPE_ETHER_VLAN:
        message((char *)"ether_vlan ");
        break;
    case PACKET_TYPE_IEEE8023:
        message((char *)"ieee8023 ");
        break;
    case PACKET_TYPE_RAW8023:
        message((char *)"raw8023 ");
        break;
    case PACKET_TYPE_ICMP:
        message((char *)"icmp ");
        break;
    case PACKET_TYPE_ICMP6:
        message((char *)"icmp6 ");
        break;
    case PACKET_TYPE_IGMP:
        message((char *)"igmp ");
        break;
    case PACKET_TYPE_IP:
        message((char *)"ip ");
        break;
    case PACKET_TYPE_IP6:
        message((char *)"ip6 ");
        break;
    case PACKET_TYPE_IPX:
        message((char *)"ipx ");
        break;
    case PACKET_TYPE_LLC_I:
        message((char *)"llc_i ");
        break;
    case PACKET_TYPE_LLC_S:
        message((char *)"llc_s ");
        break;
    case PACKET_TYPE_LLC_U:
        message((char *)"llc_u ");
        break;
    case PACKET_TYPE_GIF:
        message((char *)"gif ");
        break;
    case PACKET_TYPE_LOOP:
        message((char *)"loop ");
        break;
    case PACKET_TYPE_ENC:
        message((char *)"enc ");
        break;
    case PACKET_TYPE_SNAP:
        message((char *)"snap ");
        break;
    case PACKET_TYPE_TCP:
        message((char *)"tcp ");
        break;
    case PACKET_TYPE_UDP:
        message((char *)"udp ");
        break;
    case PACKET_TYPE_SPX:
        message((char *)"spx ");
        break;
    case PACKET_TYPE_RIP:
        message((char *)"rip ");
        break;
    case PACKET_TYPE_RIPNG:
        message((char *)"ripng ");
        break;
    case PACKET_TYPE_CDP:
        message((char *)"cdp ");
        break;
    case PACKET_TYPE_ESP:
        message((char *)"esp ");
        break;
    case PACKET_TYPE_AH:
        message((char *)"ah ");
        break;
    case PACKET_TYPE_ISAKMP:
        message((char *)"isakmp ");
        break;
    case PACKET_TYPE_GRE:
        message((char *)"gre ");
        break;
    case PACKET_TYPE_IGRP:
        message((char *)"igrp ");
        break;
    case PACKET_TYPE_EIGRP:
        message((char *)"eigrp ");
        break;
    case PACKET_TYPE_OSPF:
        message((char *)"ospf ");
        break;
    case PACKET_TYPE_BGP:
        message((char *)"bgp ");
        break;
    case PACKET_TYPE_ETHLOOP:
        message((char *)"ethloop ");
        break;
    case PACKET_TYPE_DHCP:
        message((char *)"dhcp ");
        break;
    case PACKET_TYPE_NONE:
        message((char *)"none ");
        break;
    case PACKET_TYPE_UNKNOWN:
        message((char *)"unknown ");
        break;
    }
}

c_packet_info::c_packet_info()
{
    previous_packet_type = PACKET_TYPE_UNKNOWN;
    previous_packet = 0;
    previous_packet_len = 0;

    packet_type = PACKET_TYPE_UNKNOWN;

    packet = 0;
    packet_len = 0;

    header = 0;
    header_len = 0;

    ip_options = 0;
    ip_options_len = 0;

    tcp_options = 0;
    tcp_options_len = 0;

    data = 0;
    data_len = 0;

    rip_authentry = 0;
    rip_authentry_len = 0;
    rip_entries = 0;
    rip_entries_len = 0;
    rip_md5entry = 0;
    rip_md5entry_len = 0;

    ah_authdata = 0;
    ah_authdata_len = 0;

    next_packet_type = PACKET_TYPE_NONE;
    next_packet = 0;
    next_packet_len = 0;
}

e_packet_type get_llc_type(byte *llc_packet)
{
    c_llc_i_header llc_i_header(llc_packet);
    c_llc_s_header llc_s_header(llc_packet);
    c_llc_u_header llc_u_header(llc_packet);

    if (bits(llc_i_header.get_ctrl(), LLC_I_ID_MASK) == LLC_I_ID)
    {
        return PACKET_TYPE_LLC_I;
    }

    if (bits(llc_s_header.get_ctrl(), LLC_S_ID_MASK) == LLC_S_ID)
    {
        return PACKET_TYPE_LLC_S;
    }

    if (bits(llc_u_header.get_ctrl(), LLC_U_ID_MASK) == LLC_U_ID)
    {
        return PACKET_TYPE_LLC_U;
    }

    return PACKET_TYPE_UNKNOWN;
}

e_packet_type get_ether_type(byte *ether_packet)
{
    if (ntoh(*(word *)(ether_packet + 12)) == ETHER_VLAN_TPID)
    {
        return PACKET_TYPE_ETHER_VLAN;
    }
    else
    {
        if (ntoh(*(word *)(ether_packet + 12)) >= ETHER_TYPE_MIN)
        {
            return PACKET_TYPE_ETHER;
        }
        else
        {
            if (ntoh(*(word *)(ether_packet + 14)) == NOVELL_RAW_802_3)
            {
                return PACKET_TYPE_RAW8023;
            }
            else
            {
                return PACKET_TYPE_IEEE8023;
            }
        }
    }
}

c_packet_handler::c_packet_handler(c_packet_info packet_info)
{
    ptable_counter = 0;

    while (packet_info.next_packet_type != PACKET_TYPE_NONE)
    {
        packet_info = packet_handler(packet_info);
        set_next_ptable_entry(packet_info);
    }

    set_next_ptable_entry(packet_info);
}

c_packet_info c_packet_handler::get_packet_info(u_int n)
{
    return ptable[n];
}

void c_packet_handler::set_next_ptable_entry(c_packet_info packet_info)
{
    ptable[ptable_counter++] = packet_info;
}

c_packet_info c_packet_handler::packet_handler(c_packet_info packet_info)
{
    packet_info.previous_packet_type = packet_info.packet_type;
    packet_info.previous_packet = packet_info.packet;
    packet_info.previous_packet_len = packet_info.packet_len;

    packet_info.packet_type = packet_info.next_packet_type;
    packet_info.packet = packet_info.next_packet;
    packet_info.packet_len = packet_info.next_packet_len;

    packet_info.header = packet_info.packet;
    packet_info.header_len = 0;

    packet_info.ip_options = 0;
    packet_info.ip_options_len = 0;

    packet_info.tcp_options = 0;
    packet_info.tcp_options_len = 0;

    packet_info.data = 0;
    packet_info.data_len = 0;

    packet_info.next_packet_type = PACKET_TYPE_NONE;
    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;

    switch (packet_info.packet_type)
    {
    case PACKET_TYPE_ARP:
        packet_info = arp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ETHER:
        packet_info = ether_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ETHER_VLAN:
        packet_info = ether_vlan_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IEEE8023:
        packet_info = ieee8023_packet_handler(packet_info);
        break;

    case PACKET_TYPE_RAW8023:
        packet_info = raw8023_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ICMP:
        packet_info = icmp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ICMP6:
        packet_info = icmp6_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IGMP:
        packet_info = igmp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IP:
        packet_info = ip_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IP6:
        packet_info = ip6_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IPX:
        packet_info = ipx_packet_handler(packet_info);
        break;

    case PACKET_TYPE_LLC_I:
        packet_info = llc_i_packet_handler(packet_info);
        break;

    case PACKET_TYPE_LLC_S:
        packet_info = llc_s_packet_handler(packet_info);
        break;

    case PACKET_TYPE_LLC_U:
        packet_info = llc_u_packet_handler(packet_info);
        break;

    case PACKET_TYPE_GIF:
        packet_info = gif_packet_handler(packet_info);
        break;

    case PACKET_TYPE_LOOP:
        packet_info = loop_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ENC:
        packet_info = enc_packet_handler(packet_info);
        break;

    case PACKET_TYPE_SNAP:
        packet_info = snap_packet_handler(packet_info);
        break;

    case PACKET_TYPE_TCP:
        packet_info = tcp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_UDP:
        packet_info = udp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_SPX:
        packet_info = spx_packet_handler(packet_info);
        break;

    case PACKET_TYPE_RIP:
        packet_info = rip_packet_handler(packet_info);
        break;

    case PACKET_TYPE_RIPNG:
        packet_info = ripng_packet_handler(packet_info);
        break;

    case PACKET_TYPE_CDP:
        packet_info = cdp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ESP:
        packet_info = esp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_AH:
        packet_info = ah_packet_handler(packet_info);
        break;
        /*
                case PACKET_TYPE_ISAKMP:
                    packet_info = isakmp_packet_handler(packet_info);
                    break;
        */
    case PACKET_TYPE_GRE:
        packet_info = gre_packet_handler(packet_info);
        break;

    case PACKET_TYPE_ETHLOOP:
        packet_info = ethloop_packet_handler(packet_info);
        break;

    case PACKET_TYPE_IGRP:
        packet_info = igrp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_EIGRP:
        packet_info = eigrp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_OSPF:
        packet_info = ospf_packet_handler(packet_info);
        break;

    case PACKET_TYPE_DHCP:
        packet_info = dhcp_packet_handler(packet_info);
        break;

    case PACKET_TYPE_UNKNOWN:
        packet_info = unknown_packet_handler(packet_info);
        break;

    default:
        break;
    }

    return packet_info;
}

c_packet_info c_packet_handler::arp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = ARP_HEADER_LEN;

    packet_info.next_packet_type = PACKET_TYPE_NONE;
    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;

    return packet_info;
}

c_packet_info c_packet_handler::ether_packet_handler(c_packet_info packet_info)
{
    c_ether_header header(packet_info.packet);

    packet_info.header_len = ETHER_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + ETHER_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - ETHER_HEADER_LEN;

    switch (header.get_type())
    {
    case ETHER_TYPE_IP:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case ETHER_TYPE_IP6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    case ETHER_TYPE_ARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_REVARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_IPX:
        packet_info.next_packet_type = PACKET_TYPE_IPX;
        break;

    case ETHER_TYPE_LOOPBACK:
        packet_info.next_packet_type = PACKET_TYPE_ETHLOOP;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::ether_vlan_packet_handler(
    c_packet_info packet_info)
{
    c_ether_vlan_header header(packet_info.packet);

    packet_info.header_len = ETHER_VLAN_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + ETHER_VLAN_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - ETHER_VLAN_HEADER_LEN;

    switch (header.get_type())
    {
    case ETHER_TYPE_IP:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case ETHER_TYPE_IP6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    case ETHER_TYPE_ARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_REVARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_IPX:
        packet_info.next_packet_type = PACKET_TYPE_IPX;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::ieee8023_packet_handler(
    c_packet_info packet_info)
{
    c_ieee8023_header header(packet_info.packet);

    packet_info.header_len = IEEE8023_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + IEEE8023_HEADER_LEN;
    packet_info.next_packet_len = header.get_dlen();
    packet_info.next_packet_type = get_llc_type(packet_info.next_packet);

    return packet_info;
}

c_packet_info c_packet_handler::raw8023_packet_handler(
    c_packet_info packet_info)
{
    c_raw8023_header header(packet_info.packet);

    packet_info.header_len = RAW8023_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + RAW8023_HEADER_LEN;
    packet_info.next_packet_len = header.get_dlen();
    packet_info.next_packet_type = PACKET_TYPE_IPX;

    return packet_info;
}

c_packet_info c_packet_handler::icmp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = ICMP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::icmp6_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = ICMP6_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::igmp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = IGMP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::ip_packet_handler(c_packet_info packet_info)
{
    c_ip_header header(packet_info.packet);

    packet_info.header_len = IP_HEADER_LEN;

    if (header.get_hlen() - IP_HEADER_LEN)
    {
        packet_info.ip_options = packet_info.packet + IP_HEADER_LEN;
        packet_info.ip_options_len = header.get_hlen() - IP_HEADER_LEN;
    }

    packet_info.next_packet = packet_info.packet + header.get_hlen();
    packet_info.next_packet_len = header.get_len() - header.get_hlen();

    switch (header.get_proto())
    {
    case IP_PROTO_ICMP:
        packet_info.next_packet_type = PACKET_TYPE_ICMP;
        break;

    case IP_PROTO_ICMPV6:
        packet_info.next_packet_type = PACKET_TYPE_ICMP6;
        break;

    case IP_PROTO_IGMP:
        packet_info.next_packet_type = PACKET_TYPE_IGMP;
        break;

    case IP_PROTO_TCP:
        packet_info.next_packet_type = PACKET_TYPE_TCP;
        break;

    case IP_PROTO_UDP:
        packet_info.next_packet_type = PACKET_TYPE_UDP;
        break;

    case IP_PROTO_IPV4:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case IP_PROTO_IPV6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    case IP_PROTO_ESP:
        packet_info.next_packet_type = PACKET_TYPE_ESP;
        break;

    case IP_PROTO_AH:
        packet_info.next_packet_type = PACKET_TYPE_AH;
        break;

    case IP_PROTO_GRE:
        packet_info.next_packet_type = PACKET_TYPE_GRE;
        break;

    case IP_PROTO_IGRP:
        packet_info.next_packet_type = PACKET_TYPE_IGRP;
        break;

    case IP_PROTO_EIGRP:
        packet_info.next_packet_type = PACKET_TYPE_EIGRP;
        break;

    case IP_PROTO_OSPF:
        packet_info.next_packet_type = PACKET_TYPE_OSPF;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::ip6_packet_handler(c_packet_info packet_info)
{
    c_ip6_header header(packet_info.packet);

    packet_info.header_len = IP6_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + IP6_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - IP6_HEADER_LEN;

    switch (header.get_next())
    {
    case IP_PROTO_ICMP:
        packet_info.next_packet_type = PACKET_TYPE_ICMP;
        break;

    case IP_PROTO_ICMPV6:
        packet_info.next_packet_type = PACKET_TYPE_ICMP6;
        break;

    case IP_PROTO_IGMP:
        packet_info.next_packet_type = PACKET_TYPE_IGMP;
        break;

    case IP_PROTO_TCP:
        packet_info.next_packet_type = PACKET_TYPE_TCP;
        break;

    case IP_PROTO_UDP:
        packet_info.next_packet_type = PACKET_TYPE_UDP;
        break;

    case IP_PROTO_IPV4:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case IP_PROTO_IPV6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::ipx_packet_handler(c_packet_info packet_info)
{
    c_ipx_header header(packet_info.packet);

    packet_info.header_len = IPX_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + IPX_HEADER_LEN;
    packet_info.next_packet_len = header.get_len() - IPX_HEADER_LEN;

    switch (header.get_ptype())
    {
    case IPX_TYPE_SPX:
        packet_info.next_packet_type = PACKET_TYPE_SPX;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::llc_i_packet_handler(c_packet_info packet_info)
{
    c_llc_i_header header(packet_info.packet);

    packet_info.header_len = LLC_I_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + LLC_I_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - LLC_I_HEADER_LEN;

    switch (header.get_dsap())
    {
    case LLC_SAP_SNAP:
        packet_info.next_packet_type = PACKET_TYPE_SNAP;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::llc_s_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = LLC_S_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + LLC_S_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - LLC_S_HEADER_LEN;
    packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;

    return packet_info;
}

c_packet_info c_packet_handler::llc_u_packet_handler(c_packet_info packet_info)
{
    c_llc_u_header header(packet_info.packet);

    packet_info.header_len = LLC_U_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + LLC_U_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - LLC_U_HEADER_LEN;

    switch (header.get_dsap())
    {
    case LLC_SAP_SNAP:
        packet_info.next_packet_type = PACKET_TYPE_SNAP;
        break;

    case LLC_SAP_DODIP:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case LLC_SAP_NOVELL:
        packet_info.next_packet_type = PACKET_TYPE_IPX;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::gif_packet_handler(c_packet_info packet_info)
{
    c_gif_header header(packet_info.packet);

    packet_info.header_len = GIF_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + GIF_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - GIF_HEADER_LEN;

    switch (header.get_af())
    {
    case GIF_AF_INET:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case GIF_AF_INET6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::loop_packet_handler(c_packet_info packet_info)
{
    c_loop_header header(packet_info.packet);

    packet_info.header_len = LOOP_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + LOOP_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - LOOP_HEADER_LEN;

    switch (header.get_af())
    {
    case LOOP_AF_INET:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case LOOP_AF_INET6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::enc_packet_handler(c_packet_info packet_info)
{
    c_enc_header header(packet_info.packet);

    packet_info.header_len = ENC_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + ENC_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - ENC_HEADER_LEN;

    switch (header.get_af())
    {
    case ENC_AF_INET:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case ENC_AF_INET6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::snap_packet_handler(c_packet_info packet_info)
{
    c_snap_header header(packet_info.packet);

    packet_info.header_len = SNAP_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + SNAP_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - SNAP_HEADER_LEN;

    switch (header.get_type())
    {
    case ETHER_TYPE_IP:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    case ETHER_TYPE_IP6:
        packet_info.next_packet_type = PACKET_TYPE_IP6;
        break;

    case ETHER_TYPE_ARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_REVARP:
        packet_info.next_packet_type = PACKET_TYPE_ARP;
        break;

    case ETHER_TYPE_IPX:
        packet_info.next_packet_type = PACKET_TYPE_IPX;
        break;

    case SNAP_TYPE_CDP:
        packet_info.next_packet_type = PACKET_TYPE_CDP;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::tcp_packet_handler(c_packet_info packet_info)
{
    c_tcp_header header(packet_info.packet);

    packet_info.header_len = TCP_HEADER_LEN;

    if (header.get_hlen() - TCP_HEADER_LEN)
    {
        packet_info.tcp_options = packet_info.packet + TCP_HEADER_LEN;
        packet_info.tcp_options_len = header.get_hlen() - TCP_HEADER_LEN;
    }

    packet_info.next_packet = packet_info.packet + packet_info.header_len + packet_info.tcp_options_len;
    packet_info.next_packet_len = packet_info.packet_len - packet_info.header_len - packet_info.tcp_options_len;

    if (packet_info.next_packet_len)
    {
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }
    else
    {
        packet_info.next_packet_type = PACKET_TYPE_NONE;
    }

    return packet_info;
}

c_packet_info c_packet_handler::udp_packet_handler(c_packet_info packet_info)
{
    c_udp_header header(packet_info.packet);

    packet_info.header_len = UDP_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + UDP_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - UDP_HEADER_LEN;

    if (packet_info.next_packet_len)
    {

        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;

        if ((header.get_sport() == UDP_PORT_RIP) || (header.get_dport() == UDP_PORT_RIP))
        {
            packet_info.next_packet_type = PACKET_TYPE_RIP;
        }

        if ((header.get_sport() == UDP_PORT_RIPNG) || (header.get_dport() == UDP_PORT_RIPNG))
        {
            packet_info.next_packet_type = PACKET_TYPE_RIPNG;
        }

        if ((header.get_sport() == UDP_PORT_DHCP_SERVER) || (header.get_dport() == UDP_PORT_DHCP_SERVER) ||
            (header.get_sport() == UDP_PORT_DHCP_CLIENT) || (header.get_dport() == UDP_PORT_DHCP_CLIENT))
        {
            packet_info.next_packet_type = PACKET_TYPE_DHCP;
        }
    }
    else
    {
        packet_info.next_packet_type = PACKET_TYPE_NONE;
    }

    return packet_info;
}

c_packet_info c_packet_handler::spx_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = SPX_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + SPX_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - SPX_HEADER_LEN;
    packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;

    return packet_info;
}

c_packet_info c_packet_handler::rip_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = RIP_HEADER_LEN;

    c_rip_header header(packet_info.packet);
    c_rip_authentry authentry(packet_info.packet + RIP_HEADER_LEN);

    if ((header.get_ver() == 2) && (authentry.get_id() == RIP_AUTHENTRY_ID))
    {
        packet_info.rip_authentry = packet_info.packet + RIP_HEADER_LEN;
        packet_info.rip_authentry_len = RIP_AUTHENTRY_LEN;

        switch (authentry.get_type())
        {
        case RIP_AUTHTYPE_SIMPLE:
            packet_info.rip_entries = packet_info.packet + RIP_HEADER_LEN +
                                      RIP_AUTHENTRY_LEN;
            packet_info.rip_entries_len = packet_info.packet_len -
                                          RIP_HEADER_LEN - RIP_AUTHENTRY_LEN;
            break;

        case RIP_AUTHTYPE_MD5:
            packet_info.rip_entries = packet_info.packet + RIP_HEADER_LEN +
                                      RIP_AUTHENTRY_LEN;
            packet_info.rip_entries_len = packet_info.packet_len -
                                          RIP_HEADER_LEN - RIP_AUTHENTRY_LEN -
                                          RIP_MD5ENTRY_LEN;
            packet_info.rip_md5entry = packet_info.packet +
                                       RIP_HEADER_LEN +
                                       RIP_AUTHENTRY_LEN +
                                       packet_info.rip_entries_len;
            packet_info.rip_md5entry_len = RIP_MD5ENTRY_LEN;
            break;

        default:
            packet_info.rip_entries = packet_info.packet + RIP_HEADER_LEN +
                                      RIP_AUTHENTRY_LEN;
            packet_info.rip_entries_len = packet_info.packet_len -
                                          RIP_HEADER_LEN - RIP_AUTHENTRY_LEN;
        }
    }
    else
    {
        packet_info.rip_entries = packet_info.packet + RIP_HEADER_LEN;
        packet_info.rip_entries_len = packet_info.packet_len - RIP_HEADER_LEN;
    }

    packet_info.next_packet_type = PACKET_TYPE_NONE;
    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;

    return packet_info;
}

c_packet_info c_packet_handler::ripng_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = RIPNG_HEADER_LEN;

    c_ripng_header header(packet_info.packet);

    packet_info.next_packet_type = PACKET_TYPE_NONE;
    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;

    return packet_info;
}

c_packet_info c_packet_handler::cdp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = CDP_HEADER_LEN + 0;

    packet_info.next_packet = packet_info.packet + CDP_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - CDP_HEADER_LEN;

    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::esp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = ESP_HEADER_LEN;

    packet_info.next_packet = packet_info.packet + ESP_HEADER_LEN;
    packet_info.next_packet_len = packet_info.packet_len - ESP_HEADER_LEN;

    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::ah_packet_handler(c_packet_info packet_info)
{
    c_ah_header header(packet_info.packet);

    packet_info.header_len = header.get_hlen();

    packet_info.ah_authdata_len = header.get_hlen() - AH_HEADER_LEN;

    if (packet_info.ah_authdata_len)
    {
        packet_info.ah_authdata = packet_info.header + AH_HEADER_LEN;
    }

    packet_info.next_packet = packet_info.packet + packet_info.header_len;
    packet_info.next_packet_len = packet_info.packet_len - packet_info.header_len;

    switch (header.get_proto())
    {
    case IP_PROTO_IPV4:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::gre_packet_handler(c_packet_info packet_info)
{
    c_gre_header header(packet_info.packet);

    packet_info.header_len = header.get_len();

    packet_info.next_packet = packet_info.packet + packet_info.header_len;
    packet_info.next_packet_len = packet_info.packet_len - packet_info.header_len;

    switch (header.get_type())
    {
    case ETHER_TYPE_IP:
        packet_info.next_packet_type = PACKET_TYPE_IP;
        break;

    default:
        packet_info.next_packet_type = PACKET_TYPE_UNKNOWN;
    }

    return packet_info;
}

c_packet_info c_packet_handler::ethloop_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = ETHLOOP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::igrp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = IGRP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::eigrp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = EIGRP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::ospf_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = OSPF_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::dhcp_packet_handler(c_packet_info packet_info)
{
    packet_info.header_len = DHCP_HEADER_LEN;

    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}

c_packet_info c_packet_handler::unknown_packet_handler(c_packet_info packet_info)
{
    packet_info.next_packet = 0;
    packet_info.next_packet_len = 0;
    packet_info.next_packet_type = PACKET_TYPE_NONE;

    return packet_info;
}
