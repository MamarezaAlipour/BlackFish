#ifndef _NETZ_PACKET_HANDLER_H_
#define _NETZ_PACKET_HANDLER_H_

#include "types.h"

enum e_packet_type
{
    PACKET_TYPE_ARP,
    PACKET_TYPE_ETHER,
    PACKET_TYPE_ETHER_VLAN,
    PACKET_TYPE_IEEE8023,
    PACKET_TYPE_RAW8023,
    PACKET_TYPE_ICMP,
    PACKET_TYPE_ICMP6,
    PACKET_TYPE_IGMP,
    PACKET_TYPE_IP,
    PACKET_TYPE_IP6,
    PACKET_TYPE_IPX,
    PACKET_TYPE_LLC_I,
    PACKET_TYPE_LLC_S,
    PACKET_TYPE_LLC_U,
    PACKET_TYPE_GIF,
    PACKET_TYPE_LOOP,
    PACKET_TYPE_ENC,
    PACKET_TYPE_SNAP,
    PACKET_TYPE_TCP,
    PACKET_TYPE_UDP,
    PACKET_TYPE_SPX,
    PACKET_TYPE_RIP,
    PACKET_TYPE_RIPNG,
    PACKET_TYPE_CDP,
    PACKET_TYPE_ESP,
    PACKET_TYPE_AH,
    PACKET_TYPE_ISAKMP,
    PACKET_TYPE_GRE,
    PACKET_TYPE_ETHLOOP,
    PACKET_TYPE_IGRP,
    PACKET_TYPE_EIGRP,
    PACKET_TYPE_OSPF,
    PACKET_TYPE_BGP,
    PACKET_TYPE_DHCP,
    PACKET_TYPE_NONE,
    PACKET_TYPE_UNKNOWN
};

e_packet_type get_ether_type(byte *ether_packet);

class c_packet_info
{
public:
    e_packet_type previous_packet_type;
    byte *previous_packet;
    u_int previous_packet_len;

    e_packet_type packet_type;

    byte *packet;
    u_int packet_len;

    byte *header;
    u_int header_len;

    byte *ip_options;
    u_int ip_options_len;

    byte *tcp_options;
    u_int tcp_options_len;

    byte *data;
    u_int data_len;

    byte *rip_entries;
    u_int rip_entries_len;
    byte *rip_authentry;
    u_int rip_authentry_len;
    byte *rip_md5entry;
    u_int rip_md5entry_len;

    byte *ripng_entries;
    u_int ripng_entries_len;

    byte *ah_authdata;
    u_int ah_authdata_len;

    e_packet_type next_packet_type;
    byte *next_packet;
    u_int next_packet_len;

public:
    c_packet_info();
};

class c_packet_handler
{
public:
    c_packet_handler(c_packet_info);

    c_packet_info get_packet_info(u_int = 0);

protected:
    c_packet_info ptable[16];

    u_int ptable_counter;

    void set_next_ptable_entry(c_packet_info);

protected:
    c_packet_info packet_handler(c_packet_info);

    c_packet_info arp_packet_handler(c_packet_info);
    c_packet_info ether_packet_handler(c_packet_info);
    c_packet_info ether_vlan_packet_handler(c_packet_info);
    c_packet_info ieee8023_packet_handler(c_packet_info);
    c_packet_info raw8023_packet_handler(c_packet_info);
    c_packet_info icmp_packet_handler(c_packet_info);
    c_packet_info icmp6_packet_handler(c_packet_info);
    c_packet_info igmp_packet_handler(c_packet_info);
    c_packet_info ip_packet_handler(c_packet_info);
    c_packet_info ip6_packet_handler(c_packet_info);
    c_packet_info ipx_packet_handler(c_packet_info);
    c_packet_info llc_i_packet_handler(c_packet_info);
    c_packet_info llc_s_packet_handler(c_packet_info);
    c_packet_info llc_u_packet_handler(c_packet_info);
    c_packet_info gif_packet_handler(c_packet_info);
    c_packet_info loop_packet_handler(c_packet_info);
    c_packet_info enc_packet_handler(c_packet_info);
    c_packet_info snap_packet_handler(c_packet_info);
    c_packet_info tcp_packet_handler(c_packet_info);
    c_packet_info udp_packet_handler(c_packet_info);
    c_packet_info spx_packet_handler(c_packet_info);
    c_packet_info rip_packet_handler(c_packet_info);
    c_packet_info ripng_packet_handler(c_packet_info);
    c_packet_info cdp_packet_handler(c_packet_info);
    c_packet_info esp_packet_handler(c_packet_info);
    c_packet_info ah_packet_handler(c_packet_info);
    c_packet_info isakmp_packet_handler(c_packet_info);
    c_packet_info gre_packet_handler(c_packet_info);
    c_packet_info ethloop_packet_handler(c_packet_info);
    c_packet_info igrp_packet_handler(c_packet_info);
    c_packet_info eigrp_packet_handler(c_packet_info);
    c_packet_info ospf_packet_handler(c_packet_info);
    c_packet_info bgp_packet_handler(c_packet_info);
    c_packet_info dhcp_packet_handler(c_packet_info);
    c_packet_info unknown_packet_handler(c_packet_info);
    c_packet_info data_packet_handler(c_packet_info);
};

#endif /* _NETZ_PACKET_HANDLER_H_ */
