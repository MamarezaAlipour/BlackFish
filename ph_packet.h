#include <netz/types.h>

#include "support.h"

struct s_pseudo_header;

void packet_handler(byte *, struct pcap_pkthdr *, byte *);

c_string ether_packet_handler(c_packet_info);
c_string ether_vlan_packet_handler(c_packet_info);
c_string ieee8023_packet_handler(c_packet_info);
c_string raw8023_packet_handler(c_packet_info);
c_string llc_i_packet_handler(c_packet_info);
c_string llc_s_packet_handler(c_packet_info);
c_string llc_u_packet_handler(c_packet_info);
c_string snap_packet_handler(c_packet_info);
c_string gif_packet_handler(c_packet_info);
c_string loop_packet_handler(c_packet_info);
c_string enc_packet_handler(c_packet_info);
c_string arp_packet_handler(c_packet_info);
c_string ip_packet_handler(c_packet_info);
c_string ip6_packet_handler(c_packet_info);
c_string icmp_packet_handler(c_packet_info);
c_string icmp6_packet_handler(c_packet_info);
c_string igmp_packet_handler(c_packet_info);
c_string tcp_packet_handler(c_packet_info);
c_string udp_packet_handler(c_packet_info);
c_string ipx_packet_handler(c_packet_info);
// c_string spx_packet_handler(c_packet_info);
c_string rip_packet_handler(c_packet_info);
c_string ripng_packet_handler(c_packet_info);
c_string cdp_packet_handler(c_packet_info);
c_string esp_packet_handler(c_packet_info);
c_string ah_packet_handler(c_packet_info);
// c_string isakmp_packet_handler(c_packet_info);
c_string gre_packet_handler(c_packet_info);
c_string ethloop_packet_handler(c_packet_info);
c_string igrp_packet_handler(c_packet_info);
c_string eigrp_packet_handler(c_packet_info);
c_string ospf_packet_handler(c_packet_info);
c_string dhcp_packet_handler(c_packet_info);
c_string unknown_packet_handler(c_packet_info);
// c_string data_packet_handler(c_packet_info);
c_string missing_packet_handler(c_packet_info);

c_string print_hex_data(byte *, u_int, bool = true,
                        c_string = c_string((char *)"    \t"));

c_string debug(c_packet_info);
