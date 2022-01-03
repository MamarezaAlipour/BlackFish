#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>

#include "ether_vlan_advsupp.h"
#include "ip_advsupp.h"
#include "arp_advsupp.h"

c_ether_vlan_packet::c_ether_vlan_packet(byte *src, byte *dst,
                                         word tci, word type)
{
    c_ether_vlan_header header(packet);

    header.set_src(src);
    header.set_dst(dst);
    header.set_tpid();
    header.set_tci(tci);
    header.set_type(type);

    header_len = ETHER_VLAN_HEADER_LEN;
    packet_len = header_len;
}

void c_ether_vlan_packet::add_data(byte *data, u_int data_len)
{
    memcpy(packet + header_len, data, data_len);

    packet_len = header_len + data_len;
}

void c_ether_vlan_packet::add_data(c_ip_packet ip_packet)
{
    c_ether_vlan_header header(packet);

    header.set_type(ETHER_TYPE_IP);

    ip_packet.verify();

    memcpy(packet + header_len, ip_packet.get_packet(),
           ip_packet.get_packet_len());

    packet_len = header_len + ip_packet.get_packet_len();
}

void c_ether_vlan_packet::add_data(c_arp_packet arp_packet)
{
    c_ether_vlan_header header(packet);

    header.set_type(ETHER_TYPE_ARP);

    arp_packet.verify();

    memcpy(packet + header_len, arp_packet.get_packet(),
           arp_packet.get_packet_len());

    packet_len = header_len + arp_packet.get_packet_len();
}

void c_ether_vlan_packet::verify()
{
}

int c_ether_vlan_packet::send(string *interface)
{
    verify();

    string errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_live(interface, 0, 0, 0, errbuf);

    if (!pcap)
    {
        return -1;
    }

    int retval = write(*((int *)pcap), packet, packet_len);

    pcap_close(pcap);

    return retval;
}

int c_ether_vlan_packet::send(pcap_t *pcap)
{
    verify();

    return write(*((int *)pcap), packet, packet_len);
}
