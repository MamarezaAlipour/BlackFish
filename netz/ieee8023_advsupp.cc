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

#include "ieee8023_advsupp.h"
#include "ip_advsupp.h"

c_ieee8023_packet::c_ieee8023_packet(byte *src, byte *dst, word dlen)
{
    c_ieee8023_header header(packet);

    header.set_src(src);
    header.set_dst(dst);
    header.set_dlen(dlen);

    header_len = IEEE8023_HEADER_LEN;
    packet_len = header_len;
}

void c_ieee8023_packet::add_data(byte *data, u_int data_len)
{
    memcpy(packet + header_len, data, data_len);

    packet_len = header_len + data_len;
}

void c_ieee8023_packet::verify()
{
    c_ieee8023_header header(packet);

    header.set_dlen(packet_len - header_len);
}

int c_ieee8023_packet::send(string *interface)
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

int c_ieee8023_packet::send(pcap_t *pcap)
{
    return write(*((int *)pcap), packet, packet_len);
}
