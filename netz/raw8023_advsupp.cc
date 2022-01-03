#ifdef OS_AIX
#include <memory.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>

#include "raw8023_advsupp.h"
#include "ip_advsupp.h"

c_raw8023_packet::c_raw8023_packet(byte *src, byte *dst, word dlen)
{
    c_raw8023_header header(packet);

    header.set_src(src);
    header.set_dst(dst);
    header.set_dlen(dlen);

    header_len = RAW8023_HEADER_LEN;
    packet_len = header_len;
}

void c_raw8023_packet::verify()
{
    c_raw8023_header header(packet);

    header.set_dlen(packet_len - header_len);
}

int c_raw8023_packet::send(string *interface)
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

int c_raw8023_packet::send(pcap_t *pcap)
{
    return write(*((int *)pcap), packet, packet_len);
}
