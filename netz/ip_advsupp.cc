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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include "ip_advsupp.h"
#include "tcp_advsupp.h"
#include "udp_advsupp.h"
#include "icmp_advsupp.h"
#include "cksum.h"

int c_ip_packet::send()
{
    verify();

    c_ip_header header(packet);

    sockaddr_in sin;
    int sinlen;

    int rawsock = socket(AF_INET, SOCK_RAW, 0);

    if (rawsock == -1)
    {
        return -1;
    }

    int on = 1;

    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    {
        return -1;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(header.get_dst());
    sinlen = sizeof(sin);

    int retval = sendto(rawsock, (char *)packet, header.get_len(), 0,
                        (sockaddr *)&sin, sinlen);
    close(rawsock);

    return retval;
}

c_ip_packet::c_ip_packet(dword src, dword dst, word id, byte ttl, byte tos,
                         byte frag)
{
    c_ip_header header(packet);

    header.set_ver();
    header.set_tos();
    header.set_id();
    header.set_ttl();
    header.set_frag();
    header.set_proto();
    header.set_cksum();
    header.set_src(src);
    header.set_dst(dst);

    header_len = IP_HEADER_LEN;
    packet_len = IP_HEADER_LEN;
}

c_ip_packet::c_ip_packet(char *src, char *dst, word id, byte ttl, byte tos,
                         byte frag)
{
    c_ip_header header(packet);

    header.set_ver();
    header.set_tos();
    header.set_id();
    header.set_ttl();
    header.set_frag();
    header.set_proto();
    header.set_cksum();
    header.set_src(src);
    header.set_dst(dst);

    header_len = IP_HEADER_LEN;
    packet_len = IP_HEADER_LEN;
}

void c_ip_packet::verify()
{
    c_ip_header header(packet);

    if (header_len & 3)
    {
        add_opt_nop(4 - (header_len & 3));
    }

    header.set_hlen(header_len);
    header.set_len(packet_len);
    header.set_cksum();
    header.set_cksum(cksum(packet, header_len));
}

void c_ip_packet::add_opt_eol()
{
    c_ipopt_eol option(packet + header_len);

    option.set_code();

    header_len += IPOPT_EOL_LEN;
    packet_len += IPOPT_EOL_LEN;
}

void c_ip_packet::add_opt_nop(u_int count)
{
    for (u_int i = 0; i < count; i++)
    {
        c_ipopt_nop option(packet + header_len);

        option.set_code();

        header_len += IPOPT_NOP_LEN;
        packet_len += IPOPT_NOP_LEN;
    }
}

void c_ip_packet::add_opt_rr(dword *data, u_int data_len)
{
    c_ipopt_rr option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_RR_LEN + data_len);
    option.set_ptr(IPOPT_RR_LEN + data_len + 1);

    for (u_int i = 0; i < data_len / IPOPT_RR_DATALEN; i++)
    {
        option.set_ip(i, data[i]);
    }

    header_len += IPOPT_RR_LEN + data_len;
    packet_len += IPOPT_RR_LEN + data_len;
}

void c_ip_packet::add_opt_timestamp(byte ts_of, byte ts_fl, dword *data,
                                    u_int data_len)
{
    c_ipopt_ts option(packet + header_len);

    option.set_code();
    option.set_flags((ts_of << 4) | (ts_fl & 0x0F));

    switch (ts_fl)
    {
    case IPOPT_TS_TSONLY:

        option.set_len(IPOPT_TS_LEN + data_len);
        option.set_ptr(IPOPT_TS_LEN + data_len + 1);

        for (u_int i = 0; i < data_len / IPOPT_TS_TSONLY_DATALEN; i++)
        {
            option.set_timestamp(i, data[i]);
        }

        header_len += IPOPT_TS_LEN + data_len;
        packet_len += IPOPT_TS_LEN + data_len;

        break;

    case IPOPT_TS_TSANDADDR:

        option.set_len(IPOPT_TS_LEN + data_len);
        option.set_ptr(IPOPT_TS_LEN + data_len + 1);

        for (u_int i = 0; i < data_len / IPOPT_TS_TSANDADDR_DATALEN; i++)
        {
            option.set_ip(i, data[i * 2]);
            option.set_timestamp(i, data[i * 2 + 1]);
        }

        header_len += IPOPT_TS_LEN + data_len;
        packet_len += IPOPT_TS_LEN + data_len;

        break;

    case IPOPT_TS_PRESPEC:

        option.set_len(IPOPT_TS_LEN + data_len * 2);
        option.set_ptr(IPOPT_TS_LEN + data_len * 2 + 1);

        for (u_int i = 0; i < data_len / IPOPT_TS_PRESPEC_DATALEN; i++)
        {
            option.set_ip(i, data[i]);
            option.set_timestamp(i, 0);
        }

        header_len += IPOPT_TS_LEN + data_len * 2;
        packet_len += IPOPT_TS_LEN + data_len * 2;

        break;
    }
}

void c_ip_packet::add_opt_sec(byte cl, byte *flags, u_int flags_len)
{
    c_ipopt_sec option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_SEC_LEN + flags_len);
    option.set_cl(cl);

    for (u_int i = 0; i < flags_len / IPOPT_SEC_DATALEN; i++)
    {
        if (i + 1 < flags_len / IPOPT_SEC_DATALEN)
        {
            option.set_flags(i, flags[i] | 1);
        }
        else
        {
            option.set_flags(i, flags[i] & 0xFE);
        }
    }

    header_len += IPOPT_SEC_LEN + flags_len;
    packet_len += IPOPT_SEC_LEN + flags_len;
}

void c_ip_packet::add_opt_xsec(byte asiac, byte *flags, u_int flags_len)
{
    c_ipopt_xsec option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_SEC_LEN + flags_len);
    option.set_asiac(asiac);

    for (u_int i = 0; i < flags_len / IPOPT_XSEC_DATALEN; i++)
    {
        if (i + 1 < flags_len / IPOPT_XSEC_DATALEN)
        {
            option.set_flags(i, flags[i] | 1);
        }
        else
        {
            option.set_flags(i, flags[i] & 0xFE);
        }
    }

    header_len += IPOPT_XSEC_LEN + flags_len;
    packet_len += IPOPT_XSEC_LEN + flags_len;
}

void c_ip_packet::add_opt_lsrr(dword *data, u_int data_len)
{
    c_ipopt_lsrr option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_LSRR_LEN + data_len);
    option.set_ptr(IPOPT_LSRR_LEN + data_len + 1);

    for (u_int i = 0; i < data_len / IPOPT_LSRR_DATALEN; i++)
    {
        option.set_ip(i, data[i]);
    }

    header_len += IPOPT_LSRR_LEN + data_len;
    packet_len += IPOPT_LSRR_LEN + data_len;
}

void c_ip_packet::add_opt_ssrr(dword *data, u_int data_len)
{
    c_ipopt_ssrr option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_SSRR_LEN + data_len);
    option.set_ptr(IPOPT_SSRR_LEN + data_len + 1);

    for (u_int i = 0; i < data_len / IPOPT_SSRR_DATALEN; i++)
    {
        option.set_ip(i, data[i]);
    }

    header_len += IPOPT_SSRR_LEN + data_len;
    packet_len += IPOPT_SSRR_LEN + data_len;
}

void c_ip_packet::add_opt_satid(word stream_id)
{
    c_ipopt_satid option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_SATID_LEN);
    option.set_id(stream_id);

    header_len += IPOPT_SATID_LEN;
    packet_len += IPOPT_SATID_LEN;
}

void c_ip_packet::add_opt_pmtu(word mtu)
{
    c_ipopt_pmtu option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_PMTU_LEN);
    option.set_mtu(mtu);

    header_len += IPOPT_PMTU_LEN;
    packet_len += IPOPT_PMTU_LEN;
}

void c_ip_packet::add_opt_rmtu(word mtu)
{
    c_ipopt_pmtu option(packet + header_len);

    option.set_code();
    option.set_len(IPOPT_RMTU_LEN);
    option.set_mtu(mtu);

    header_len += IPOPT_RMTU_LEN;
    packet_len += IPOPT_RMTU_LEN;
}

void c_ip_packet::add_opt_generic(byte code, byte *data, u_int data_len)
{
    c_ipopt_generic option(packet + header_len);

    option.set_code(code);
    option.set_len(IPOPT_GENERIC_LEN + data_len);
    option.set_data(data, data_len);

    header_len += IPOPT_GENERIC_LEN + data_len;
    packet_len += IPOPT_GENERIC_LEN + data_len;
}

void c_ip_packet::add_data(byte *data, u_int data_len)
{
    verify();

    memcpy(packet + header_len, data, data_len);

    packet_len = header_len + data_len;
}

void c_ip_packet::add_data(c_tcp_packet tcp_packet)
{
    verify();

    c_ip_header ip_header(packet);

    tcp_packet.verify();

    packet_len = header_len + tcp_packet.get_packet_len();

    ip_header.set_proto(IP_PROTO_TCP);
    ip_header.set_hlen(header_len);
    ip_header.set_len(packet_len);

    c_ipp_header ipp_header(ip_header);

    tcp_packet.verify(ipp_header.get_pseudo_header());

    memcpy(packet + header_len, tcp_packet.get_packet(),
           tcp_packet.get_packet_len());
}

void c_ip_packet::add_data(c_udp_packet udp_packet)
{
    verify();

    c_ip_header ip_header(packet);

    udp_packet.verify();

    packet_len = header_len + udp_packet.get_packet_len();

    ip_header.set_proto(IP_PROTO_UDP);
    ip_header.set_hlen(header_len);
    ip_header.set_len(packet_len);

    c_ipp_header ipp_header(ip_header);

    udp_packet.verify(ipp_header.get_pseudo_header());

    memcpy(packet + header_len, udp_packet.get_packet(),
           udp_packet.get_packet_len());
}

void c_ip_packet::add_data(c_icmp_packet icmp_packet)
{
    verify();

    c_ip_header ip_header(packet);

    icmp_packet.verify();
    packet_len = header_len + icmp_packet.get_packet_len();

    ip_header.set_proto(IP_PROTO_ICMP);
    ip_header.set_hlen(header_len);
    ip_header.set_len(packet_len);

    memcpy(packet + header_len, icmp_packet.get_packet(),
           icmp_packet.get_packet_len());
}

void c_ip_packet::add_data(c_ip_packet ip_packet)
{
    verify();

    c_ip_header ip_header(packet);

    ip_packet.verify();
    packet_len = header_len + ip_packet.get_packet_len();

    ip_header.set_proto(IP_PROTO_IPV4);
    ip_header.set_hlen(header_len);
    ip_header.set_len(packet_len);

    memcpy(packet + header_len, ip_packet.get_packet(),
           ip_packet.get_packet_len());
}
