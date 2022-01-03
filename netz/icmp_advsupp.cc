#include "icmp_advsupp.h"
#include "cksum.h"

c_icmp_packet::c_icmp_packet(byte type, byte code)
{
    c_icmp_header header(packet);

    header.set_type(type);
    header.set_code(code);
    header.set_cksum();

    header_len = ICMP_HEADER_LEN;
    packet_len = header_len;
}

void c_icmp_packet::verify()
{
    c_icmp_header header(packet);

    header.set_cksum();
    header.set_cksum(cksum(packet, packet_len));
}

c_icmp_packet_echoreply::c_icmp_packet_echoreply(word id, word seqnumber,
                                                 byte *data, u_int data_len) : c_icmp_packet(ICMP_ECHOREPLY)
{
    c_icmp_message_echoreply message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_data(data, data_len);

    packet_len = header_len + ICMP_ECHOREPLY_LEN + data_len;
}

c_icmp_packet_unreach::c_icmp_packet_unreach(byte code, c_ip_header ipheader,
                                             byte *ipdata) : c_icmp_packet(ICMP_UNREACH, code)
{
    c_icmp_message_unreach message(packet);

    message.set_unused();
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_UNREACH_LEN;
}

c_icmp_packet_sourcequench::c_icmp_packet_sourcequench(c_ip_header ipheader,
                                                       byte *ipdata) : c_icmp_packet(ICMP_SOURCEQUENCH)
{
    c_icmp_message_sourcequench message(packet);

    message.set_unused();
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_SOURCEQUENCH_LEN;
}

c_icmp_packet_redirect::c_icmp_packet_redirect(byte code, dword gateway,
                                               c_ip_header ipheader, byte *ipdata) : c_icmp_packet(ICMP_REDIRECT, code)
{
    c_icmp_message_redirect message(packet);

    message.set_gateway(gateway);
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_REDIRECT_LEN;
}

c_icmp_packet_echorequest::c_icmp_packet_echorequest(word id, word seqnumber,
                                                     byte *data, u_int data_len) : c_icmp_packet(ICMP_ECHOREQUEST)
{
    c_icmp_message_echorequest message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_data(data, data_len);

    packet_len = header_len + ICMP_ECHOREPLY_LEN + data_len;
}

c_icmp_packet_routeradvert::c_icmp_packet_routeradvert(byte addrnumber,
                                                       byte addrentrysize, word lifetime, dword *data, u_int data_len)
    : c_icmp_packet(ICMP_ROUTERADVERT)
{
    c_icmp_message_routeradvert message(packet);

    message.set_addrnumber(addrnumber);
    message.set_addrentrysize(addrentrysize);
    message.set_lifetime(lifetime);

    for (u_int i = 0; i < data_len / ICMP_ROUTERADVERT_DATALEN; i++)
    {
        message.set_address(i, data[i * 2]);
        message.set_plevel(i, data[i * 2 + 1]);
    }

    packet_len = header_len + ICMP_ROUTERADVERT_LEN + data_len;
}

c_icmp_packet_routersolicit::c_icmp_packet_routersolicit()
    : c_icmp_packet(ICMP_ROUTERSOLICIT)
{
    c_icmp_message_routersolicit message(packet);

    message.set_unused();

    packet_len = header_len + ICMP_ROUTERSOLICIT_LEN;
}

c_icmp_packet_timexceed::c_icmp_packet_timexceed(byte code,
                                                 c_ip_header ipheader, byte *ipdata) : c_icmp_packet(ICMP_TIMEXCEED, code)
{
    c_icmp_message_timexceed message(packet);

    message.set_unused();
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_TIMEXCEED_LEN;
}

c_icmp_packet_paramprob::c_icmp_packet_paramprob(byte code, byte pointer,
                                                 c_ip_header ipheader, byte *ipdata) : c_icmp_packet(ICMP_PARAMPROB, code)
{
    c_icmp_message_paramprob message(packet);

    message.set_pointer(pointer);
    message.set_unused(0);
    message.set_unused(1);
    message.set_unused(2);
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_PARAMPROB_LEN;
}

c_icmp_packet_tsrequest::c_icmp_packet_tsrequest(word id, word seqnumber,
                                                 dword originate, dword receive, dword transmit)
    : c_icmp_packet(ICMP_TSREQUEST)
{
    c_icmp_message_tsrequest message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_originate(originate);
    message.set_receive(receive);
    message.set_transmit(transmit);

    packet_len = header_len + ICMP_TSREQUEST_LEN;
}

c_icmp_packet_tsreply::c_icmp_packet_tsreply(word id, word seqnumber,
                                             dword originate, dword receive, dword transmit)
    : c_icmp_packet(ICMP_TSREPLY)
{
    c_icmp_message_tsreply message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_originate(originate);
    message.set_receive(receive);
    message.set_transmit(transmit);

    packet_len = header_len + ICMP_TSREPLY_LEN;
}

c_icmp_packet_inforequest::c_icmp_packet_inforequest(word id,
                                                     word seqnumber) : c_icmp_packet(ICMP_INFOREQUEST)
{
    c_icmp_message_inforequest message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);

    packet_len = header_len + ICMP_INFOREQUEST_LEN;
}

c_icmp_packet_inforeply::c_icmp_packet_inforeply(word id,
                                                 word seqnumber) : c_icmp_packet(ICMP_INFOREPLY)
{
    c_icmp_message_inforeply message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);

    packet_len = header_len + ICMP_INFOREPLY_LEN;
}

c_icmp_packet_maskrequest::c_icmp_packet_maskrequest(word id, word seqnumber,
                                                     dword mask) : c_icmp_packet(ICMP_MASKREQUEST)
{
    c_icmp_message_maskrequest message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_mask(mask);

    packet_len = header_len + ICMP_MASKREQUEST_LEN;
}

c_icmp_packet_maskreply::c_icmp_packet_maskreply(word id, word seqnumber,
                                                 dword mask) : c_icmp_packet(ICMP_MASKREPLY)
{
    c_icmp_message_maskreply message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_mask(mask);

    packet_len = header_len + ICMP_MASKREPLY_LEN;
}

c_icmp_packet_traceroute::c_icmp_packet_traceroute(word id, word outhopcount,
                                                   word rethopcount, dword outlinkspeed, dword outlinkmtu)
    : c_icmp_packet(ICMP_TRACEROUTE)
{
    c_icmp_message_traceroute message(packet);

    message.set_id(id);
    message.set_unused();
    message.set_outhopcount(outhopcount);
    message.set_rethopcount(rethopcount);
    message.set_outlinkspeed(outlinkspeed);
    message.set_outlinkmtu(outlinkmtu);

    packet_len = header_len + ICMP_TRACEROUTE_LEN;
}

c_icmp_packet_converr::c_icmp_packet_converr(byte code, dword pointer,
                                             byte *badpacket, u_int badpacket_len) : c_icmp_packet(ICMP_CONVERR, code)
{
    c_icmp_message_converr message(packet);

    message.set_pointer(pointer);
    message.set_badpacket(badpacket, badpacket_len);

    packet_len = header_len + ICMP_CONVERR_LEN + badpacket_len;
}

c_icmp_packet_dnamerequest::c_icmp_packet_dnamerequest(word id, word seqnumber)
    : c_icmp_packet(ICMP_DNAMEREQUEST)
{
    c_icmp_message_dnamerequest message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);

    packet_len = header_len + ICMP_DNAMEREQUEST_LEN;
}

c_icmp_packet_dnamereply::c_icmp_packet_dnamereply(word id, word seqnumber,
                                                   dword ttl, byte *names, u_int names_len) : c_icmp_packet(ICMP_DNAMEREPLY)
{
    c_icmp_message_dnamereply message(packet);

    message.set_id(id);
    message.set_seqnumber(seqnumber);
    message.set_ttl(ttl);
    message.set_names(names, names_len);

    packet_len = header_len + ICMP_DNAMEREPLY_LEN + names_len;
}

c_icmp_packet_security::c_icmp_packet_security(byte code, word pointer,
                                               c_ip_header ipheader, byte *ipdata) : c_icmp_packet(ICMP_SECURITY, code)
{
    c_icmp_message_security message(packet);

    message.set_unused();
    message.set_pointer(pointer);
    message.set_ipheader(ipheader);
    message.set_ipdata(ipdata);

    packet_len = header_len + ICMP_SECURITY_LEN;
}
