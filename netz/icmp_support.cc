#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "icmp_support.h"
#include "support.h"

c_icmp_header::c_icmp_header(byte *icmp_header)
{
    header = (s_icmp_header *)icmp_header;
}

s_icmp_header *c_icmp_header::get_header()
{
    return header;
}

byte c_icmp_header::get_type()
{
    return ntoh(header->type);
}

void c_icmp_header::set_type(byte type)
{
    header->type = hton(type);
}

byte c_icmp_header::get_code()
{
    return ntoh(header->code);
}

void c_icmp_header::set_code(byte code)
{
    header->code = hton(code);
}

word c_icmp_header::get_cksum()
{
    return header->cksum;
}

void c_icmp_header::set_cksum(word cksum)
{
    header->cksum = cksum;
}

c_icmp_message_echoreply::c_icmp_message_echoreply(c_icmp_header icmp_header)
{
    message = (s_icmp_message_echoreply *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_echoreply::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_echoreply::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_echoreply::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_echoreply::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

byte *c_icmp_message_echoreply::get_data()
{
    return message->data;
}

void c_icmp_message_echoreply::set_data(byte *data, u_int data_len)
{
    memcpy(message->data, data, data_len);
}

c_icmp_message_unreach::c_icmp_message_unreach(c_icmp_header icmp_header)
{
    message = (s_icmp_message_unreach *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_unreach::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_unreach::set_unused(dword unused)
{
    message->unused = hton(unused);
}

c_ip_header c_icmp_message_unreach::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_unreach::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_unreach::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_unreach::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}

c_icmp_message_sourcequench::c_icmp_message_sourcequench(c_icmp_header icmp_header)
{
    message = (s_icmp_message_sourcequench *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_sourcequench::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_sourcequench::set_unused(dword unused)
{
    message->unused = hton(unused);
}

c_ip_header c_icmp_message_sourcequench::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_sourcequench::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_sourcequench::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_sourcequench::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}

c_icmp_message_redirect::c_icmp_message_redirect(c_icmp_header icmp_header)
{
    message = (s_icmp_message_redirect *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_redirect::get_gateway()
{
    return ntoh(message->gateway);
}

void c_icmp_message_redirect::set_gateway(dword gateway)
{
    message->gateway = hton(gateway);
}

c_ip_header c_icmp_message_redirect::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_redirect::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_redirect::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_redirect::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}

c_icmp_message_echorequest::c_icmp_message_echorequest(c_icmp_header icmp_header)
{
    message = (s_icmp_message_echorequest *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_echorequest::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_echorequest::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_echorequest::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_echorequest::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

byte *c_icmp_message_echorequest::get_data()
{
    return message->data;
}

void c_icmp_message_echorequest::set_data(byte *data, u_int data_len)
{
    memcpy(message->data, data, data_len);
}

c_icmp_message_timexceed::c_icmp_message_timexceed(c_icmp_header icmp_header)
{
    message = (s_icmp_message_timexceed *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_timexceed::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_timexceed::set_unused(dword unused)
{
    message->unused = hton(unused);
}

c_ip_header c_icmp_message_timexceed::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_timexceed::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_timexceed::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_timexceed::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}

c_icmp_message_paramprob::c_icmp_message_paramprob(c_icmp_header icmp_header)
{
    message = (s_icmp_message_paramprob *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

byte c_icmp_message_paramprob::get_pointer()
{
    return ntoh(message->pointer);
}

void c_icmp_message_paramprob::set_pointer(byte pointer)
{
    message->pointer = hton(pointer);
}

byte c_icmp_message_paramprob::get_unused(u_int n)
{
    return ntoh(message->unused[n]);
}

void c_icmp_message_paramprob::set_unused(u_int n, byte unused)
{
    message->unused[n] = hton(unused);
}

c_ip_header c_icmp_message_paramprob::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_paramprob::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_paramprob::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_paramprob::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}

c_icmp_message_routeradvert::c_icmp_message_routeradvert(c_icmp_header icmp_header)
{
    message = (s_icmp_message_routeradvert *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

byte c_icmp_message_routeradvert::get_addrnumber()
{
    return ntoh(message->addrnumber);
}

void c_icmp_message_routeradvert::set_addrnumber(byte addrnumber)
{
    message->addrnumber = hton(addrnumber);
}

byte c_icmp_message_routeradvert::get_addrentrysize()
{
    return ntoh(message->addrentrysize);
}

void c_icmp_message_routeradvert::set_addrentrysize(byte addrentrysize)
{
    message->addrentrysize = hton(addrentrysize);
}

word c_icmp_message_routeradvert::get_lifetime()
{
    return ntoh(message->lifetime);
}

void c_icmp_message_routeradvert::set_lifetime(word lifetime)
{
    message->lifetime = hton(lifetime);
}

dword c_icmp_message_routeradvert::get_address(u_int n)
{
    return ntoh(message->router[n].address);
}

void c_icmp_message_routeradvert::set_address(u_int n, dword address)
{
    message->router[n].address = hton(address);
}

dword c_icmp_message_routeradvert::get_plevel(u_int n)
{
    return ntoh(message->router[n].plevel);
}

void c_icmp_message_routeradvert::set_plevel(u_int n, dword plevel)
{
    message->router[n].plevel = hton(plevel);
}

c_icmp_message_routersolicit::c_icmp_message_routersolicit(c_icmp_header icmp_header)
{
    message = (s_icmp_message_routersolicit *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

c_icmp_message_tsrequest::c_icmp_message_tsrequest(c_icmp_header icmp_header)
{
    message = (s_icmp_message_tsrequest *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_routersolicit::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_routersolicit::set_unused(dword unused)
{
    message->unused = hton(unused);
}

word c_icmp_message_tsrequest::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_tsrequest::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_tsrequest::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_tsrequest::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

dword c_icmp_message_tsrequest::get_originate()
{
    return ntoh(message->originate);
}

void c_icmp_message_tsrequest::set_originate(dword originate)
{
    message->originate = hton(originate);
}

dword c_icmp_message_tsrequest::get_receive()
{
    return ntoh(message->receive);
}

void c_icmp_message_tsrequest::set_receive(dword receive)
{
    message->receive = hton(receive);
}

dword c_icmp_message_tsrequest::get_transmit()
{
    return ntoh(message->transmit);
}

void c_icmp_message_tsrequest::set_transmit(dword transmit)
{
    message->transmit = hton(transmit);
}

c_icmp_message_tsreply::c_icmp_message_tsreply(c_icmp_header icmp_header)
{
    message = (s_icmp_message_tsreply *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_tsreply::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_tsreply::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_tsreply::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_tsreply::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

dword c_icmp_message_tsreply::get_originate()
{
    return ntoh(message->originate);
}

void c_icmp_message_tsreply::set_originate(dword originate)
{
    message->originate = hton(originate);
}

dword c_icmp_message_tsreply::get_receive()
{
    return ntoh(message->receive);
}

void c_icmp_message_tsreply::set_receive(dword receive)
{
    message->receive = hton(receive);
}

dword c_icmp_message_tsreply::get_transmit()
{
    return ntoh(message->transmit);
}

void c_icmp_message_tsreply::set_transmit(dword transmit)
{
    message->transmit = hton(transmit);
}

c_icmp_message_inforequest::c_icmp_message_inforequest(c_icmp_header icmp_header)
{
    message = (s_icmp_message_inforequest *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_inforequest::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_inforequest::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_inforequest::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_inforequest::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

c_icmp_message_inforeply::c_icmp_message_inforeply(c_icmp_header icmp_header)
{
    message = (s_icmp_message_inforeply *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_inforeply::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_inforeply::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_inforeply::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_inforeply::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

c_icmp_message_maskrequest::c_icmp_message_maskrequest(c_icmp_header icmp_header)
{
    message = (s_icmp_message_maskrequest *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_maskrequest::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_maskrequest::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_maskrequest::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_maskrequest::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

dword c_icmp_message_maskrequest::get_mask()
{
    return ntoh(message->mask);
}

void c_icmp_message_maskrequest::set_mask(dword mask)
{
    message->mask = hton(mask);
}

c_icmp_message_maskreply::c_icmp_message_maskreply(c_icmp_header icmp_header)
{
    message = (s_icmp_message_maskreply *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_maskreply::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_maskreply::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_maskreply::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_maskreply::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

dword c_icmp_message_maskreply::get_mask()
{
    return ntoh(message->mask);
}

void c_icmp_message_maskreply::set_mask(dword mask)
{
    message->mask = hton(mask);
}

c_icmp_message_traceroute::c_icmp_message_traceroute(c_icmp_header icmp_header)
{
    message = (s_icmp_message_traceroute *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_traceroute::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_traceroute::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_traceroute::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_traceroute::set_unused(word unused)
{
    message->unused = hton(unused);
}

word c_icmp_message_traceroute::get_outhopcount()
{
    return ntoh(message->outhopcount);
}

void c_icmp_message_traceroute::set_outhopcount(word outhopcount)
{
    message->outhopcount = hton(outhopcount);
}

word c_icmp_message_traceroute::get_rethopcount()
{
    return ntoh(message->rethopcount);
}

void c_icmp_message_traceroute::set_rethopcount(word rethopcount)
{
    message->rethopcount = hton(rethopcount);
}

dword c_icmp_message_traceroute::get_outlinkspeed()
{
    return ntoh(message->outlinkspeed);
}

void c_icmp_message_traceroute::set_outlinkspeed(dword outlinkspeed)
{
    message->outlinkspeed = hton(outlinkspeed);
}

dword c_icmp_message_traceroute::get_outlinkmtu()
{
    return ntoh(message->outlinkmtu);
}

void c_icmp_message_traceroute::set_outlinkmtu(dword outlinkmtu)
{
    message->outlinkmtu = hton(outlinkmtu);
}

c_icmp_message_converr::c_icmp_message_converr(c_icmp_header icmp_header)
{
    message = (s_icmp_message_converr *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

dword c_icmp_message_converr::get_pointer()
{
    return hton(message->pointer);
}

void c_icmp_message_converr::set_pointer(dword pointer)
{
    message->pointer = hton(pointer);
}

byte *c_icmp_message_converr::get_badpacket()
{
    return message->badpacket;
}

void c_icmp_message_converr::set_badpacket(byte *badpacket, u_int badpacket_len)
{
    memcpy(message->badpacket, badpacket, badpacket_len);
}

c_icmp_message_dnamerequest::c_icmp_message_dnamerequest(c_icmp_header icmp_header)
{
    message = (s_icmp_message_dnamerequest *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_dnamerequest::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_dnamerequest::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_dnamerequest::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_dnamerequest::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

c_icmp_message_dnamereply::c_icmp_message_dnamereply(c_icmp_header icmp_header)
{
    message = (s_icmp_message_dnamereply *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_dnamereply::get_id()
{
    return ntoh(message->id);
}

void c_icmp_message_dnamereply::set_id(word id)
{
    message->id = hton(id);
}

word c_icmp_message_dnamereply::get_seqnumber()
{
    return ntoh(message->seqnumber);
}

void c_icmp_message_dnamereply::set_seqnumber(word seqnumber)
{
    message->seqnumber = hton(seqnumber);
}

dword c_icmp_message_dnamereply::get_ttl()
{
    return ntoh(message->ttl);
}

void c_icmp_message_dnamereply::set_ttl(dword ttl)
{
    message->ttl = hton(ttl);
}

byte *c_icmp_message_dnamereply::get_names()
{
    return message->names;
}

void c_icmp_message_dnamereply::set_names(byte *names, u_int names_len)
{
    memcpy(message->names, names, names_len);
}

c_icmp_message_security::c_icmp_message_security(c_icmp_header icmp_header)
{
    message = (s_icmp_message_security *)(((byte *)icmp_header.get_header()) + ICMP_HEADER_LEN);
}

word c_icmp_message_security::get_unused()
{
    return ntoh(message->unused);
}

void c_icmp_message_security::set_unused(word unused)
{
    message->unused = hton(unused);
}

word c_icmp_message_security::get_pointer()
{
    return ntoh(message->pointer);
}

void c_icmp_message_security::set_pointer(word pointer)
{
    message->pointer = hton(pointer);
}

c_ip_header c_icmp_message_security::get_ipheader()
{
    return c_ip_header(&message->ipheader);
}

void c_icmp_message_security::set_ipheader(c_ip_header ipheader)
{
    memcpy(&message->ipheader, ipheader.get_header(), IP_HEADER_LEN);
}

byte *c_icmp_message_security::get_ipdata()
{
    return message->ipdata;
}

void c_icmp_message_security::set_ipdata(byte *ipdata)
{
    memcpy(message->ipdata, ipdata, 8);
}
