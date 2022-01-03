#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "icmp6_support.h"

c_icmp6_header::c_icmp6_header(byte *icmp6_header)
{
    header = (s_icmp6_header *)icmp6_header;
}

s_icmp6_header *c_icmp6_header::get_header()
{
    return header;
}

byte c_icmp6_header::get_type()
{
    return ntoh(header->type);
}

void c_icmp6_header::set_type(byte type)
{
    header->type = hton(type);
}

byte c_icmp6_header::get_code()
{
    return ntoh(header->code);
}

void c_icmp6_header::set_code(byte code)
{
    header->code = hton(code);
}

word c_icmp6_header::get_cksum()
{
    return ntoh(header->cksum);
}

void c_icmp6_header::set_cksum(word cksum)
{
    header->cksum = hton(cksum);
}

c_icmp6_pkttoobig::c_icmp6_pkttoobig(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_pkttoobig *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

dword c_icmp6_pkttoobig::get_mtu()
{
    return ntoh(body->mtu);
}

void c_icmp6_pkttoobig::set_mtu(dword mtu)
{
    body->mtu = hton(mtu);
}

c_icmp6_paramprob::c_icmp6_paramprob(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_paramprob *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

dword c_icmp6_paramprob::get_pointer()
{
    return ntoh(body->pointer);
}

void c_icmp6_paramprob::set_pointer(dword pointer)
{
    body->pointer = hton(pointer);
}

c_icmp6_echorequest::c_icmp6_echorequest(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_echorequest *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

word c_icmp6_echorequest::get_id()
{
    return ntoh(body->id);
}

void c_icmp6_echorequest::set_id(word id)
{
    body->id = hton(id);
}

word c_icmp6_echorequest::get_seqnumber()
{
    return ntoh(body->seqnumber);
}

void c_icmp6_echorequest::set_seqnumber(word seqnumber)
{
    body->seqnumber = hton(seqnumber);
}

c_icmp6_echoreply::c_icmp6_echoreply(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_echoreply *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

word c_icmp6_echoreply::get_id()
{
    return ntoh(body->id);
}

void c_icmp6_echoreply::set_id(word id)
{
    body->id = hton(id);
}

word c_icmp6_echoreply::get_seqnumber()
{
    return ntoh(body->seqnumber);
}

void c_icmp6_echoreply::set_seqnumber(word seqnumber)
{
    body->seqnumber = hton(seqnumber);
}

c_icmp6_routeradvert::c_icmp6_routeradvert(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_routeradvert *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

byte c_icmp6_routeradvert::get_hoplimit()
{
    return ntoh(body->hoplimit);
}

void c_icmp6_routeradvert::set_hoplimit(byte hoplimit)
{
    body->hoplimit = hton(hoplimit);
}

byte c_icmp6_routeradvert::get_flags()
{
    return ntoh(body->flags);
}

void c_icmp6_routeradvert::set_flags(byte flags)
{
    body->flags = hton(flags);
}

byte c_icmp6_routeradvert::get_flag_mac()
{
    return bits(get_flags(), ICMP6_ROUTER_ADVERTISEMENT_FLAG_MAC_MASK);
}

void c_icmp6_routeradvert::set_flag_mac(byte flag)
{
    set_flags(bits(get_flags(), ICMP6_ROUTER_ADVERTISEMENT_FLAG_MAC_MASK, flag));
}

byte c_icmp6_routeradvert::get_flag_osc()
{
    return bits(get_flags(), ICMP6_ROUTER_ADVERTISEMENT_FLAG_OSC_MASK);
}

void c_icmp6_routeradvert::set_flag_osc(byte flag)
{
    set_flags(bits(get_flags(), ICMP6_ROUTER_ADVERTISEMENT_FLAG_OSC_MASK, flag));
}

word c_icmp6_routeradvert::get_lifetime()
{
    return ntoh(body->lifetime);
}

void c_icmp6_routeradvert::set_lifetime(word lifetime)
{
    body->lifetime = hton(lifetime);
}

dword c_icmp6_routeradvert::get_reachtimer()
{
    return ntoh(body->reachabletime);
}

void c_icmp6_routeradvert::set_reachtimer(dword reachabletime)
{
    body->reachabletime = hton(reachabletime);
}

dword c_icmp6_routeradvert::get_retrtimer()
{
    return ntoh(body->retranstimer);
}

void c_icmp6_routeradvert::set_retrtimer(dword retranstimer)
{
    body->retranstimer = hton(retranstimer);
}

c_icmp6_nbsolicit::c_icmp6_nbsolicit(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_nbsolicit *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

byte c_icmp6_nbsolicit::get_target(u_int n)
{
    return ntoh(body->target[n]);
}

void c_icmp6_nbsolicit::set_target(u_int n, byte targetbyte)
{
    body->target[n] = hton(targetbyte);
}

byte *c_icmp6_nbsolicit::get_target()
{
    return body->target;
}

void c_icmp6_nbsolicit::set_target(byte *target)
{
    memcpy(body->target, target, sizeof(body->target));
}

c_icmp6_nbadvert::c_icmp6_nbadvert(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_nbadvert *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

byte c_icmp6_nbadvert::get_flags()
{
    return ntoh(body->flags);
}

void c_icmp6_nbadvert::set_flags(byte flags)
{
    body->flags = hton(flags);
}

byte c_icmp6_nbadvert::get_flag_router()
{
    return bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER_MASK);
}

void c_icmp6_nbadvert::set_flag_router(byte flag)
{
    set_flags(bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER_MASK, flag));
}

byte c_icmp6_nbadvert::get_flag_solicited()
{
    return bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED_MASK);
}

void c_icmp6_nbadvert::set_flag_solicited(byte flag)
{
    set_flags(bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED_MASK, flag));
}

byte c_icmp6_nbadvert::get_flag_override()
{
    return bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE_MASK);
}

void c_icmp6_nbadvert::set_flag_override(byte flag)
{
    set_flags(bits(get_flags(), ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE_MASK, flag));
}

byte c_icmp6_nbadvert::get_target(u_int n)
{
    return ntoh(body->target[n]);
}

void c_icmp6_nbadvert::set_target(u_int n, byte targetbyte)
{
    body->target[n] = hton(targetbyte);
}

byte *c_icmp6_nbadvert::get_target()
{
    return body->target;
}

void c_icmp6_nbadvert::set_target(byte *target)
{
    memcpy(body->target, target, sizeof(body->target));
}

c_icmp6_redirect::c_icmp6_redirect(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_redirect *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

byte c_icmp6_redirect::get_target(u_int n)
{
    return ntoh(body->target[n]);
}

void c_icmp6_redirect::set_target(u_int n, byte targetbyte)
{
    body->target[n] = hton(targetbyte);
}

byte *c_icmp6_redirect::get_target()
{
    return body->target;
}

void c_icmp6_redirect::set_target(byte *target)
{
    memcpy(body->target, target, sizeof(body->target));
}

byte c_icmp6_redirect::get_dst(u_int n)
{
    return ntoh(body->target[n]);
}

void c_icmp6_redirect::set_dst(u_int n, byte dstbyte)
{
    body->dst[n] = hton(dstbyte);
}

byte *c_icmp6_redirect::get_dst()
{
    return body->dst;
}

void c_icmp6_redirect::set_dst(byte *dst)
{
    memcpy(body->dst, dst, sizeof(body->dst));
}

c_icmp6_routerrenum::c_icmp6_routerrenum(c_icmp6_header icmp6_header)
{
    body = (s_icmp6_routerrenum *)(((byte *)icmp6_header.get_header()) + ICMP6_HEADER_LEN);
}

dword c_icmp6_routerrenum::get_seqnumber()
{
    return ntoh(body->seqnumber);
}

void c_icmp6_routerrenum::set_seqnumber(dword seqnumber)
{
    body->seqnumber = hton(seqnumber);
}

byte c_icmp6_routerrenum::get_segnumber()
{
    return ntoh(body->segnumber);
}

void c_icmp6_routerrenum::set_segnumber(byte segnumber)
{
    body->segnumber = hton(segnumber);
}

byte c_icmp6_routerrenum::get_flags()
{
    return ntoh(body->flags);
}

void c_icmp6_routerrenum::set_flags(byte flags)
{
    body->flags = hton(flags);
}

word c_icmp6_routerrenum::get_maxdelay()
{
    return ntoh(body->maxdelay);
}

void c_icmp6_routerrenum::set_maxdelay(word maxdelay)
{
    body->maxdelay = hton(maxdelay);
}
