#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "ip6_support.h"
#include "support.h"
#include "cksum.h"

c_ip6_header::c_ip6_header(byte *ip6_header)
{
    header = (s_ip6_header *)ip6_header;
}

c_ip6_header::c_ip6_header(s_ip6_header *ip6_header)
{
    header = ip6_header;
}

byte c_ip6_header::get_ver()
{
    return bits(ntoh(header->vcf), IP6_VERSION_MASK);
}

void c_ip6_header::set_ver(byte ver)
{
    header->vcf = hton(bits(ntoh(header->vcf), IP6_VERSION_MASK, ver));
}

byte c_ip6_header::get_tclass()
{
    return bits(ntoh(header->vcf), IP6_TCLASS_MASK);
}

void c_ip6_header::set_tclass(byte tclass)
{
    header->vcf = hton(bits(ntoh(header->vcf), IP6_TCLASS_MASK, tclass));
}

dword c_ip6_header::get_flabel()
{
    return bits(ntoh(header->vcf), IP6_FLABEL_MASK);
}

void c_ip6_header::set_flabel(dword flabel)
{
    header->vcf = hton(bits(ntoh(header->vcf), IP6_FLABEL_MASK, flabel));
}

word c_ip6_header::get_plen()
{
    return ntoh(header->plen);
}

void c_ip6_header::set_plen(word plen)
{
    header->plen = hton(plen);
}

byte c_ip6_header::get_next()
{
    return ntoh(header->next);
}

void c_ip6_header::set_next(byte next)
{
    header->next = hton(next);
}

byte c_ip6_header::get_hlimit()
{
    return ntoh(header->hlimit);
}

void c_ip6_header::set_hlimit(byte hlimit)
{
    header->hlimit = hton(hlimit);
}

byte c_ip6_header::get_src(u_int n)
{
    return ntoh(header->src[n]);
}

void c_ip6_header::set_src(u_int n, byte srcbyte)
{
    header->src[n] = hton(srcbyte);
}

byte c_ip6_header::get_dst(u_int n)
{
    return ntoh(header->dst[n]);
}

void c_ip6_header::set_dst(u_int n, byte dstbyte)
{
    header->dst[n] = hton(dstbyte);
}

byte *c_ip6_header::get_src()
{
    return header->src;
}

void c_ip6_header::set_src(byte *src)
{
    memcpy(header->src, src, IP6_ADDR_LEN);
}

byte *c_ip6_header::get_dst()
{
    return header->dst;
}

void c_ip6_header::set_dst(byte *dst)
{
    memcpy(header->dst, dst, IP6_ADDR_LEN);
}

c_ip6p_header::c_ip6p_header(c_ip6_header ip6_header)
{
    memcpy(ip6p_header.src, ip6_header.get_src(), IP6_ADDR_LEN);
    memcpy(ip6p_header.dst, ip6_header.get_dst(), IP6_ADDR_LEN);
    ip6p_header.plen = hton(ip6_header.get_plen());
    ip6p_header.pad[0] = 0;
    ip6p_header.pad[1] = 0;
    ip6p_header.pad[2] = 0;
    ip6p_header.next = hton(ip6_header.get_next());
}

c_pseudo_header c_ip6p_header::get_pseudo_header()
{
    c_pseudo_header pseudo_header;

    memcpy(pseudo_header.header, (byte *)&ip6p_header, IP6P_HEADER_LEN);

    pseudo_header.header_len = IP6P_HEADER_LEN;
    pseudo_header.header_type = PSEUDO_HEADER_TYPE_IP6;

    return pseudo_header;
}
