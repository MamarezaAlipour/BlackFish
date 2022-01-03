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
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ip_support.h"
#include "support.h"
#include "cksum.h"

/*
 * IP header support
 */

c_ip_header::c_ip_header(byte *ip_header)
{
    header = (s_ip_header *)ip_header;
}

c_ip_header::c_ip_header(s_ip_header *ip_header)
{
    header = (s_ip_header *)ip_header;
}

s_ip_header *c_ip_header::get_header()
{
    return header;
}

byte c_ip_header::get_ver()
{
    return bits(ntoh(header->vl), IP_VL_VER_MASK);
}

void c_ip_header::set_ver(byte ver)
{
    header->vl = hton(bits(ntoh(header->vl), IP_VL_VER_MASK, ver));
}

byte c_ip_header::get_hlen()
{
    return bits(ntoh(header->vl), IP_VL_HLEN_MASK) << 2;
}

void c_ip_header::set_hlen(byte hlen)
{
    header->vl = hton(bits(ntoh(header->vl), IP_VL_HLEN_MASK, hlen >> 2));
}

byte c_ip_header::get_tos()
{
    return ntoh(header->tos);
}

void c_ip_header::set_tos(byte tos)
{
    header->tos = hton(tos);
}

byte c_ip_header::get_tos_prec()
{
    return bits(ntoh(header->tos), IP_TOS_PREC_MASK);
}

void c_ip_header::set_tos_prec(byte prec)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_PREC_MASK, prec));
}

byte c_ip_header::get_tos_delay()
{
    return bits(ntoh(header->tos), IP_TOS_DELAY_MASK);
}

void c_ip_header::set_tos_delay(byte delay)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_DELAY_MASK, delay));
}

byte c_ip_header::get_tos_throughput()
{
    return bits(ntoh(header->tos), IP_TOS_THROUGHPUT_MASK);
}

void c_ip_header::set_tos_throughput(byte throughput)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_THROUGHPUT_MASK,
                            throughput));
}

byte c_ip_header::get_tos_reliability()
{
    return bits(ntoh(header->tos), IP_TOS_RELIABILITY_MASK);
}

void c_ip_header::set_tos_reliability(byte reliability)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_RELIABILITY_MASK,
                            reliability));
}

byte c_ip_header::get_tos_ectcap()
{
    return bits(ntoh(header->tos), IP_TOS_ECTCAP_MASK);
}

void c_ip_header::set_tos_ectcap(byte ectcap)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_ECTCAP_MASK, ectcap));
}

byte c_ip_header::get_tos_congestion()
{
    return bits(ntoh(header->tos), IP_TOS_CONGESTION_MASK);
}

void c_ip_header::set_tos_congestion(byte congestion)
{
    header->tos = hton(bits(ntoh(header->tos), IP_TOS_CONGESTION_MASK,
                            congestion));
}

word c_ip_header::get_len()
{
    return ntoh(header->len);
}

void c_ip_header::set_len(word len)
{
    header->len = hton(len);
}

word c_ip_header::get_id()
{
    return ntoh(header->id);
}

void c_ip_header::set_id(word id)
{
    header->id = hton(id);
}

word c_ip_header::get_frag()
{
    return ntoh(header->frag);
}

void c_ip_header::set_frag(word frag)
{
    header->frag = hton(frag);
}

byte c_ip_header::get_frag_rf()
{
    return bits(ntoh(header->frag), IP_FRAG_RF_MASK);
}

void c_ip_header::set_frag_rf(byte rf)
{
    header->frag = hton(bits(ntoh(header->frag), IP_FRAG_RF_MASK, rf));
}

byte c_ip_header::get_frag_df()
{
    return bits(ntoh(header->frag), IP_FRAG_DF_MASK);
}

void c_ip_header::set_frag_df(byte df)
{
    header->frag = hton(bits(ntoh(header->frag), IP_FRAG_DF_MASK, df));
}

byte c_ip_header::get_frag_mf()
{
    return bits(ntoh(header->frag), IP_FRAG_MF_MASK);
}

void c_ip_header::set_frag_mf(byte mf)
{
    header->frag = hton(bits(ntoh(header->frag), IP_FRAG_MF_MASK, mf));
}

word c_ip_header::get_frag_off()
{
    return bits(ntoh(header->frag), IP_FRAG_OFF_MASK);
}

void c_ip_header::set_frag_off(word off)
{
    header->frag = hton(bits(ntoh(header->frag), IP_FRAG_OFF_MASK, off));
}

byte c_ip_header::get_ttl()
{
    return ntoh(header->ttl);
}

void c_ip_header::set_ttl(byte ttl)
{
    header->ttl = ntoh(ttl);
}

byte c_ip_header::get_proto()
{
    return ntoh(header->proto);
}

void c_ip_header::set_proto(byte proto)
{
    header->proto = hton(proto);
}

word c_ip_header::get_cksum()
{
    return header->cksum;
}

void c_ip_header::set_cksum(word cksum)
{
    header->cksum = cksum;
}

dword c_ip_header::get_src()
{
    return ntoh(header->src);
}

void c_ip_header::set_src(dword src)
{
    header->src = hton(src);
}

void c_ip_header::set_src(string *src)
{
    header->src = conv_str_ip(src);
}

dword c_ip_header::get_dst()
{
    return ntoh(header->dst);
}

void c_ip_header::set_dst(dword dst)
{
    header->dst = hton(dst);
}

void c_ip_header::set_dst(string *dst)
{
    header->dst = conv_str_ip(dst);
}

/*
 * IP options support
 */

c_ipopt_generic::c_ipopt_generic(byte *ip_option)
{
    option = (s_ipopt_generic *)ip_option;
}

byte c_ipopt_generic::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_generic::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_generic::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_generic::set_len(byte len)
{
    option->len = hton(len);
}

byte *c_ipopt_generic::get_data()
{
    return option->data;
}

void c_ipopt_generic::set_data(byte *data, u_int len)
{
    memcpy(option->data, data, len);
}

c_ipopt_eol::c_ipopt_eol(byte *ip_option)
{
    option = (s_ipopt_eol *)ip_option;
}

byte c_ipopt_eol::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_eol::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_eol::get_len()
{
    return IPOPT_EOL_LEN;
}

c_ipopt_nop::c_ipopt_nop(byte *ip_option)
{
    option = (s_ipopt_nop *)ip_option;
}

byte c_ipopt_nop::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_nop::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_nop::get_len()
{
    return IPOPT_NOP_LEN;
}

c_ipopt_rr::c_ipopt_rr(byte *ip_option)
{
    option = (s_ipopt_rr *)ip_option;
}

byte c_ipopt_rr::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_rr::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_rr::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_rr::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_rr::get_ptr()
{
    return ntoh(option->ptr);
}

void c_ipopt_rr::set_ptr(byte ptr)
{
    option->ptr = hton(ptr);
}

dword c_ipopt_rr::get_ip(u_int n)
{
    return ntoh(option->ip[n]);
}

void c_ipopt_rr::set_ip(u_int n, dword ip)
{
    option->ip[n] = hton(ip);
}

c_ipopt_pmtu::c_ipopt_pmtu(byte *ip_option)
{
    option = (s_ipopt_pmtu *)ip_option;
}

byte c_ipopt_pmtu::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_pmtu::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_pmtu::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_pmtu::set_len(byte len)
{
    option->len = hton(len);
}

word c_ipopt_pmtu::get_mtu()
{
    return ntoh(option->mtu);
}

void c_ipopt_pmtu::set_mtu(word mtu)
{
    option->mtu = hton(mtu);
}

c_ipopt_rmtu::c_ipopt_rmtu(byte *ip_option)
{
    option = (s_ipopt_rmtu *)ip_option;
}

byte c_ipopt_rmtu::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_rmtu::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_rmtu::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_rmtu::set_len(byte len)
{
    option->len = hton(len);
}

word c_ipopt_rmtu::get_mtu()
{
    return ntoh(option->mtu);
}

void c_ipopt_rmtu::set_mtu(word mtu)
{
    option->mtu = hton(mtu);
}

c_ipopt_ts::c_ipopt_ts(byte *ip_option)
{
    option = (s_ipopt_ts *)ip_option;
}

byte c_ipopt_ts::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_ts::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_ts::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_ts::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_ts::get_ptr()
{
    return ntoh(option->ptr);
}

void c_ipopt_ts::set_ptr(byte ptr)
{
    option->ptr = hton(ptr);
}

byte c_ipopt_ts::get_flags()
{
    return bits(ntoh(option->ovfl), IPOPT_TS_OVFL_FLAGS_MASK);
}

void c_ipopt_ts::set_flags(byte flags)
{
    option->ovfl = hton(bits(ntoh(option->ovfl), IPOPT_TS_OVFL_FLAGS_MASK,
                             flags));
}

byte c_ipopt_ts::get_ovflow()
{
    return bits(ntoh(option->ovfl), IPOPT_TS_OVFL_OVFLOW_MASK);
}

void c_ipopt_ts::set_ovflow(byte ovflow)
{
    option->ovfl = hton(bits(ntoh(option->ovfl), IPOPT_TS_OVFL_OVFLOW_MASK,
                             ovflow));
}

dword c_ipopt_ts::get_ip(u_int n)
{
    dword ip;

    switch (get_flags())
    {
    case IPOPT_TS_TSANDADDR:
        ip = ntoh(option->tsandaddr[n].ip);
        break;

    case IPOPT_TS_PRESPEC:
        ip = ntoh(option->prespec[n].ip);
        break;
    }

    return ip;
}

void c_ipopt_ts::set_ip(u_int n, dword ip)
{
    switch (get_flags())
    {
    case IPOPT_TS_TSANDADDR:
        option->tsandaddr[n].ip = hton(ip);
        break;

    case IPOPT_TS_PRESPEC:
        option->prespec[n].ip = hton(ip);
        break;
    }
}

dword c_ipopt_ts::get_timestamp(u_int n)
{
    dword timestamp;

    switch (get_flags())
    {
    case IPOPT_TS_TSONLY:
        timestamp = ntoh(option->tsonly[n].timestamp);
        break;

    case IPOPT_TS_TSANDADDR:
        timestamp = ntoh(option->tsandaddr[n].timestamp);
        break;

    case IPOPT_TS_PRESPEC:
        timestamp = ntoh(option->prespec[n].timestamp);
        break;
    }

    return timestamp;
}

void c_ipopt_ts::set_timestamp(u_int n, dword timestamp)
{
    switch (get_flags())
    {
    case IPOPT_TS_TSONLY:
        option->tsonly[n].timestamp = hton(timestamp);
        break;

    case IPOPT_TS_TSANDADDR:
        option->tsandaddr[n].timestamp = hton(timestamp);
        break;

    case IPOPT_TS_PRESPEC:
        option->prespec[n].timestamp = hton(timestamp);
        break;
    }
}

c_ipopt_tr::c_ipopt_tr(byte *ip_option)
{
    option = (s_ipopt_tr *)ip_option;
}

byte c_ipopt_tr::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_tr::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_tr::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_tr::set_len(byte len)
{
    option->len = hton(len);
}

word c_ipopt_tr::get_id()
{
    return ntoh(option->id);
}

void c_ipopt_tr::set_id(word id)
{
    option->id = hton(id);
}

word c_ipopt_tr::get_ohcount()
{
    return ntoh(option->ohcount);
}

void c_ipopt_tr::set_ohcount(word ohcount)
{
    option->ohcount = hton(ohcount);
}

word c_ipopt_tr::get_rhcount()
{
    return ntoh(option->rhcount);
}

void c_ipopt_tr::set_rhcount(word rhcount)
{
    option->rhcount = hton(rhcount);
}

dword c_ipopt_tr::get_originator()
{
    return ntoh(option->originator);
}

void c_ipopt_tr::set_originator(dword originator)
{
    option->originator = hton(originator);
}

c_ipopt_sec::c_ipopt_sec(byte *ip_option)
{
    option = (s_ipopt_sec *)ip_option;
}

byte c_ipopt_sec::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_sec::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_sec::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_sec::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_sec::get_cl()
{
    return ntoh(option->cl);
}

void c_ipopt_sec::set_cl(byte cl)
{
    option->cl = hton(cl);
}

byte c_ipopt_sec::get_flags(u_int n)
{
    return ntoh(option->flags[n]);
}

void c_ipopt_sec::set_flags(u_int n, byte flags)
{
    option->flags[n] = hton(flags);
}

c_ipopt_lsrr::c_ipopt_lsrr(byte *ip_option)
{
    option = (s_ipopt_lsrr *)ip_option;
}

byte c_ipopt_lsrr::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_lsrr::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_lsrr::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_lsrr::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_lsrr::get_ptr()
{
    return ntoh(option->ptr);
}

void c_ipopt_lsrr::set_ptr(byte ptr)
{
    option->ptr = hton(ptr);
}

dword c_ipopt_lsrr::get_ip(u_int n)
{
    return ntoh(option->ip[n]);
}

void c_ipopt_lsrr::set_ip(u_int n, dword ip)
{
    option->ip[n] = hton(ip);
}

c_ipopt_xsec::c_ipopt_xsec(byte *ip_option)
{
    option = (s_ipopt_xsec *)ip_option;
}

byte c_ipopt_xsec::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_xsec::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_xsec::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_xsec::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_xsec::get_asiac()
{
    return ntoh(option->asiac);
}

void c_ipopt_xsec::set_asiac(byte asiac)
{
    option->asiac = hton(asiac);
}

byte c_ipopt_xsec::get_flags(u_int n)
{
    return ntoh(option->flags[n]);
}

void c_ipopt_xsec::set_flags(u_int n, byte flags)
{
    option->flags[n] = hton(flags);
}

c_ipopt_satid::c_ipopt_satid(byte *ip_option)
{
    option = (s_ipopt_satid *)ip_option;
}

byte c_ipopt_satid::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_satid::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_satid::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_satid::set_len(byte len)
{
    option->len = hton(len);
}

word c_ipopt_satid::get_id()
{
    return ntoh(option->id);
}

void c_ipopt_satid::set_id(word id)
{
    option->id = hton(id);
}

c_ipopt_ssrr::c_ipopt_ssrr(byte *ip_option)
{
    option = (s_ipopt_ssrr *)ip_option;
}

byte c_ipopt_ssrr::get_code()
{
    return ntoh(option->code);
}

void c_ipopt_ssrr::set_code(byte code)
{
    option->code = hton(code);
}

byte c_ipopt_ssrr::get_len()
{
    return ntoh(option->len);
}

void c_ipopt_ssrr::set_len(byte len)
{
    option->len = hton(len);
}

byte c_ipopt_ssrr::get_ptr()
{
    return ntoh(option->ptr);
}

void c_ipopt_ssrr::set_ptr(byte ptr)
{
    option->ptr = hton(ptr);
}

dword c_ipopt_ssrr::get_ip(u_int n)
{
    return ntoh(option->ip[n]);
}

void c_ipopt_ssrr::set_ip(u_int n, dword ip)
{
    option->ip[n] = hton(ip);
}

/*
 * IP pseudo header support
 */

c_ipp_header::c_ipp_header(c_ip_header ip_header)
{
    ipp_header.src = ip_header.get_src();
    ipp_header.dst = ip_header.get_dst();
    ipp_header.pad = 0;
    ipp_header.proto = hton(ip_header.get_proto());
    ipp_header.len = hton((word)(ip_header.get_len() - ip_header.get_hlen()));
}

c_ipp_header::c_ipp_header(byte *header)
{
    memcpy((byte *)&ipp_header, header, IPP_HEADER_LEN);
}

dword c_ipp_header::get_src()
{
    return ipp_header.src;
}

dword c_ipp_header::get_dst()
{
    return ipp_header.dst;
}

byte c_ipp_header::get_pad()
{
    return ipp_header.pad;
}

byte c_ipp_header::get_proto()
{
    return ntoh(ipp_header.proto);
}

word c_ipp_header::get_len()
{
    return ntoh(ipp_header.len);
}

c_pseudo_header c_ipp_header::get_pseudo_header()
{
    c_pseudo_header pseudo_header;

    memcpy(pseudo_header.header, (byte *)&ipp_header, IPP_HEADER_LEN);

    pseudo_header.header_len = IPP_HEADER_LEN;
    pseudo_header.header_type = PSEUDO_HEADER_TYPE_IP;

    return pseudo_header;
}
