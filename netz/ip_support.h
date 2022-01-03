#ifndef _NETZ_IP_SUPPORT_H_
#define _NETZ_IP_SUPPORT_H_

#include "ip.h"

class c_pseudo_header;

/*
 * IP header support
 */

class c_ip_header
{
protected:
    s_ip_header *header;

public:
    c_ip_header(byte *);
    c_ip_header(s_ip_header *);

    s_ip_header *get_header();

    byte get_ver();
    byte get_hlen();
    byte get_tos();
    byte get_tos_prec();
    byte get_tos_delay();
    byte get_tos_throughput();
    byte get_tos_reliability();
    byte get_tos_ectcap();
    byte get_tos_congestion();
    word get_len();
    word get_id();
    word get_frag();
    byte get_frag_rf();
    byte get_frag_df();
    byte get_frag_mf();
    word get_frag_off();
    byte get_ttl();
    byte get_proto();
    word get_cksum();
    dword get_src();
    dword get_dst();

    void set_ver(byte = 4);
    void set_hlen(byte = sizeof(s_ip_header));
    void set_tos(byte = 0);
    void set_tos_prec(byte);
    void set_tos_delay(byte);
    void set_tos_throughput(byte);
    void set_tos_reliability(byte);
    void set_tos_ectcap(byte);
    void set_tos_congestion(byte);
    void set_len(word = sizeof(s_ip_header));
    void set_id(word = 0);
    void set_frag(word = 0);
    void set_frag_rf(byte);
    void set_frag_df(byte);
    void set_frag_mf(byte);
    void set_frag_off(word);
    void set_ttl(byte = 64);
    void set_proto(byte = 0);
    void set_cksum(word = 0);
    void set_src(dword);
    void set_src(string *);
    void set_dst(dword);
    void set_dst(string *);
};

/*
 * IP options support
 */

class c_ipopt_generic
{
protected:
    s_ipopt_generic *option;

public:
    c_ipopt_generic(byte *);

    byte get_code();
    byte get_len();
    byte *get_data();

    void set_code(byte code);
    void set_len(byte len);
    void set_data(byte *, u_int);
};

class c_ipopt_eol
{
protected:
    s_ipopt_eol *option;

public:
    c_ipopt_eol(byte *);

    byte get_code();
    byte get_len();

    void set_code(byte = IPOPT_EOL);
};

class c_ipopt_nop
{
protected:
    s_ipopt_nop *option;

public:
    c_ipopt_nop(byte *);
    byte get_code();
    byte get_len();

    void set_code(byte = IPOPT_NOP);
};

class c_ipopt_rr
{
protected:
    s_ipopt_rr *option;

public:
    c_ipopt_rr(byte *);

    byte get_code();
    byte get_len();
    byte get_ptr();
    dword get_ip(u_int);

    void set_code(byte = IPOPT_RR);
    void set_len(byte = IPOPT_RR_LEN);
    void set_ptr(byte);
    void set_ip(u_int, dword);
};

class c_ipopt_pmtu
{
protected:
    s_ipopt_pmtu *option;

public:
    c_ipopt_pmtu(byte *);

    byte get_code();
    byte get_len();
    word get_mtu();

    void set_code(byte = IPOPT_PMTU);
    void set_len(byte = IPOPT_PMTU_LEN);
    void set_mtu(word);
};

class c_ipopt_rmtu
{
protected:
    s_ipopt_rmtu *option;

public:
    c_ipopt_rmtu(byte *);

    byte get_code();
    byte get_len();
    word get_mtu();

    void set_code(byte = IPOPT_RMTU);
    void set_len(byte = IPOPT_RMTU_LEN);
    void set_mtu(word);
};

class c_ipopt_ts
{
protected:
    s_ipopt_ts *option;

public:
    c_ipopt_ts(byte *);

    byte get_code();
    byte get_len();
    byte get_ptr();
    byte get_flags();
    byte get_ovflow();
    dword get_ip(u_int);
    dword get_timestamp(u_int);

    void set_code(byte = IPOPT_TS);
    void set_len(byte = IPOPT_TS_LEN);
    void set_ptr(byte);
    void set_flags(byte);
    void set_ovflow(byte);
    void set_ip(u_int, dword);
    void set_timestamp(u_int, dword);
};

class c_ipopt_tr
{
protected:
    s_ipopt_tr *option;

public:
    c_ipopt_tr(byte *);

    byte get_code();
    byte get_len();
    word get_id();
    word get_ohcount();
    word get_rhcount();
    dword get_originator();

    void set_code(byte = IPOPT_TR);
    void set_len(byte = IPOPT_TR_LEN);
    void set_id(word);
    void set_ohcount(word);
    void set_rhcount(word);
    void set_originator(dword);
};

class c_ipopt_sec
{
protected:
    s_ipopt_sec *option;

public:
    c_ipopt_sec(byte *);

    byte get_code();
    byte get_len();
    byte get_cl();
    byte get_flags(u_int);

    void set_code(byte = IPOPT_SEC);
    void set_len(byte = IPOPT_SEC_LEN);
    void set_cl(byte);
    void set_flags(u_int, byte);
};

class c_ipopt_lsrr
{
protected:
    s_ipopt_lsrr *option;

public:
    c_ipopt_lsrr(byte *);

    byte get_code();
    byte get_len();
    byte get_ptr();
    dword get_ip(u_int);

    void set_code(byte = IPOPT_LSRR);
    void set_len(byte = IPOPT_LSRR_LEN);
    void set_ptr(byte);
    void set_ip(u_int, dword);
};

class c_ipopt_xsec
{
protected:
    s_ipopt_xsec *option;

public:
    c_ipopt_xsec(byte *);

    byte get_code();
    byte get_len();
    byte get_asiac();
    byte get_flags(u_int);

    void set_code(byte = IPOPT_XSEC);
    void set_len(byte = IPOPT_XSEC_LEN);
    void set_asiac(byte);
    void set_flags(u_int, byte);
};

class c_ipopt_satid
{
protected:
    s_ipopt_satid *option;

public:
    c_ipopt_satid(byte *);

    byte get_code();
    byte get_len();
    word get_id();

    void set_code(byte = IPOPT_SATID);
    void set_len(byte = IPOPT_SATID_LEN);
    void set_id(word);
};

class c_ipopt_ssrr
{
protected:
    s_ipopt_ssrr *option;

public:
    c_ipopt_ssrr(byte *);

    byte get_code();
    byte get_len();
    byte get_ptr();
    dword get_ip(u_int);

    void set_code(byte = IPOPT_SSRR);
    void set_len(byte = IPOPT_SSRR_LEN);
    void set_ptr(byte);
    void set_ip(u_int, dword);
};

/*
 * IP pseudo header support
 */

class c_ipp_header
{
protected:
    s_ipp_header ipp_header;

public:
    c_ipp_header(c_ip_header);
    c_ipp_header(byte *);

    dword get_src();
    dword get_dst();
    byte get_pad();
    byte get_proto();
    word get_len();

    c_pseudo_header get_pseudo_header();
};

#endif /* _NETZ_IP_SUPPORT_H_ */
