#ifndef _NETZ_TCP_SUPPORT_H_
#define _NETZ_TCP_SUPPORT_H_

#include "tcp.h"

class c_tcp_header
{

protected:
    s_tcp_header *header;

public:
    c_tcp_header(byte *tcp_header);
    c_tcp_header(s_tcp_header *tcp_header);

    word get_sport();
    word get_dport();
    dword get_seq();
    dword get_ack();
    byte get_hlen();
    byte get_flags();
    word get_win();
    word get_cksum();
    word get_urp();

    byte get_flag_fin();
    byte get_flag_syn();
    byte get_flag_rst();
    byte get_flag_psh();
    byte get_flag_ack();
    byte get_flag_urg();
    byte get_flag_x();
    byte get_flag_y();

    void set_sport(word);
    void set_dport(word);
    void set_seq(dword);
    void set_ack(dword);
    void set_hlen(byte = sizeof(s_tcp_header));
    void set_flags(byte);
    void set_win(word);
    void set_cksum(word = 0);
    void set_urp(word);

    void set_flag_fin(byte = 1);
    void set_flag_syn(byte = 1);
    void set_flag_rst(byte = 1);
    void set_flag_psh(byte = 1);
    void set_flag_ack(byte = 1);
    void set_flag_urg(byte = 1);
    void set_flag_x(byte = 1);
    void set_flag_y(byte = 1);
};

/*
 * TCP options support
 */

/*
 * Generic TCP Option
 */

class c_tcpopt_generic
{
protected:
    s_tcpopt_generic *option;

public:
    c_tcpopt_generic(byte *);

    byte get_code();
    byte get_len();
    byte *get_data();

    void set_code(byte);
    void set_len(byte);
    void set_data(byte *, u_int);
};

/*
 * EOL - end of list (RFC 793)
 */

class c_tcpopt_eol
{
protected:
    s_tcpopt_eol *option;

public:
    c_tcpopt_eol(byte *);

    byte get_code();
    byte get_len();

    void set_code(byte = TCPOPT_EOL);
};

/*
 * NOP - no operation (RFC 793)
 */

class c_tcpopt_nop
{
protected:
    s_tcpopt_nop *option;

public:
    c_tcpopt_nop(byte *);

    byte get_code();
    byte get_len();

    void set_code(byte = TCPOPT_NOP);
};

/*
 * MSS - max segment size (RFC 793)
 */

class c_tcpopt_mss
{
protected:
    s_tcpopt_mss *option;

public:
    c_tcpopt_mss(byte *);

    byte get_code();
    byte get_len();
    word get_size();

    void set_code(byte = TCPOPT_MSS);
    void set_len(byte = TCPOPT_MSS_LEN);
    void set_size(word);
};

/*
 * WSCALE - window scale (RFC 1323)
 */

class c_tcpopt_wscale
{
protected:
    s_tcpopt_wscale *option;

public:
    c_tcpopt_wscale(byte *);

    byte get_code();
    byte get_len();
    byte get_scale();

    void set_code(byte = TCPOPT_WSCALE);
    void set_len(byte = TCPOPT_WSCALE_LEN);
    void set_scale(byte);
};

/*
 * SACKPERM - selective ack permited (RFC 2018)
 */

class c_tcpopt_sackperm
{
protected:
    s_tcpopt_sackperm *option;

public:
    c_tcpopt_sackperm(byte *);

    byte get_code();
    byte get_len();

    void set_code(byte = TCPOPT_SACKPERM);
    void set_len(byte = TCPOPT_SACKPERM_LEN);
};

/*
 * SACK - selective ack (RFC 2018)
 */

class c_tcpopt_sack
{
protected:
    s_tcpopt_sack *option;

public:
    c_tcpopt_sack(byte *);

    byte get_code();
    byte get_len();
    dword get_ledge(u_int);
    dword get_redge(u_int);

    void set_code(byte = TCPOPT_SACK);
    void set_len(byte);
    void set_ledge(u_int, dword);
    void set_redge(u_int, dword);
};

/*
 * ECHO - echo request (RFC 1072)
 */

class c_tcpopt_echo
{
protected:
    s_tcpopt_echo *option;

public:
    c_tcpopt_echo(byte *);

    byte get_code();
    byte get_len();
    dword get_info();

    void set_code(byte = TCPOPT_ECHO);
    void set_len(byte = TCPOPT_ECHO_LEN);
    void set_info(dword);
};

/*
 * ECHOREPLY - echo reply (RFC 1072)
 */

class c_tcpopt_echoreply
{
protected:
    s_tcpopt_echoreply *option;

public:
    c_tcpopt_echoreply(byte *);

    byte get_code();
    byte get_len();
    dword get_info();

    void set_code(byte = TCPOPT_ECHOREPLY);
    void set_len(byte = TCPOPT_ECHOREPLY_LEN);
    void set_info(dword);
};

/*
 * TIMESTAMP - timestamp (RFC 1323)
 */

class c_tcpopt_timestamp
{
protected:
    s_tcpopt_timestamp *option;

public:
    c_tcpopt_timestamp(byte *);

    byte get_code();
    byte get_len();
    dword get_tsval();
    dword get_tsecr();

    void set_code(byte = TCPOPT_TIMESTAMP);
    void set_len(byte = TCPOPT_TIMESTAMP_LEN);
    void set_tsval(dword);
    void set_tsecr(dword);
};

/*
 * POCPERM - poc permited (RFC 1693)
 */

class c_tcpopt_pocperm
{
protected:
    s_tcpopt_pocperm *option;

public:
    c_tcpopt_pocperm(byte *);

    byte get_code();
    byte get_len();

    void set_code(byte = TCPOPT_POCPERM);
    void set_len(byte = TCPOPT_POCPERM_LEN);
};

/*
 * POCSPROF - poc service profile (RFC 1693)
 */

class c_tcpopt_pocsprof
{
protected:
    s_tcpopt_pocsprof *option;

public:
    c_tcpopt_pocsprof(byte *);

    byte get_code();
    byte get_len();
    byte get_sflag();
    byte get_eflag();

    void set_code(byte = TCPOPT_POCSPROF);
    void set_len(byte = TCPOPT_POCSPROF_LEN);
    void set_sflag(byte);
    void set_eflag(byte);
};

/*
 * CC - cc (Braden)
 */

class c_tcpopt_cc
{
protected:
    s_tcpopt_cc *option;

public:
    c_tcpopt_cc(byte *);

    byte get_code();
    byte get_len();
    word get_segment();

    void set_code(byte = TCPOPT_CC);
    void set_len(byte = TCPOPT_CC_LEN);
    void set_segment(word);
};

/*
 * CCNEW - ccnew (Braden)
 */

class c_tcpopt_ccnew
{
protected:
    s_tcpopt_ccnew *option;

public:
    c_tcpopt_ccnew(byte *);

    byte get_code();
    byte get_len();
    word get_segment();

    void set_code(byte = TCPOPT_CCNEW);
    void set_len(byte = TCPOPT_CCNEW_LEN);
    void set_segment(word);
};

/*
 * CCECHO - ccecho (Braden)
 */

class c_tcpopt_ccecho
{
protected:
    s_tcpopt_ccecho *option;

public:
    c_tcpopt_ccecho(byte *);

    byte get_code();
    byte get_len();
    word get_segment();

    void set_code(byte = TCPOPT_CCECHO);
    void set_len(byte = TCPOPT_CCECHO_LEN);
    void set_segment(word);
};

/*
 * ALTCSR - alternative checksum request (RFC 1146)
 */

class c_tcpopt_altcsr
{
protected:
    s_tcpopt_altcsr *option;

public:
    c_tcpopt_altcsr(byte *);

    byte get_code();
    byte get_len();
    word get_cksum();

    void set_code(byte = TCPOPT_ALTCSR);
    void set_len(byte = TCPOPT_ALTCSR_LEN);
    void set_cksum(word);
};

/*
 * ALTCSD - alternative checksum data (RFC 1146)
 */

class c_tcpopt_altcsd
{
protected:
    s_tcpopt_altcsd *option;

public:
    c_tcpopt_altcsd(byte *);

    byte get_code();
    byte get_len();
    byte *get_data();

    void set_code(byte = TCPOPT_ALTCSD);
    void set_len(byte);
    void set_data(byte *, u_int);
};

/*
 * SIGNATURE - MD5 signature (RFC 2385)
 */

class c_tcpopt_signature
{
protected:
    s_tcpopt_signature *option;

public:
    c_tcpopt_signature(byte *);

    byte get_code();
    byte get_len();
    string *get_signature();

    void set_code(byte = TCPOPT_SIGNATURE);
    void set_len(byte = TCPOPT_SIGNATURE_LEN);
    void set_signature(string *);
};

#endif /* _NETZ_TCP_SUPPORT_H_ */
