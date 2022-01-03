#ifndef _NETZ_TCP_ADVSUPP_H_
#define _NETZ_TCP_ADVSUPP_H_

#include "tcp_support.h"

struct c_pseudo_header;

class c_tcp_packet
{

protected:
    byte packet[64 * 1024];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_tcp_packet(word sport, word dport, dword seq = 0, dword ack = 0,
                 byte flags = 0, word win = 0, word urp = 0);

    void add_opt_eol();

    void add_opt_nop(u_int = 1);

    void add_opt_mss(word = 536);

    void add_opt_wscale(byte);

    void add_opt_sackperm();

    void add_opt_sack(dword *, u_int);

    void add_opt_echo(dword);

    void add_opt_echoreply(dword);

    void add_opt_timestamp(dword, dword);

    void add_opt_pocperm();

    void add_opt_pocsprof(byte, byte);

    void add_opt_cc(dword);

    void add_opt_ccnew(dword);

    void add_opt_ccecho(dword);

    void add_opt_altcsr(word);

    void add_opt_altcsd(byte *, u_int);

    void add_opt_signature(string *);

    void add_opt_generic(byte, byte *, u_int);

    void add_data(byte *data, u_int data_len);

    void verify();

    void verify(c_pseudo_header);
};

#endif /* _NETZ_TCP_ADVSUPP_H_ */
