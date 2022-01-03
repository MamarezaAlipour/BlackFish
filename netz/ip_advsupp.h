#ifndef _NETZ_IP_ADVSUPP_H_
#define _NETZ_IP_ADVSUPP_H_

#include "ip_support.h"

class c_tcp_packet;
class c_udp_packet;
class c_icmp_packet;

class c_ip_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_ip_packet(dword, dword, word = 0, byte = 64, byte = 0, byte = 0);
    c_ip_packet(char *, char *, word = 0, byte = 64, byte = 0, byte = 0);

    void add_opt_eol();
    void add_opt_nop(u_int = 1);
    void add_opt_rr(dword *, u_int);
    void add_opt_timestamp(byte, byte, dword *, u_int);
    void add_opt_sec(byte, byte *, u_int);
    void add_opt_xsec(byte asiac, byte *, u_int);
    void add_opt_lsrr(dword *, u_int);
    void add_opt_ssrr(dword *, u_int);
    void add_opt_satid(word);
    void add_opt_pmtu(word);
    void add_opt_rmtu(word);
    void add_opt_generic(byte type, byte *, u_int);

    void add_data(byte *, u_int);
    void add_data(c_tcp_packet);
    void add_data(c_udp_packet);
    void add_data(c_icmp_packet);
    void add_data(c_ip_packet);

    void verify();

    int send();
};

#endif /* _NETZ_IP_ADVSUPP_H_ */
