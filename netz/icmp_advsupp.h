#ifndef _NETZ_ICMP_ADVSUPP_H_
#define _NETZ_ICMP_ADVSUPP_H_

#include "icmp_support.h"

class c_icmp_packet
{

protected:
    byte packet[64 * 1024];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_icmp_packet(byte, byte = 0);
    void verify();
};

class c_icmp_packet_echoreply : public c_icmp_packet
{
public:
    c_icmp_packet_echoreply(word = 0, word = 0, byte * = 0, u_int = 0);
};

class c_icmp_packet_unreach : public c_icmp_packet
{
public:
    c_icmp_packet_unreach(byte, c_ip_header, byte *);
};

class c_icmp_packet_sourcequench : public c_icmp_packet
{
public:
    c_icmp_packet_sourcequench(c_ip_header, byte *);
};

class c_icmp_packet_redirect : public c_icmp_packet
{
public:
    c_icmp_packet_redirect(byte, dword, c_ip_header, byte *);
};

class c_icmp_packet_echorequest : public c_icmp_packet
{
public:
    c_icmp_packet_echorequest(word = 0, word = 0, byte * = 0, u_int = 0);
};

class c_icmp_packet_routeradvert : public c_icmp_packet
{
public:
    c_icmp_packet_routeradvert(byte, byte, word, dword *, u_int);
};

class c_icmp_packet_routersolicit : public c_icmp_packet
{
public:
    c_icmp_packet_routersolicit();
};

class c_icmp_packet_timexceed : public c_icmp_packet
{
public:
    c_icmp_packet_timexceed(byte, c_ip_header, byte *);
};

class c_icmp_packet_paramprob : public c_icmp_packet
{
public:
    c_icmp_packet_paramprob(byte, byte, c_ip_header, byte *);
};

class c_icmp_packet_tsrequest : public c_icmp_packet
{
public:
    c_icmp_packet_tsrequest(word, word, dword, dword, dword);
};

class c_icmp_packet_tsreply : public c_icmp_packet
{
public:
    c_icmp_packet_tsreply(word, word, dword, dword, dword);
};

class c_icmp_packet_inforequest : public c_icmp_packet
{
public:
    c_icmp_packet_inforequest(word, word);
};

class c_icmp_packet_inforeply : public c_icmp_packet
{
public:
    c_icmp_packet_inforeply(word, word);
};

class c_icmp_packet_maskrequest : public c_icmp_packet
{
public:
    c_icmp_packet_maskrequest(word, word, dword);
};

class c_icmp_packet_maskreply : public c_icmp_packet
{
public:
    c_icmp_packet_maskreply(word, word, dword);
};

class c_icmp_packet_traceroute : public c_icmp_packet
{
public:
    c_icmp_packet_traceroute(word, word, word, dword, dword);
};

class c_icmp_packet_converr : public c_icmp_packet
{
public:
    c_icmp_packet_converr(byte, dword, byte *, u_int);
};

class c_icmp_packet_dnamerequest : public c_icmp_packet
{
public:
    c_icmp_packet_dnamerequest(word, word);
};

class c_icmp_packet_dnamereply : public c_icmp_packet
{
public:
    c_icmp_packet_dnamereply(word, word, dword, byte * = 0, u_int = 0);
};

class c_icmp_packet_security : public c_icmp_packet
{
public:
    c_icmp_packet_security(byte, word, c_ip_header, byte *);
};

#endif /* _NETZ_ICMP_ADVSUPP_H_ */
