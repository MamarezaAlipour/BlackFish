#ifndef _NETZ_ICMP_SUPPORT_H_
#define _NETZ_ICMP_SUPPORT_H_

#include "icmp.h"
#include "ip_support.h"

class c_icmp_header
{
protected:
    s_icmp_header *header;

public:
    c_icmp_header(byte *);
    s_icmp_header *get_header();

    byte get_type();
    byte get_code();
    word get_cksum();

    void set_type(byte);
    void set_code(byte = 0);
    void set_cksum(word = 0);
};

class c_icmp_message_echoreply
{
protected:
    s_icmp_message_echoreply *message;

public:
    c_icmp_message_echoreply(c_icmp_header);

    word get_id();
    word get_seqnumber();
    byte *get_data();

    void set_id(word);
    void set_seqnumber(word);
    void set_data(byte *, u_int);
};

class c_icmp_message_unreach
{
protected:
    s_icmp_message_unreach *message;

public:
    c_icmp_message_unreach(c_icmp_header);

    dword get_unused();
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_unused(dword = 0);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

class c_icmp_message_sourcequench
{
protected:
    s_icmp_message_sourcequench *message;

public:
    c_icmp_message_sourcequench(c_icmp_header);

    dword get_unused();
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_unused(dword = 0);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

class c_icmp_message_redirect
{
protected:
    s_icmp_message_redirect *message;

public:
    c_icmp_message_redirect(c_icmp_header);

    dword get_gateway();
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_gateway(dword);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

class c_icmp_message_echorequest
{
protected:
    s_icmp_message_echorequest *message;

public:
    c_icmp_message_echorequest(c_icmp_header);

    word get_id();
    word get_seqnumber();
    byte *get_data();

    void set_id(word);
    void set_seqnumber(word);
    void set_data(byte *, u_int);
};

class c_icmp_message_routeradvert
{
protected:
    s_icmp_message_routeradvert *message;

public:
    c_icmp_message_routeradvert(c_icmp_header);

    byte get_addrnumber();
    byte get_addrentrysize();
    word get_lifetime();
    dword get_address(u_int);
    dword get_plevel(u_int);

    void set_addrnumber(byte);
    void set_addrentrysize(byte);
    void set_lifetime(word);
    void set_address(u_int, dword);
    void set_plevel(u_int, dword);
};

class c_icmp_message_routersolicit
{
protected:
    s_icmp_message_routersolicit *message;

public:
    c_icmp_message_routersolicit(c_icmp_header);

    dword get_unused();

    void set_unused(dword = 0);
};

class c_icmp_message_timexceed
{
protected:
    s_icmp_message_timexceed *message;

public:
    c_icmp_message_timexceed(c_icmp_header);

    dword get_unused();
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_unused(dword = 0);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

class c_icmp_message_paramprob
{
protected:
    s_icmp_message_paramprob *message;

public:
    c_icmp_message_paramprob(c_icmp_header);

    byte get_pointer();
    byte get_unused(u_int);
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_pointer(byte);
    void set_unused(u_int, byte = 0);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

class c_icmp_message_tsrequest
{
protected:
    s_icmp_message_tsrequest *message;

public:
    c_icmp_message_tsrequest(c_icmp_header);

    word get_id();
    word get_seqnumber();
    dword get_originate();
    dword get_receive();
    dword get_transmit();

    void set_id(word);
    void set_seqnumber(word);
    void set_originate(dword);
    void set_receive(dword);
    void set_transmit(dword);
};

class c_icmp_message_tsreply
{
protected:
    s_icmp_message_tsreply *message;

public:
    c_icmp_message_tsreply(c_icmp_header);

    word get_id();
    word get_seqnumber();
    dword get_originate();
    dword get_receive();
    dword get_transmit();

    void set_id(word);
    void set_seqnumber(word);
    void set_originate(dword);
    void set_receive(dword);
    void set_transmit(dword);
};

class c_icmp_message_inforequest
{
protected:
    s_icmp_message_inforequest *message;

public:
    c_icmp_message_inforequest(c_icmp_header);

    word get_id();
    word get_seqnumber();

    void set_id(word);
    void set_seqnumber(word);
};

class c_icmp_message_inforeply
{
protected:
    s_icmp_message_inforeply *message;

public:
    c_icmp_message_inforeply(c_icmp_header);

    word get_id();
    word get_seqnumber();

    void set_id(word);
    void set_seqnumber(word);
};

class c_icmp_message_maskrequest
{
protected:
    s_icmp_message_maskrequest *message;

public:
    c_icmp_message_maskrequest(c_icmp_header);

    word get_id();
    word get_seqnumber();
    dword get_mask();

    void set_id(word);
    void set_seqnumber(word);
    void set_mask(dword);
};

class c_icmp_message_maskreply
{
protected:
    s_icmp_message_maskreply *message;

public:
    c_icmp_message_maskreply(c_icmp_header);

    word get_id();
    word get_seqnumber();
    dword get_mask();

    void set_id(word);
    void set_seqnumber(word);
    void set_mask(dword);
};

class c_icmp_message_traceroute
{
protected:
    s_icmp_message_traceroute *message;

public:
    c_icmp_message_traceroute(c_icmp_header);

    word get_id();
    word get_unused();
    word get_outhopcount();
    word get_rethopcount();
    dword get_outlinkspeed();
    dword get_outlinkmtu();

    void set_id(word);
    void set_unused(word = 0);
    void set_outhopcount(word);
    void set_rethopcount(word);
    void set_outlinkspeed(dword);
    void set_outlinkmtu(dword);
};

class c_icmp_message_converr
{
protected:
    s_icmp_message_converr *message;

public:
    c_icmp_message_converr(c_icmp_header);

    dword get_pointer();
    byte *get_badpacket();

    void set_pointer(dword);
    void set_badpacket(byte *, u_int);
};

class c_icmp_message_dnamerequest
{
protected:
    s_icmp_message_dnamerequest *message;

public:
    c_icmp_message_dnamerequest(c_icmp_header);

    word get_id();
    word get_seqnumber();

    void set_id(word);
    void set_seqnumber(word);
};

class c_icmp_message_dnamereply
{
protected:
    s_icmp_message_dnamereply *message;

public:
    c_icmp_message_dnamereply(c_icmp_header);

    word get_id();
    word get_seqnumber();
    dword get_ttl();
    byte *get_names();

    void set_id(word);
    void set_seqnumber(word);
    void set_ttl(dword);
    void set_names(byte *, u_int);
};

class c_icmp_message_security
{
protected:
    s_icmp_message_security *message;

public:
    c_icmp_message_security(c_icmp_header);

    word get_unused();
    word get_pointer();
    c_ip_header get_ipheader();
    byte *get_ipdata();

    void set_unused(word = 0);
    void set_pointer(word);
    void set_ipheader(c_ip_header);
    void set_ipdata(byte *);
};

#endif /* _NETZ_ICMP_SUPPORT_H_ */
