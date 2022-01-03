#ifndef _NETZ_ICMP6_SUPPORT_H_
#define _NETZ_ICMP6_SUPPORT_H_

#include "icmp6.h"
#include "support.h"

class c_icmp6_header
{
protected:
     s_icmp6_header *header;

public:
     c_icmp6_header(byte *);
     s_icmp6_header *get_header();

     byte get_type();
     byte get_code();
     word get_cksum();

     void set_type(byte);
     void set_code(byte);
     void set_cksum(word);
};

class c_icmp6_pkttoobig
{
protected:
     s_icmp6_pkttoobig *body;

public:
     c_icmp6_pkttoobig(c_icmp6_header);

     dword get_mtu();

     void set_mtu(dword);
};

class c_icmp6_paramprob
{
protected:
     s_icmp6_paramprob *body;

public:
     c_icmp6_paramprob(c_icmp6_header);

     dword get_pointer();

     void set_pointer(dword);
};

class c_icmp6_echorequest
{
protected:
     s_icmp6_echorequest *body;

public:
     c_icmp6_echorequest(c_icmp6_header);

     word get_id();
     word get_seqnumber();

     void set_id(word);
     void set_seqnumber(word);
};

class c_icmp6_echoreply
{
protected:
     s_icmp6_echoreply *body;

public:
     c_icmp6_echoreply(c_icmp6_header);

     word get_id();
     word get_seqnumber();

     void set_id(word);
     void set_seqnumber(word);
};

class c_icmp6_routeradvert
{
protected:
     s_icmp6_routeradvert *body;

public:
     c_icmp6_routeradvert(c_icmp6_header);

     byte get_hoplimit();
     byte get_flags();
     byte get_flag_mac();
     byte get_flag_osc();
     word get_lifetime();
     dword get_reachtimer();
     dword get_retrtimer();

     void set_hoplimit(byte);
     void set_flags(byte);
     void set_flag_mac(byte = 1);
     void set_flag_osc(byte = 1);
     void set_lifetime(word);
     void set_reachtimer(dword);
     void set_retrtimer(dword);
};

class c_icmp6_nbsolicit
{
protected:
     s_icmp6_nbsolicit *body;

public:
     c_icmp6_nbsolicit(c_icmp6_header);

     byte get_target(u_int);
     byte *get_target();

     void set_target(u_int, byte);
     void set_target(byte *);
};

class c_icmp6_nbadvert
{
protected:
     s_icmp6_nbadvert *body;

public:
     c_icmp6_nbadvert(c_icmp6_header);

     byte get_flags();
     byte get_flag_router();
     byte get_flag_solicited();
     byte get_flag_override();
     byte get_target(u_int);
     byte *get_target();

     void set_flags(byte);
     void set_flag_router(byte = 1);
     void set_flag_solicited(byte = 1);
     void set_flag_override(byte = 1);
     void set_target(u_int, byte);
     void set_target(byte *);
};

class c_icmp6_redirect
{
protected:
     s_icmp6_redirect *body;

public:
     c_icmp6_redirect(c_icmp6_header);

     byte get_target(u_int);
     byte *get_target();
     byte get_dst(u_int);
     byte *get_dst();

     void set_target(u_int, byte);
     void set_target(byte *);
     void set_dst(u_int, byte);
     void set_dst(byte *);
};

class c_icmp6_routerrenum
{
protected:
     s_icmp6_routerrenum *body;

public:
     c_icmp6_routerrenum(c_icmp6_header);

     dword get_seqnumber();
     byte get_segnumber();
     byte get_flags();
     word get_maxdelay();

     void set_seqnumber(dword);
     void set_segnumber(byte);
     void set_flags(byte);
     void set_maxdelay(word);
};

#endif /* _NETZ_ICMP6_SUPPORT_H_ */
