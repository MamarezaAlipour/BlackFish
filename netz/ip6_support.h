#ifndef _NETZ_IP6_SUPPORT_H_
#define _NETZ_IP6_SUPPORT_H_

#include "ip6.h"

class c_pseudo_header;

class c_ip6_header
{
protected:
    s_ip6_header *header;

public:
    c_ip6_header(byte *);
    c_ip6_header(s_ip6_header *);

    byte get_ver();
    byte get_tclass();
    dword get_flabel();
    word get_plen();
    byte get_next();
    byte get_hlimit();
    byte get_src(u_int);
    byte *get_src();
    byte get_dst(u_int);
    byte *get_dst();

    void set_ver(byte);
    void set_tclass(byte);
    void set_flabel(dword);
    void set_plen(word);
    void set_next(byte);
    void set_hlimit(byte);
    void set_src(byte *);
    void set_src(u_int, byte);
    void set_dst(byte *);
    void set_dst(u_int, byte);
};

class c_ip6p_header
{
protected:
    s_ip6p_header ip6p_header;

public:
    c_ip6p_header(c_ip6_header);

    c_pseudo_header get_pseudo_header();
};

#endif /* _NETZ_IP6_SUPPORT_H_ */
