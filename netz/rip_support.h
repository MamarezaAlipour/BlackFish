#ifndef _NETZ_RIP_SUPPORT_H_
#define _NETZ_RIP_SUPPORT_H_

#include "rip.h"

/*
 * Rip protocol support class.
 */

class c_rip_entry;

class c_rip_header
{

protected:
    s_rip_header *header;

public:
    c_rip_header(byte *);
    c_rip_header(s_rip_header *);

    byte get_cmd();
    byte get_ver();
    word get_pad();

    void set_cmd(byte);
    void set_ver(byte);
    void set_pad(word = 0);
};

class c_rip_entry
{

protected:
    s_rip_entry *entry;

public:
    c_rip_entry(byte *);
    c_rip_entry(s_rip_entry *);

    word get_afi();
    word get_tag();
    dword get_ip();
    dword get_mask();
    dword get_nexthop();
    dword get_metric();

    void set_afi(word);
    void set_tag(word = 0);
    void set_ip(dword);
    void set_mask(dword = 0);
    void set_nexthop(dword = 0);
    void set_metric(dword);
};

class c_rip_authentry
{

protected:
    s_rip_authentry *authentry;

public:
    c_rip_authentry(byte *);
    c_rip_authentry(s_rip_authentry *);

    word get_id();
    word get_type();
    byte *get_key();
    word get_len();
    byte get_keyid();
    byte get_adlen();
    byte get_seq();

    void set_id(word = RIP_AUTHENTRY_ID);
    void set_type(word = RIP_AUTHTYPE_SIMPLE);
    void set_key(byte *);
    void set_len(word);
    void set_keyid(byte);
    void set_adlen(byte);
    void set_seq(byte);
};

class c_rip_md5entry
{

protected:
    s_rip_md5entry *md5entry;

public:
    c_rip_md5entry(byte *);
    c_rip_md5entry(s_rip_md5entry *);

    word get_id1();
    word get_id2();
    byte *get_key();

    void set_id1(word = 0xFFFF);
    void set_id2(word = 0x0001);
    void set_key(byte *);
};

#endif /* _NETZ_RIP_SUPPORT_H_ */
