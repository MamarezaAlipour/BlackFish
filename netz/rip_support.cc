#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "rip_support.h"
#include "support.h"

c_rip_header::c_rip_header(byte *rip_header)
{
    header = (s_rip_header *)rip_header;
}

c_rip_header::c_rip_header(s_rip_header *rip_header)
{
    header = rip_header;
}

byte c_rip_header::get_cmd()
{
    return ntoh(header->cmd);
}

void c_rip_header::set_cmd(byte cmd)
{
    header->cmd = hton(cmd);
}

byte c_rip_header::get_ver()
{
    return ntoh(header->ver);
}

void c_rip_header::set_ver(byte ver)
{
    header->ver = hton(ver);
}

word c_rip_header::get_pad()
{
    return ntoh(header->pad);
}

void c_rip_header::set_pad(word pad)
{
    header->pad = hton(pad);
}

c_rip_entry::c_rip_entry(byte *rip_entry)
{
    entry = (s_rip_entry *)rip_entry;
}

c_rip_entry::c_rip_entry(s_rip_entry *rip_entry)
{
    entry = rip_entry;
}

word c_rip_entry::get_afi()
{
    return ntoh(entry->afi);
}

void c_rip_entry::set_afi(word afi)
{
    entry->afi = hton(afi);
}

word c_rip_entry::get_tag()
{
    return ntoh(entry->tag);
}

void c_rip_entry::set_tag(word tag)
{
    entry->tag = hton(tag);
}

dword c_rip_entry::get_ip()
{
    return entry->ip;
}

void c_rip_entry::set_ip(dword ip)
{
    entry->ip = hton(ip);
}

dword c_rip_entry::get_mask()
{
    return entry->mask;
}

void c_rip_entry::set_mask(dword mask)
{
    entry->mask = hton(mask);
}

dword c_rip_entry::get_nexthop()
{
    return entry->nexthop;
}

void c_rip_entry::set_nexthop(dword nexthop)
{
    entry->nexthop = hton(nexthop);
}

dword c_rip_entry::get_metric()
{
    return ntoh(entry->metric);
}

void c_rip_entry::set_metric(dword metric)
{
    entry->metric = hton(metric);
}

c_rip_authentry::c_rip_authentry(byte *rip_authentry)
{
    authentry = (s_rip_authentry *)rip_authentry;
}

c_rip_authentry::c_rip_authentry(s_rip_authentry *rip_authentry)
{
    authentry = rip_authentry;
}

word c_rip_authentry::get_id()
{
    return ntoh(authentry->id);
}

void c_rip_authentry::set_id(word id)
{
    authentry->id = hton(id);
}

word c_rip_authentry::get_type()
{
    return ntoh(authentry->type);
}

void c_rip_authentry::set_type(word type)
{
    authentry->type = hton(type);
}

byte *c_rip_authentry::get_key()
{
    return authentry->key;
}

void c_rip_authentry::set_key(byte *key)
{
    memcpy(authentry->key, key, 16);
}

word c_rip_authentry::get_len()
{
    return ntoh(authentry->md5.len);
}

void c_rip_authentry::set_len(word len)
{
    authentry->md5.len = hton(len);
}

byte c_rip_authentry::get_keyid()
{
    return ntoh(authentry->md5.keyid);
}

void c_rip_authentry::set_keyid(byte keyid)
{
    authentry->md5.keyid = hton(keyid);
}

byte c_rip_authentry::get_adlen()
{
    return ntoh(authentry->md5.adlen);
}

void c_rip_authentry::set_adlen(byte adlen)
{
    authentry->md5.adlen = hton(adlen);
}

byte c_rip_authentry::get_seq()
{
    return ntoh(authentry->md5.seq);
}

void c_rip_authentry::set_seq(byte seq)
{
    authentry->md5.seq = hton(seq);
}

c_rip_md5entry::c_rip_md5entry(byte *rip_md5entry)
{
    md5entry = (s_rip_md5entry *)rip_md5entry;
}

c_rip_md5entry::c_rip_md5entry(s_rip_md5entry *rip_md5entry)
{
    md5entry = rip_md5entry;
}

word c_rip_md5entry::get_id1()
{
    return ntoh(md5entry->id1);
}

void c_rip_md5entry::set_id1(word id1)
{
    md5entry->id1 = hton(id1);
}

word c_rip_md5entry::get_id2()
{
    return ntoh(md5entry->id1);
}

void c_rip_md5entry::set_id2(word id2)
{
    md5entry->id2 = hton(id2);
}

byte *c_rip_md5entry::get_key()
{
    return md5entry->key;
}

void c_rip_md5entry::set_key(byte *key)
{
    memcpy(md5entry->key, key, 16);
}
