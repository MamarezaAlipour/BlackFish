#ifndef _NETZ_ARP_SUPPORT_H_
#define _NETZ_ARP_SUPPORT_H_

#include "arp.h"

class c_arp_header
{
protected:
    s_arp_header *header;
    byte *sha;
    byte *spa;
    byte *tha;
    byte *tpa;

public:
    c_arp_header(byte *);
    c_arp_header(s_arp_header *);

    word get_hrtype();
    word get_prtype();
    byte get_hrlen();
    byte get_prlen();
    word get_operation();
    byte *get_sha();
    byte *get_spa();
    byte *get_tha();
    byte *get_tpa();

    void set_hrtype(word = 4);
    void set_prtype(word = 4);
    void set_hrlen(byte = 6);
    void set_prlen(byte = 6);
    void set_operation(word);
    void set_sha(byte *, u_int = 0);
    void set_spa(byte *, u_int = 0);
    void set_tha(byte *, u_int = 0);
    void set_tpa(byte *, u_int = 0);
};

#endif /* _NETZ_ARP_SUPPORT_H_ */
