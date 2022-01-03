#ifndef _NETZ_UDP_ADVSUPP_H_
#define _NETZ_UDP_ADVSUPP_H_

#include "udp_support.h"

struct c_pseudo_header;

class c_udp_packet
{

protected:
    byte packet[64 * 1024];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_udp_packet(word, word);

    void add_data(byte *, u_int);

    void verify();

    void verify(c_pseudo_header);
};

#endif /* _NETZ_UDP_ADVSUPP_H_ */
