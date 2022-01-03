#ifndef _NETZ_LLC_S_ADVSUPP_H_
#define _NETZ_LLC_S_ADVSUPP_H_

#include "llc_s_support.h"

class c_llc_s_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_llc_s_packet(byte, byte, byte, byte, byte);

    void verify();
};

#endif /* _NETZ_LLC_S_ADVSUPP_H_ */
