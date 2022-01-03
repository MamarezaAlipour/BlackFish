#ifndef _NETZ_LLC_I_ADVSUPP_H_
#define _NETZ_LLC_I_ADVSUPP_H_

#include "llc_i_support.h"

class c_llc_i_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_llc_i_packet(byte, byte, byte, byte, byte);

    void verify();
};

#endif /* _NETZ_LLC_I_ADVSUPP_H_ */
