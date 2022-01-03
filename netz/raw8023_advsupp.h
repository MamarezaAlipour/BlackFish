#ifndef _NETZ_RAW8023_ADVSUPP_H_
#define _NETZ_RAW8023_ADVSUPP_H_

#include "raw8023_support.h"

class c_ip_packet;
struct pcap;

class c_raw8023_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_raw8023_packet(byte *, byte *, word = 0);

    // void add_data(c_ipx_packet);

    void verify();

    int send(string *);
    int send(pcap *);
};

#endif /* _NETZ_RAW8023_ADVSUPP_H_ */
