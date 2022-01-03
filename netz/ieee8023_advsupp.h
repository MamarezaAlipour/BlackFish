#ifndef _NETZ_IEEE8023_ADVSUPP_H_
#define _NETZ_IEEE8023_ADVSUPP_H_

#include "ieee8023_support.h"

class c_ip_packet;
struct pcap;

class c_ieee8023_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_ieee8023_packet(byte *, byte *, word = 0);

    void add_data(byte *, u_int);

    void verify();

    int send(string *);
    int send(pcap *);
};

#endif /* _NETZ_IEEE8023_ADVSUPP_H_ */
