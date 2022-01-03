#ifndef _NETZ_ETHER_ADVSUPP_H_
#define _NETZ_ETHER_ADVSUPP_H_

#include "ether_support.h"

class c_ip_packet;
class c_arp_packet;
struct pcap;

class c_ether_packet
{
protected:
    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;

public:
    byte *get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }

public:
    c_ether_packet(byte *, byte *, word = ETHER_TYPE_MIN);

    void add_data(byte *, u_int);
    void add_data(c_ip_packet);
    void add_data(c_arp_packet);

    void verify();

    int send(string *);
    int send(pcap *);
};

#endif /* _NETZ_ETHER_ADVSUPP_H_ */
