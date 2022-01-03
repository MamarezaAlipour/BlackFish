#ifndef _NETZ_ARP_ADVSUPP_H_
#define _NETZ_ARP_ADVSUPP_H_

#include "arp_support.h"


class c_arp_packet
{
protected:

    byte packet[1024 * 64];

    u_int header_len;
    u_int packet_len;


public:

    byte* get_packet() { return packet; }
    u_int get_packet_len() { return packet_len; }


public:

    c_arp_packet(byte*, byte*, byte*, byte*, word, word = ARP_HRTYPE_ETHER,
        word = ARP_PRTYPE_IP, byte = ARP_HRLEN_ETHER, byte = ARP_PRLEN_IP);

    void verify();
};

#endif /* _NETZ_ARP_ADVSUPP_H_ */
