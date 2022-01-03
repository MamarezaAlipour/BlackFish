#include "arp_advsupp.h"


c_arp_packet::c_arp_packet(byte* sha, byte* spa, byte* tha, byte* tpa,
    word operation, word hrtype, word prtype, byte hrlen, byte prlen)
{
    c_arp_header header(packet);

    header.set_operation(operation);
    header.set_hrtype(hrtype);
    header.set_prtype(prtype);
    header.set_hrlen(hrlen);
    header.set_prlen(prlen); 
    header.set_sha(sha);
    header.set_spa(spa); 
    header.set_tha(tha);
    header.set_tpa(tpa);

    header_len = ARP_HEADER_LEN;
    packet_len = header_len + 2 * (hrlen + prlen);    
}


void c_arp_packet::verify()
{

}

