#include "llc_s_advsupp.h"

c_llc_s_packet::c_llc_s_packet(byte ssap, byte dsap, byte s, byte nr, byte pf)
{
    c_llc_s_header header(packet);

    header.set_ssap(ssap);
    header.set_dsap(dsap);
    header.set_ctrl();
    header.set_ctrl_s(s);
    header.set_ctrl_nr(nr);
    header.set_ctrl_pf(pf);

    header_len = LLC_S_HEADER_LEN;
    packet_len = header_len;
}

void c_llc_s_packet::verify()
{
}
