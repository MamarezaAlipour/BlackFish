#include "llc_i_advsupp.h"

c_llc_i_packet::c_llc_i_packet(byte ssap, byte dsap, byte ns, byte nr, byte pf)
{
    c_llc_i_header header(packet);

    header.set_ssap(ssap);
    header.set_dsap(dsap);
    header.set_ctrl();
    header.set_ctrl_ns(ns);
    header.set_ctrl_nr(nr);
    header.set_ctrl_pf(pf);

    header_len = LLC_I_HEADER_LEN;
    packet_len = header_len;
}

void c_llc_i_packet::verify()
{
}
