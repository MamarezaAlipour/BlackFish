#include "llc_u_advsupp.h"

c_llc_u_packet::c_llc_u_packet(byte ssap, byte dsap, byte m, byte pf)
{
    c_llc_u_header header(packet);

    header.set_ssap(ssap);
    header.set_dsap(dsap);
    header.set_ctrl();
    header.set_ctrl_m(m);
    header.set_ctrl_pf(pf);

    header_len = LLC_U_HEADER_LEN;
    packet_len = header_len;
}

void c_llc_u_packet::verify()
{
}
