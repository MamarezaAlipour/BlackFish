#include "llc_u_support.h"
#include "support.h"

c_llc_u_header::c_llc_u_header(byte *llc_u_header)
{
    header = (s_llc_u_header *)llc_u_header;
}

c_llc_u_header::c_llc_u_header(s_llc_u_header *llc_u_header)
{
    header = llc_u_header;
}

byte c_llc_u_header::get_dsap()
{
    return ntoh(header->dsap);
}

void c_llc_u_header::set_dsap(byte dsap)
{
    header->dsap = hton(dsap);
}

byte c_llc_u_header::get_dsap_ig()
{
    return bits(ntoh(header->dsap), LLC_DSAP_IG_MASK);
}

void c_llc_u_header::set_dsap_ig(byte ig)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_IG_MASK, ig));
}

byte c_llc_u_header::get_dsap_addr()
{
    return bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK);
}

void c_llc_u_header::set_dsap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK, addr));
}

byte c_llc_u_header::get_ssap()
{
    return ntoh(header->ssap);
}

void c_llc_u_header::set_ssap(byte ssap)
{
    header->ssap = hton(ssap);
}

byte c_llc_u_header::get_ssap_cr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_CR_MASK);
}

void c_llc_u_header::set_ssap_cr(byte cr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_CR_MASK, cr));
}

byte c_llc_u_header::get_ssap_addr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK);
}

void c_llc_u_header::set_ssap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK, addr));
}

byte c_llc_u_header::get_ctrl()
{
    return ntoh(header->ctrl);
}

void c_llc_u_header::set_ctrl(byte ctrl)
{
    header->ctrl = hton(ctrl);
}

byte c_llc_u_header::get_ctrl_m()
{
    return bits(header->ctrl, LLC_U_M_MASK);
}

void c_llc_u_header::set_ctrl_m(byte m)
{
    header->ctrl = bits(header->ctrl, LLC_U_M_MASK, m);
}

byte c_llc_u_header::get_ctrl_pf()
{
    return bits(header->ctrl, LLC_U_PF_MASK);
}

void c_llc_u_header::set_ctrl_pf(byte pf)
{
    header->ctrl = bits(header->ctrl, LLC_U_PF_MASK, pf);
}
