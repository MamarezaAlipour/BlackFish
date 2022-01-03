#include "llc_i_support.h"
#include "support.h"

c_llc_i_header::c_llc_i_header(byte *llc_i_header)
{
    header = (s_llc_i_header *)llc_i_header;
}

c_llc_i_header::c_llc_i_header(s_llc_i_header *llc_i_header)
{
    header = llc_i_header;
}

byte c_llc_i_header::get_dsap()
{
    return ntoh(header->dsap);
}

void c_llc_i_header::set_dsap(byte dsap)
{
    header->dsap = hton(dsap);
}

byte c_llc_i_header::get_dsap_ig()
{
    return bits(ntoh(header->dsap), LLC_DSAP_IG_MASK);
}

void c_llc_i_header::set_dsap_ig(byte ig)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_IG_MASK, ig));
}

byte c_llc_i_header::get_dsap_addr()
{
    return bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK);
}

void c_llc_i_header::set_dsap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK, addr));
}

byte c_llc_i_header::get_ssap()
{
    return ntoh(header->ssap);
}

void c_llc_i_header::set_ssap(byte ssap)
{
    header->ssap = hton(ssap);
}

byte c_llc_i_header::get_ssap_cr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_CR_MASK);
}

void c_llc_i_header::set_ssap_cr(byte cr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_CR_MASK, cr));
}

byte c_llc_i_header::get_ssap_addr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK);
}

void c_llc_i_header::set_ssap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK, addr));
}

word c_llc_i_header::get_ctrl()
{
    return ntoh(header->ctrl);
}

void c_llc_i_header::set_ctrl(word ctrl)
{
    header->ctrl = hton(ctrl);
}

byte c_llc_i_header::get_ctrl_ns()
{
    return bits(header->ctrl, LLC_I_NS_MASK);
}

void c_llc_i_header::set_ctrl_ns(byte ns)
{
    header->ctrl = bits(header->ctrl, LLC_I_NS_MASK, ns);
}

byte c_llc_i_header::get_ctrl_nr()
{
    return bits(header->ctrl, LLC_I_NR_MASK);
}

void c_llc_i_header::set_ctrl_nr(byte nr)
{
    header->ctrl = bits(header->ctrl, LLC_I_NR_MASK, nr);
}

byte c_llc_i_header::get_ctrl_pf()
{
    return bits(header->ctrl, LLC_I_PF_MASK);
}

void c_llc_i_header::set_ctrl_pf(byte pf)
{
    header->ctrl = bits(header->ctrl, LLC_I_PF_MASK, pf);
}
