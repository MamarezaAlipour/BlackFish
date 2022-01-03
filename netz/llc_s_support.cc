#include "llc_s_support.h"
#include "support.h"

c_llc_s_header::c_llc_s_header(byte *llc_s_header)
{
    header = (s_llc_s_header *)llc_s_header;
}

c_llc_s_header::c_llc_s_header(s_llc_s_header *llc_s_header)
{
    header = llc_s_header;
}

byte c_llc_s_header::get_dsap()
{
    return ntoh(header->dsap);
}

void c_llc_s_header::set_dsap(byte dsap)
{
    header->dsap = hton(dsap);
}

byte c_llc_s_header::get_dsap_ig()
{
    return bits(ntoh(header->dsap), LLC_DSAP_IG_MASK);
}

void c_llc_s_header::set_dsap_ig(byte ig)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_IG_MASK, ig));
}

byte c_llc_s_header::get_dsap_addr()
{
    return bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK);
}

void c_llc_s_header::set_dsap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->dsap), LLC_DSAP_ADDR_MASK, addr));
}

byte c_llc_s_header::get_ssap()
{
    return ntoh(header->ssap);
}

void c_llc_s_header::set_ssap(byte ssap)
{
    header->ssap = hton(ssap);
}

byte c_llc_s_header::get_ssap_cr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_CR_MASK);
}

void c_llc_s_header::set_ssap_cr(byte cr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_CR_MASK, cr));
}

byte c_llc_s_header::get_ssap_addr()
{
    return bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK);
}

void c_llc_s_header::set_ssap_addr(byte addr)
{
    header->dsap = hton(bits(ntoh(header->ssap), LLC_SSAP_ADDR_MASK, addr));
}

word c_llc_s_header::get_ctrl()
{
    return ntoh(header->ctrl);
}

void c_llc_s_header::set_ctrl(word ctrl)
{
    header->ctrl = hton(ctrl);
}

byte c_llc_s_header::get_ctrl_s()
{
    return bits(header->ctrl, LLC_S_S_MASK);
}

void c_llc_s_header::set_ctrl_s(byte s)
{
    header->ctrl = bits(header->ctrl, LLC_S_S_MASK, s);
}

byte c_llc_s_header::get_ctrl_nr()
{
    return bits(header->ctrl, LLC_S_NR_MASK);
}

void c_llc_s_header::set_ctrl_nr(byte nr)
{
    header->ctrl = bits(header->ctrl, LLC_S_NR_MASK, nr);
}

byte c_llc_s_header::get_ctrl_pf()
{
    return bits(header->ctrl, LLC_S_PF_MASK);
}

void c_llc_s_header::set_ctrl_pf(byte pf)
{
    header->ctrl = bits(header->ctrl, LLC_S_PF_MASK, pf);
}
