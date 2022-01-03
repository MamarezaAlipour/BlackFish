#include "spx_support.h"

c_spx_header::c_spx_header(byte *spx_header)
{
    header = (s_spx_header *)spx_header;
}

c_spx_header::c_spx_header(s_spx_header *spx_header)
{
    header = spx_header;
}

byte c_spx_header::get_ccflags()
{
    return ntoh(header->ccflags);
}

void c_spx_header::set_ccflags(byte ccflags)
{
    header->ccflags = hton(ccflags);
}

byte c_spx_header::get_ccflag_eom()
{
    return bits(get_ccflags(), SPX_CCFLAGS_EOM);
}

void c_spx_header::set_ccflag_eom(byte flag)
{
    header->ccflags = hton(bits(ntoh(header->ccflags),
                                SPX_CCFLAGS_EOM, flag));
}

byte c_spx_header::get_ccflag_ack()
{
    return bits(get_ccflags(), SPX_CCFLAGS_ACK);
}

void c_spx_header::set_ccflag_ack(byte flag)
{
    header->ccflags = hton(bits(ntoh(header->ccflags),
                                SPX_CCFLAGS_ACK, flag));
}

byte c_spx_header::get_ccflag_sys()
{
    return bits(get_ccflags(), SPX_CCFLAGS_SYS);
}

void c_spx_header::set_ccflag_sys(byte flag)
{
    header->ccflags = hton(bits(ntoh(header->ccflags),
                                SPX_CCFLAGS_SYS, flag));
}

byte c_spx_header::get_dtype()
{
    return ntoh(header->dtype);
}

void c_spx_header::set_dtype(byte dtype)
{
    header->dtype = hton(dtype);
}

word c_spx_header::get_srcid()
{
    return ntoh(header->srcid);
}

void c_spx_header::set_srcid(word srcid)
{
    header->srcid = hton(srcid);
}

word c_spx_header::get_dstid()
{
    return ntoh(header->dstid);
}

void c_spx_header::set_dstid(word dstid)
{
    header->dstid = hton(dstid);
}

word c_spx_header::get_seq()
{
    return ntoh(header->seq);
}

void c_spx_header::set_seq(word seq)
{
    header->seq = hton(seq);
}

word c_spx_header::get_ack()
{
    return ntoh(header->ack);
}

void c_spx_header::set_ack(word ack)
{
    header->ack = hton(ack);
}

word c_spx_header::get_alloc()
{
    return ntoh(header->alloc);
}

void c_spx_header::set_alloc(word alloc)
{
    header->alloc = hton(alloc);
}
