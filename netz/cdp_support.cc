#include "cdp_support.h"
#include "support.h"

c_cdp_header::c_cdp_header(byte *cdp_header)
{
    header = (s_cdp_header *)cdp_header;
}

c_cdp_header::c_cdp_header(s_cdp_header *cdp_header)
{
    header = cdp_header;
}

byte c_cdp_header::get_ver()
{
    return ntoh(header->ver);
}

byte c_cdp_header::get_ttl()
{
    return ntoh(header->ttl);
}

word c_cdp_header::get_cksum()
{
    return ntoh(header->cksum);
}

c_cdp_dheader::c_cdp_dheader(byte *cdp_dheader)
{
    header = (s_cdp_dheader *)cdp_dheader;
}

c_cdp_dheader::c_cdp_dheader(s_cdp_dheader *cdp_dheader)
{
    header = cdp_dheader;
}

word c_cdp_dheader::get_type()
{
    return ntoh(header->type);
}

word c_cdp_dheader::get_len()
{
    return ntoh(header->len);
}

string *c_cdp_dheader::get_devid()
{
    return (string *)header + CDP_DHEADER_LEN;
}
