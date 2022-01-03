#include "dhcp_support.h"
#include "support.h"

c_dhcp_header::c_dhcp_header(byte *dhcp_header)
{
    header = (s_dhcp_header *)dhcp_header;
}

c_dhcp_header::c_dhcp_header(s_dhcp_header *dhcp_header)
{
    header = dhcp_header;
}

byte c_dhcp_header::get_op()
{
    return ntoh(header->op);
}

byte c_dhcp_header::get_hrtype()
{
    return ntoh(header->hrtype);
}

byte c_dhcp_header::get_hrlen()
{
    return ntoh(header->hrlen);
}

byte c_dhcp_header::get_hops()
{
    return ntoh(header->hops);
}

dword c_dhcp_header::get_xid()
{
    return ntoh(header->xid);
}

word c_dhcp_header::get_secs()
{
    return ntoh(header->secs);
}

word c_dhcp_header::get_flags()
{
    return ntoh(header->flags);
}

byte c_dhcp_header::get_flag_b()
{
    return bits(get_flags(), DHCP_FLAG_B_MASK);
}

dword c_dhcp_header::get_ciaddr()
{
    return header->ciaddr;
}

dword c_dhcp_header::get_yiaddr()
{
    return header->yiaddr;
}

dword c_dhcp_header::get_siaddr()
{
    return header->siaddr;
}

dword c_dhcp_header::get_giaddr()
{
    return header->giaddr;
}

byte *c_dhcp_header::get_chaddr()
{
    return header->chaddr;
}

byte *c_dhcp_header::get_sname()
{
    return header->sname;
}

byte *c_dhcp_header::get_file()
{
    return header->file;
}
