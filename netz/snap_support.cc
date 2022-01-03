#include "snap_support.h"
#include "support.h"

c_snap_header::c_snap_header(byte *snap_header)
{
    header = (s_snap_header *)snap_header;
}

c_snap_header::c_snap_header(s_snap_header *snap_header)
{
    header = (s_snap_header *)snap_header;
}

byte c_snap_header::get_oui(u_int n)
{
    return ntoh(header->oui[n]);
}

dword c_snap_header::get_oui()
{
    dword oui = (dword(ntoh(header->oui[0])) << 16) +
                (dword(ntoh(header->oui[1])) << 8) +
                (dword(ntoh(header->oui[2])) << 0);
    return oui;
}

void c_snap_header::set_oui(u_int n, byte oui)
{
    header->oui[n] = hton(oui);
}

void c_snap_header::set_oui(dword oui)
{
    header->oui[2] = hton(oui << rotation(0x000000FF));
    header->oui[1] = hton(oui << rotation(0x0000FF00));
    header->oui[0] = hton(oui << rotation(0x00FF0000));
}

word c_snap_header::get_type()
{
    return ntoh(header->type);
}

void c_snap_header::set_type(word type)
{
    header->type = hton(type);
}
