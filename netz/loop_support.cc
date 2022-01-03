#include "loop_support.h"
#include "support.h"

c_loop_header::c_loop_header(byte *loop_header)
{
    header = (s_loop_header *)loop_header;
}

c_loop_header::c_loop_header(s_loop_header *loop_header)
{
    header = loop_header;
}

dword c_loop_header::get_af()
{
    return ntoh(header->af);
}

void c_loop_header::set_af(dword af)
{
    header->af = hton(af);
}
