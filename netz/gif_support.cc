#include "gif_support.h"
#include "support.h"

c_gif_header::c_gif_header(byte *gif_header)
{
    header = (s_gif_header *)gif_header;
}

c_gif_header::c_gif_header(s_gif_header *gif_header)
{
    header = gif_header;
}

dword c_gif_header::get_af()
{
    return ntoh(header->af);
}

void c_gif_header::set_af(dword af)
{
    header->af = hton(af);
}
