#include "ethloop_support.h"
#include "support.h"

c_ethloop_header::c_ethloop_header(byte *ethloop_header)
{
    header = (s_ethloop_header *)ethloop_header;
}

c_ethloop_header::c_ethloop_header(s_ethloop_header *ethloop_header)
{
    header = ethloop_header;
}

byte c_ethloop_header::get_data(u_int n)
{
    return ntoh(header->data[n]);
}
