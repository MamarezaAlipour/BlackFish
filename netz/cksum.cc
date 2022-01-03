#include "cksum.h"

word cksum(byte *data, u_int data_len)
{
    dword cksum = 0;

    while (data_len > 1)
    {
        cksum += *((word *)data);

        if (cksum & 0x80000000)
        {
            cksum = (cksum & 0xFFFF) + (cksum >> 16);
        }

        data += 2;
        data_len -= 2;
    }

    if (data_len)
    {
        cksum += (word) * (byte *)data;
    }

    while (cksum >> 16)
    {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    return ~cksum;
}

word cksum(byte *data, u_int data_len, c_pseudo_header pseudo_header)
{
    dword cksum = 0;

    byte *pheader = pseudo_header.header;
    u_int pheader_len = pseudo_header.header_len;

    while (pheader_len)
    {
        cksum += *((word *)pheader);

        if (cksum & 0x80000000)
        {
            cksum = (cksum & 0xFFFF) + (cksum >> 16);
        }

        pheader += 2;
        pheader_len -= 2;
    }

    while (data_len > 1)
    {
        cksum += *((word *)data);

        if (cksum & 0x80000000)
        {
            cksum = (cksum & 0xFFFF) + (cksum >> 16);
        }

        data += 2;
        data_len -= 2;
    }

    if (data_len)
    {
        cksum += (word) * (byte *)data;
    }

    while (cksum >> 16)
    {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    return ~cksum;
}
