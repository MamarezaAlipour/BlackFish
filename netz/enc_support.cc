#include "enc_support.h"
#include "support.h"

c_enc_header::c_enc_header(byte *enc_header)
{
    header = (s_enc_header *)enc_header;
}

c_enc_header::c_enc_header(s_enc_header *enc_header)
{
    header = enc_header;
}

dword c_enc_header::get_af()
{
    return ntoh(header->af);
}

void c_enc_header::set_af(dword af)
{
    header->af = hton(af);
}

dword c_enc_header::get_spi()
{
    return ntoh(header->spi);
}

void c_enc_header::set_spi(dword spi)
{
    header->spi = hton(spi);
}

dword c_enc_header::get_flags()
{
    return ntoh(header->flags);
}

void c_enc_header::set_flags(dword flags)
{
    header->flags = hton(flags);
}
