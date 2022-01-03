#include "esp_support.h"
#include "support.h"

c_esp_header::c_esp_header(byte *esp_header)
{
    header = (s_esp_header *)esp_header;
}

c_esp_header::c_esp_header(s_esp_header *esp_header)
{
    header = esp_header;
}

dword c_esp_header::get_spi()
{
    return ntoh(header->spi);
}

void c_esp_header::set_spi(dword spi)
{
    header->spi = hton(spi);
}

dword c_esp_header::get_seq()
{
    return ntoh(header->seq);
}

void c_esp_header::set_seq(dword seq)
{
    header->seq = hton(seq);
}
