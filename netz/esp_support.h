#ifndef _NETZ_ESP_SUPPORT_H_
#define _NETZ_ESP_SUPPORT_H_

#include "esp.h"

/*
 * ESP protocol support class.
 */

class c_esp_header
{

protected:
    s_esp_header *header;

public:
    c_esp_header(byte *);
    c_esp_header(s_esp_header *);

    dword get_spi();
    dword get_seq();

    void set_spi(dword);
    void set_seq(dword);
};

#endif /* _NETZ_ESP_SUPPORT_H_ */
