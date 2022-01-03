#ifndef _NETZ_ENC_SUPPORT_H_
#define _NETZ_ENC_SUPPORT_H_

#include "enc.h"

/*
 * ENC interface header support class.
 */

class c_enc_header
{

protected:
    s_enc_header *header;

public:
    c_enc_header(byte *);
    c_enc_header(s_enc_header *);

    dword get_af();
    dword get_spi();
    dword get_flags();

    void set_af(dword);
    void set_spi(dword);
    void set_flags(dword);
};

#endif /* _NETZ_ENC_SUPPORT_H_ */
