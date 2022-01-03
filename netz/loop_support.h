#ifndef _NETZ_LOOP_SUPPORT_H_
#define _NETZ_LOOP_SUPPORT_H_

#include "loop.h"

/*
 * PCAP LOOP header support class.
 */

class c_loop_header
{

protected:
    s_loop_header *header;

public:
    c_loop_header(byte *);
    c_loop_header(s_loop_header *);

    dword get_af();

    void set_af(dword);
};

#endif /* _NETZ_LOOP_SUPPORT_H_ */
