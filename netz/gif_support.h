#ifndef _NETZ_GIF_SUPPORT_H_
#define _NETZ_GIF_SUPPORT_H_

#include "gif.h"

/*
 * GIF interface header support class.
 */

class c_gif_header
{

protected:
    s_gif_header *header;

public:
    c_gif_header(byte *);
    c_gif_header(s_gif_header *);

    dword get_af();

    void set_af(dword);
};

#endif /* _NETZ_GIF_SUPPORT_H_ */
