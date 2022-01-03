#ifndef _NETZ_SNAP_SUPPORT_H_
#define _NETZ_SNAP_SUPPORT_H_

#include "snap.h"

class c_snap_header
{
protected:
    s_snap_header *header;

public:
    c_snap_header(byte *);
    c_snap_header(s_snap_header *);

    byte get_oui(u_int);
    dword get_oui();
    word get_type();

    void set_oui(u_int, byte);
    void set_oui(dword);
    void set_type(word);
};

#endif /* _NETZ_SNAP_SUPPORT_H_ */
