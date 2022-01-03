#ifndef _NETZ_CDP_SUPPORT_H_
#define _NETZ_CDP_SUPPORT_H_

#include "cdp.h"

/*
 * CDP protocol support classes.
 */

class c_cdp_header
{

protected:
    s_cdp_header *header;

public:
    c_cdp_header(byte *);
    c_cdp_header(s_cdp_header *);

    byte get_ver();
    byte get_ttl();
    word get_cksum();
};

class c_cdp_dheader
{

protected:
    s_cdp_dheader *header;

public:
    c_cdp_dheader(byte *);
    c_cdp_dheader(s_cdp_dheader *);

    word get_type();
    word get_len();

    string *get_devid();
};

#endif /* _NETZ_CDP_SUPPORT_H_ */
