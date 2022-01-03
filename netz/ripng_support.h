#ifndef _NETZ_RIPNG_SUPPORT_H_
#define _NETZ_RIPNG_SUPPORT_H_

#include "ripng.h"

/*
 * RIPng protocol support class.
 */

class c_ripng_header
{

protected:
    s_ripng_header *header;

public:
    c_ripng_header(byte *);
    c_ripng_header(s_ripng_header *);

    byte get_cmd();
    byte get_ver();
};

/*
 * RIPng route entry support class.
 */

class c_ripng_route_entry
{

protected:
    s_ripng_route_entry *route_entry;

public:
    c_ripng_route_entry(byte *);
    c_ripng_route_entry(s_ripng_route_entry *);

    byte *get_prefix();
    word get_tag();
    byte get_prefix_len();
    byte get_metric();
};

/*
 * RIPng next hop entry support class.
 */

class c_ripng_next_hop_entry
{

protected:
    s_ripng_next_hop_entry *next_hop_entry;

public:
    c_ripng_next_hop_entry(byte *);
    c_ripng_next_hop_entry(s_ripng_next_hop_entry *);

    byte *get_next_hop();
};

#endif /* _NETZ_RIPNG_SUPPORT_H_ */
