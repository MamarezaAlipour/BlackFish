#include "ripng_support.h"
#include "support.h"

c_ripng_header::c_ripng_header(byte *ripng_header)
{
    header = (s_ripng_header *)ripng_header;
}

c_ripng_header::c_ripng_header(s_ripng_header *ripng_header)
{
    header = ripng_header;
}

byte c_ripng_header::get_cmd()
{
    return ntoh(header->cmd);
}

byte c_ripng_header::get_ver()
{
    return ntoh(header->ver);
}

c_ripng_route_entry::c_ripng_route_entry(byte *ripng_route_entry)
{
    route_entry = (s_ripng_route_entry *)ripng_route_entry;
}

c_ripng_route_entry::c_ripng_route_entry(s_ripng_route_entry *ripng_route_entry)
{
    route_entry = ripng_route_entry;
}

byte *c_ripng_route_entry::get_prefix()
{
    return route_entry->prefix;
}

word c_ripng_route_entry::get_tag()
{
    return ntoh(route_entry->tag);
}

byte c_ripng_route_entry::get_prefix_len()
{
    return ntoh(route_entry->prefix_len);
}

byte c_ripng_route_entry::get_metric()
{
    return ntoh(route_entry->metric);
}

c_ripng_next_hop_entry::c_ripng_next_hop_entry(byte *ripng_next_hop_entry)
{
    next_hop_entry = (s_ripng_next_hop_entry *)ripng_next_hop_entry;
}

c_ripng_next_hop_entry::c_ripng_next_hop_entry(s_ripng_next_hop_entry *ripng_next_hop_entry)
{
    next_hop_entry = ripng_next_hop_entry;
}

byte *c_ripng_next_hop_entry::get_next_hop()
{
    return next_hop_entry->next_hop;
}
