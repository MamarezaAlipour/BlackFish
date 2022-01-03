#include <netz.h>

#include "hr_type.h"
#include "support.h"

c_string print_arp_hrtype(word hrtype)
{
    switch (hrtype)
    {
    case ARP_HRTYPE_ETHER:
        return c_string((char *)"Ethernet");

    case ARP_HRTYPE_IEEE802:
        return c_string((char *)"IEEE 802");

    case ARP_HRTYPE_FRELAY:
        return c_string((char *)"Frame Relay");

    default:
        return c_string((char *)"Unknown");
    }
}
