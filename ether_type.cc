#include <netz.h>

#include "ether_type.h"
#include "support.h"

c_string print_ether_type(word type)
{
    switch (type)
    {
    case ETHER_TYPE_IDP:
        return c_string((char *)"IDP");

    case ETHER_TYPE_IP:
        return c_string((char *)"IPv4");

    case ETHER_TYPE_X75:
        return c_string((char *)"X.75");

    case ETHER_TYPE_NBS:
        return c_string((char *)"NBS");

    case ETHER_TYPE_ECMA:
        return c_string((char *)"ECMA");

    case ETHER_TYPE_CHAOS:
        return c_string((char *)"Chaos");

    case ETHER_TYPE_X25:
        return c_string((char *)"X.25");

    case ETHER_TYPE_ARP:
        return c_string((char *)"ARP");

    case ETHER_TYPE_XNS:
        return c_string((char *)"XNS");

    case ETHER_TYPE_XPUP:
        return c_string((char *)"XPUP");

    case ETHER_TYPE_DECNET:
        return c_string((char *)"DecNet");

    case ETHER_TYPE_EXCELAN:
        return c_string((char *)"ExceLan");

    case ETHER_TYPE_SGI:
        return c_string((char *)"SGI");

    case ETHER_TYPE_REVARP:
        return c_string((char *)"RevARP");

    case ETHER_TYPE_UM:
        return c_string((char *)"UM");

    case ETHER_TYPE_ATT:
        return c_string((char *)"ATT");

    case ETHER_TYPE_APPLETALK:
        return c_string((char *)"AppleTalk");

    case ETHER_TYPE_BANYAN_80C4:
        return c_string((char *)"Banyan");

    case ETHER_TYPE_BANYAN_80C5:
        return c_string((char *)"Banyan");

    case ETHER_TYPE_IBMSNA:
        return c_string((char *)"IBM SNA");

    case ETHER_TYPE_AARP:
        return c_string((char *)"AARP");

    case ETHER_TYPE_APOLLO:
        return c_string((char *)"Apollo");

    case ETHER_TYPE_BRIDGE_8132:
        return c_string((char *)"Bridge");

    case ETHER_TYPE_BRIDGE_8133:
        return c_string((char *)"Bridge");

    case ETHER_TYPE_BRIDGE_8134:
        return c_string((char *)"Bridge");

    case ETHER_TYPE_BRIDGE_8135:
        return c_string((char *)"Bridge");

    case ETHER_TYPE_BRIDGE_8136:
        return c_string((char *)"Bridge");

    case ETHER_TYPE_IPX:
        return c_string((char *)"IPX");

    case ETHER_TYPE_NOVELL_8138:
        return c_string((char *)"Novell");

    case ETHER_TYPE_SNMP:
        return c_string((char *)"SNMP");

    case ETHER_TYPE_ASCOM:
        return c_string((char *)"Ascom");

    case ETHER_TYPE_AES_823E:
        return c_string((char *)"AES");

    case ETHER_TYPE_AES_823F:
        return c_string((char *)"AES");

    case ETHER_TYPE_AES_8240:
        return c_string((char *)"AES");

    case ETHER_TYPE_IP6:
        return c_string((char *)"IPv6");

    case ETHER_TYPE_PPPOEDISC:
        return c_string((char *)"PPPoE disc");

    case ETHER_TYPE_PPPOE:
        return c_string((char *)"PPPoE");

    case ETHER_TYPE_LOOPBACK:
        return c_string((char *)"Loopback");

    case ETHER_TYPE_BBN:
        return c_string((char *)"BBN");

    case SNAP_TYPE_CDP:
        return c_string((char *)"CDP");

    default:
        return c_string((char *)"Unknown");
    }
}
