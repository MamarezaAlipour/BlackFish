#include <netz.h>

#include "ip_proto.h"
#include "support.h"

c_string print_ip_proto(byte proto)
{
    switch (proto)
    {
    case IP_PROTO_TCP:
        return c_string((char *)"TCP");

    case IP_PROTO_UDP:
        return c_string((char *)"UDP");

    case IP_PROTO_ICMP:
        return c_string((char *)"ICMP");

    case IP_PROTO_IGMP:
        return c_string((char *)"IGMP");

    case IP_PROTO_IPV4:
        return c_string((char *)"IPv4");

    case IP_PROTO_EGP:
        return c_string((char *)"EGP");

    case IP_PROTO_IGRP:
        return c_string((char *)"IGRP");

    case IP_PROTO_PUP:
        return c_string((char *)"PUP");

    case IP_PROTO_IDP:
        return c_string((char *)"IDP");

    case IP_PROTO_TP:
        return c_string((char *)"TP");

    case IP_PROTO_IPV6:
        return c_string((char *)"IPv6");

    case IP_PROTO_ROUTING:
        return c_string((char *)"Routing header");

    case IP_PROTO_FRAGMENT:
        return c_string((char *)"Fragment header");

    case IP_PROTO_RSVP:
        return c_string((char *)"RSVP");

    case IP_PROTO_GRE:
        return c_string((char *)"GRE");

    case IP_PROTO_ESP:
        return c_string((char *)"ESP");

    case IP_PROTO_AH:
        return c_string((char *)"AH");

    case IP_PROTO_MOBILE:
        return c_string((char *)"Mobile header");

    case IP_PROTO_ICMPV6:
        return c_string((char *)"ICMPv6");

    case IP_PROTO_NONE:
        return c_string((char *)"None");

    case IP_PROTO_DSTOPTS:
        return c_string((char *)"DSTOPTS");

    case IP_PROTO_EON:
        return c_string((char *)"EON");

    case IP_PROTO_EIGRP:
        return c_string((char *)"EIGRP");

    case IP_PROTO_OSPF:
        return c_string((char *)"OSPF");

    case IP_PROTO_ETHERIP:
        return c_string((char *)"Ethernet over IP");

    case IP_PROTO_ENCAP:
        return c_string((char *)"ENCAP");

    case IP_PROTO_PIM:
        return c_string((char *)"PIM");

    case IP_PROTO_IPCOMP:
        return c_string((char *)"IPCOMP");

    case IP_PROTO_RAW:
        return c_string((char *)"RAW");

    default:
        return c_string((char *)"Unknown");
    }
}
