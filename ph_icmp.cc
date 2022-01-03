#include <netz.h>

#include "netz/cksum.h"
#include "support.h"
#include "ph_packet.h"
#include "ip_proto.h"

c_string print_icmp_info(u_int, u_int);
c_string print_ip_info(c_ip_header, byte *);

c_string icmp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_icmp_header header(packet_info.packet);

    output_string.add((char *)"ICMP\t");

    output_string.add((char *)"TYPE %u  CODE %u  '",
                      header.get_type(), header.get_code());

    output_string += print_icmp_info(header.get_type(), header.get_code());

    output_string.add((char *)"'\n");

    output_string.add((char *)"\t(LEN %u)  CKSUM %u ",
                      packet_info.packet_len, header.get_cksum());

    if (!cksum(packet_info.packet, packet_info.packet_len))
    {
        output_string.add((char *)"(OK)");
    }
    else
    {
        output_string.add((char *)"(BAD)");
    }

    output_string.add((char *)"  ");

    switch (header.get_type())
    {
    case ICMP_ECHOREPLY:
    {
        c_icmp_message_echoreply message(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          message.get_id(),
                          message.get_seqnumber());

        break;
    }

    case ICMP_UNREACH:
    {
        c_icmp_message_unreach message(header);

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_SOURCEQUENCH:
    {
        c_icmp_message_sourcequench message(header);

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_REDIRECT:
    {
        c_icmp_message_redirect message(header);

        string gateway_string[16];

        output_string.add((char *)"GATE %s",
                          conv_ip_str(gateway_string, message.get_gateway()));

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_ECHOREQUEST:
    {
        c_icmp_message_echorequest message(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          message.get_id(),
                          message.get_seqnumber());

        break;
    }

    case ICMP_TIMEXCEED:
    {
        c_icmp_message_timexceed message(header);

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_PARAMPROB:
    {
        c_icmp_message_paramprob message(header);

        output_string.add((char *)"PTR %u",
                          message.get_pointer());

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_ROUTERADVERT:
    {
        c_icmp_message_routeradvert message(header);

        output_string.add((char *)"NUM %u  SIZE %u  LTIME %u",
                          message.get_addrnumber(),
                          message.get_addrentrysize(),
                          message.get_lifetime());

        string router_string[16];

        for (int i = 0; i < message.get_addrnumber(); i++)
        {
            output_string.add((char *)"\n    \tROUTER %s  PLEVEL %u",
                              conv_ip_str(router_string, message.get_address(i)),
                              message.get_plevel(i));
        }

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_TSREQUEST:
    {
        c_icmp_message_tsrequest message(header);

        output_string.add((char *)"ID %u  SQN %u",
                          message.get_id(),
                          message.get_seqnumber());

        output_string.add((char *)"\n    \tORG %u  REC %u  TRS %u",
                          message.get_originate(),
                          message.get_receive(),
                          message.get_transmit());

        output_string.add((char *)"\n");

        break;
    }

    case ICMP_INFOREQUEST:
    {
        c_icmp_message_inforequest message(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          message.get_id(),
                          message.get_seqnumber());

        break;
    }

    case ICMP_INFOREPLY:
    {
        c_icmp_message_inforeply message(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          message.get_id(),
                          message.get_seqnumber());

        break;
    }

    case ICMP_MASKREQUEST:
    {
        c_icmp_message_maskrequest message(header);

        output_string.add((char *)"ID %u  SQN %u",
                          message.get_id(),
                          message.get_seqnumber());

        string mask_string[16];

        output_string.add((char *)"\n    \tMASK %s\n",
                          conv_ip_str(mask_string, message.get_mask()));

        break;
    }

    case ICMP_MASKREPLY:
    {
        c_icmp_message_maskreply message(header);

        output_string.add((char *)"ID %u  SQN %u",
                          message.get_id(),
                          message.get_seqnumber());

        string mask_string[16];

        output_string.add((char *)"\n    \tMASK %s\n",
                          conv_ip_str(mask_string, message.get_mask()));

        break;
    }

    case ICMP_TRACEROUTE:
    {
        c_icmp_message_traceroute message(header);

        output_string.add((char *)"ID %u",
                          message.get_id());

        output_string.add((char *)"\n    \tOUT %u  RET %u  SPD %u  MTU %u\n",
                          message.get_outhopcount(),
                          message.get_rethopcount(),
                          message.get_outlinkspeed(),
                          message.get_outlinkmtu());

        break;
    }

    case ICMP_SECURITY:
    {
        c_icmp_message_security message(header);

        output_string.add((char *)"PTR %u",
                          message.get_pointer());

        output_string += print_ip_info(message.get_ipheader(),
                                       message.get_ipdata());

        output_string.add((char *)"\n");

        break;
    }

    default:
        output_string.add((char *)"\n");
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_icmp_info(u_int type, u_int code)
{
    switch (type)
    {
    case ICMP_ECHOREPLY:
        return c_string((char *)"Echo Reply");

    case ICMP_UNREACH:
        switch (code)
        {
        case ICMP_UNREACH_NET:
            return c_string((char *)"Net Unreachable");

        case ICMP_UNREACH_HOST:
            return c_string((char *)"Host Unreachable");

        case ICMP_UNREACH_PROTOCOL:
            return c_string((char *)"Protocol Unreachable");

        case ICMP_UNREACH_PORT:
            return c_string((char *)"Port Unreachable");

        case ICMP_UNREACH_NEEDFRAG:
            return c_string((char *)"Fragmentation Needed and Don't Fragment was Set");

        case ICMP_UNREACH_SRCFAIL:
            return c_string((char *)"Source Route Failed");

        case ICMP_UNREACH_NETUNK:
            return c_string((char *)"Destination Network Unknown");

        case ICMP_UNREACH_HOSTUNK:
            return c_string((char *)"Destination Host Unknown");

        case ICMP_UNREACH_ISOLATED:
            return c_string((char *)"Source Host Isolated");

        case ICMP_UNREACH_NETPROHIB:
            return c_string((char *)"Comm. with Dest. Net. is Adm. Prohib.");

        case ICMP_UNREACH_TOSNET:
            return c_string((char *)"Comm. with Dest. Host is Adm. Prohib.");

        case ICMP_UNREACH_TOSHOST:
            return c_string((char *)"Destination Network Unreachable for ToS");

        case ICMP_UNREACH_FILTERPROHIB:
            return c_string((char *)"Destination Host Unreachable for ToS");
        }

    case ICMP_SOURCEQUENCH:
        return c_string((char *)"Source Quench");

    case ICMP_REDIRECT:
        switch (code)
        {
        case ICMP_REDIRECT_NET:
            return c_string((char *)"Redirect Datagram for the Network (or subnet)");

        case ICMP_REDIRECT_HOST:
            return c_string((char *)"Redirect Datagram for the Host");

        case ICMP_REDIRECT_TOSNET:
            return c_string((char *)"Redirect Datagram for the Type of Service and Network");

        case ICMP_REDIRECT_TOSHOST:
            return c_string((char *)"Redirect Datagram for the ToS and Host");
        }

    case ICMP_ALTHOSTADDR:
        return c_string((char *)"Alternate Address for Host");

    case ICMP_ECHOREQUEST:
        return c_string((char *)"Echo");

    case ICMP_ROUTERADVERT:
        return c_string((char *)"Router Advertisement");

    case ICMP_ROUTERSOLICIT:
        return c_string((char *)"Router Solicitation");

    case ICMP_TIMEXCEED:
        switch (code)
        {
        case ICMP_TIMEXCEED_INTRANS:
            return c_string((char *)"Time to Live exceeded in Transit");

        case ICMP_TIMEXCEED_REASS:
            return c_string((char *)"Fragment Reassembly Time Exceeded");
        }

    case ICMP_PARAMPROB:
        switch (code)
        {
        case ICMP_PARAMPROB_ERRATPTR:
            return c_string((char *)"Pointer Indicates the Error");

        case ICMP_PARAMPROB_OPTABSENT:
            return c_string((char *)"Missing a Required Option");

        case ICMP_PARAMPROB_LENGTH:
            return c_string((char *)"Bad Length");
        }

    case ICMP_TSREQUEST:
        return c_string((char *)"Timestamp Request");

    case ICMP_TSREPLY:
        return c_string((char *)"Timestamp Reply");

    case ICMP_INFOREQUEST:
        return c_string((char *)"Information Request");

    case ICMP_INFOREPLY:
        return c_string((char *)"Information Reply");

    case ICMP_MASKREQUEST:
        return c_string((char *)"Address Mask Request");

    case ICMP_MASKREPLY:
        return c_string((char *)"Address Mask Reply");

    case ICMP_RESERVED19:
        return c_string((char *)"Reserved-19 (for Security)");

    case ICMP_RESERVED20:
        return c_string((char *)"Reserved-20 (for Robustness Experiment)");

    case ICMP_RESERVED21:
        return c_string((char *)"Reserved-21 (for Robustness Experiment)");

    case ICMP_RESERVED22:
        return c_string((char *)"Reserved-22 (for Robustness Experiment)");

    case ICMP_RESERVED23:
        return c_string((char *)"Reserved-23 (for Robustness Experiment)");

    case ICMP_RESERVED24:
        return c_string((char *)"Reserved-24 (for Robustness Experiment)");

    case ICMP_RESERVED25:
        return c_string((char *)"Reserved-25 (for Robustness Experiment)");

    case ICMP_RESERVED26:
        return c_string((char *)"Reserved-26 (for Robustness Experiment)");

    case ICMP_RESERVED27:
        return c_string((char *)"Reserved-27 (for Robustness Experiment)");

    case ICMP_RESERVED28:
        return c_string((char *)"Reserved-28 (for Robustness Experiment)");

    case ICMP_RESERVED29:
        return c_string((char *)"Reserved-29 (for Robustness Experiment)");

    case ICMP_TRACEROUTE:
        return c_string((char *)"Traceroute");

    case ICMP_CONVERR:
        return c_string((char *)"Datagram Conversion Error");

    case ICMP_MOBHRED:
        return c_string((char *)"Mobile Host Redirect");

    case ICMP_WHEREAREYOU:
        return c_string((char *)"IPv6 Where-Are-You");

    case ICMP_IAMHERE:
        return c_string((char *)"IPv6 I-Am-Here");

    case ICMP_MOBREGREQ:
        return c_string((char *)"Mobile Registration Request");

    case ICMP_MOBREGREP:
        return c_string((char *)"Mobile Registration Reply");

    case ICMP_SKIP:
        return c_string((char *)"Skip");

    case ICMP_SECURITY:
        switch (code)
        {
        case ICMP_SECURITY_BADSPI:
            return c_string((char *)"Security - Bad SPI");

        case ICMP_SECURITY_AUTHENFAIL:
            return c_string((char *)"Security - Authenticaton Failed");

        case ICMP_SECURITY_DECOMPFAIL:
            return c_string((char *)"Security - Decompression Failed");

        case ICMP_SECURITY_DECRYPFAIL:
            return c_string((char *)"Security - Decryption Failed");

        case ICMP_SECURITY_NEEDAUTHEN:
            return c_string((char *)"Security - Need Authentication");

        case ICMP_SECURITY_NEEDAUTHOR:
            return c_string((char *)"Security - Need Authorization");
        }

    default:
        return c_string((char *)"Unknown");
    }
}

c_string print_ip_info(c_ip_header header, byte *data)
{
    c_string output_string;

    string src_string[16];
    string dst_string[16];

    output_string.add((char *)"\n\nIP HDR\tSRC %s  DST %s  VER %u  CKSUM %u  ",
                      conv_ip_str(src_string, header.get_src()),
                      conv_ip_str(dst_string, header.get_dst()),
                      header.get_ver(),
                      header.get_cksum());

    output_string.add((char *)"ID %u\n\tHLEN %u  LEN %u  TTL %u  ",
                      header.get_id(),
                      header.get_hlen(),
                      header.get_len(),
                      header.get_ttl());

    output_string.add_hex((char *)"TOS 0x%02X  ",
                          header.get_tos());

    output_string.add_hex((char *)"FRAG 0x%02X  ",
                          header.get_frag());

    output_string.add((char *)"PROTO 0x%02X (",
                      header.get_proto());

    output_string += print_ip_proto(header.get_proto());

    output_string.add((char *)")\n\n");

    output_string.add_hex((char *)"IP DTA\t0x%02X ", data[0]);
    output_string.add_hex((char *)"0x%02X ", data[1]);
    output_string.add_hex((char *)"0x%02X ", data[2]);
    output_string.add_hex((char *)"0x%02X ", data[3]);
    output_string.add_hex((char *)"0x%02X ", data[4]);
    output_string.add_hex((char *)"0x%02X ", data[5]);
    output_string.add_hex((char *)"0x%02X ", data[6]);
    output_string.add_hex((char *)"0x%02X", data[7]);

    return output_string;
}
