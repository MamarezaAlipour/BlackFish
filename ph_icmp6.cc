#include <netz.h>

#include "ph_packet.h"
#include "support.h"

c_string print_icmp6_info(u_int, u_int);

c_string icmp6_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_icmp6_header header(packet_info.packet);

    output_string.add((char *)"ICMPv6\t");

    output_string.add((char *)"TYPE %u  CODE %u  '",
                      header.get_type(), header.get_code());

    output_string += print_icmp6_info(header.get_type(), header.get_code());

    output_string.add((char *)"'\n");

    output_string.add((char *)"\t(LEN %u)  CKSUM %u ",
                      packet_info.packet_len, header.get_cksum());

    c_pseudo_header pseudo_header;

    if (packet_info.previous_packet_type == PACKET_TYPE_IP)
    {
        c_ipp_header ipp_header(c_ip_header(packet_info.previous_packet));
        pseudo_header = ipp_header.get_pseudo_header();
    }

    if (packet_info.previous_packet_type == PACKET_TYPE_IP6)
    {
        c_ip6p_header ip6p_header(c_ip6_header(packet_info.previous_packet));
        pseudo_header = ip6p_header.get_pseudo_header();
    }

    if (!cksum(packet_info.packet, packet_info.packet_len,
               pseudo_header))
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
    case ICMP6_PACKET_TOO_BIG:
    {
        c_icmp6_pkttoobig body(header);

        output_string.add((char *)"MTU %u\n",
                          body.get_mtu());

        break;
    }

    case ICMP6_PARAMPROB:
    {
        c_icmp6_paramprob body(header);

        output_string.add((char *)"PTR %u\n",
                          body.get_pointer());

        break;
    }

    case ICMP6_ECHO_REQUEST:
    {
        c_icmp6_echorequest body(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          body.get_id(),
                          body.get_seqnumber());

        break;
    }

    case ICMP6_ECHO_REPLY:
    {
        c_icmp6_echoreply body(header);

        output_string.add((char *)"ID %u  SQN %u\n",
                          body.get_id(),
                          body.get_seqnumber());

        break;
    }

    case ICMP6_NEIGHBOR_SOLICITATION:
    {
        c_icmp6_nbsolicit body(header);

        string addr_string[40];

        output_string.add((char *)"\n\tTARGET %s\n", conv_ip6_str(addr_string,
                                                                  body.get_target()));

        break;
    }

    case ICMP6_NEIGHBOR_ADVERTISEMENT:
    {
        c_icmp6_nbadvert body(header);

        output_string.add((char *)"\n\tFLAGS |");

        if (body.get_flag_router())
        {
            output_string.add((char *)"R|");
        }
        else
        {
            output_string.add((char *)" |");
        }

        if (body.get_flag_solicited())
        {
            output_string.add((char *)"S|");
        }
        else
        {
            output_string.add((char *)" |");
        }

        if (body.get_flag_override())
        {
            output_string.add((char *)"O|");
        }
        else
        {
            output_string.add((char *)" |");
        }

        string addr_string[40];

        output_string.add((char *)"  TARGET %s\n", conv_ip6_str(addr_string,
                                                                body.get_target()));

        break;
    }

    case ICMP6_ROUTER_ADVERTISEMENT:
    {
        c_icmp6_routeradvert body(header);

        output_string.add((char *)"\n\tHLIMIT %u  RTRLT %u  FLAGS |",
                          body.get_hoplimit(),
                          body.get_lifetime());

        if (body.get_flag_mac())
        {
            output_string.add((char *)"M|");
        }
        else
        {
            output_string.add((char *)" |");
        }

        if (body.get_flag_osc())
        {
            output_string.add((char *)"O|");
        }
        else
        {
            output_string.add((char *)" |");
        }

        output_string.add((char *)"  REACHT %u  RETRT %u\n",
                          body.get_reachtimer(),
                          body.get_retrtimer());

        break;
    }

    default:
        output_string.add((char *)"\n");
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_icmp6_info(u_int type, u_int code)
{
    switch (type)
    {
    case ICMP6_UNREACH:
        switch (code)
        {
        case ICMP6_UNREACH_NOROUTE:
            return c_string((char *)"No Route to Destination");

        case ICMP6_UNREACH_DSTPROHIB:
            return c_string((char *)"Communication with Destination "
                                    "Administratively Prohibited");

        case ICMP6_UNREACH_NOTNEIGHBOR:
            return c_string((char *)"No Route to Destination - Not a Neighbor");

        case ICMP6_UNREACH_BADADDR:
            return c_string((char *)"Destination Unreachable - Bad Address");

        case ICMP6_UNREACH_BADPORT:
            return c_string((char *)"Destination Unreachable -  Bad Port");
        }

    case ICMP6_PACKET_TOO_BIG:
        return c_string((char *)"Packet is Larger than the MTU of the Outgoing Link");

    case ICMP6_TIMEXCEED:
        switch (code)
        {
        case ICMP6_TIMEXCEED_TRANSIT:
            return c_string((char *)"Hop Limit Exceeded in Transit");

        case ICMP6_TIMEXCEED_REASSEMBLY:
            return c_string((char *)"Fragment Reassembly Time Exceeded");
        }

    case ICMP6_PARAMPROB:
        switch (code)
        {
        case ICMP6_PARAMPROB_HEADER:
            return c_string((char *)"Erroneous Header Field Encountered");

        case ICMP6_PARAMPROB_NEXTHEADER:
            return c_string((char *)"Unrecognized Next Header Type Encountered");

        case ICMP6_PARAMPROB_OPTION:
            return c_string((char *)"Unrecognized IPv6 Option Encountered");
        }

    case ICMP6_ECHO_REQUEST:
        return c_string((char *)"Echo Request");

    case ICMP6_ECHO_REPLY:
        return c_string((char *)"Echo Reply");

    case ICMP6_MEMBERSHIP_QUERY:
        return c_string((char *)"Membership Query");

    case ICMP6_MEMBERSHIP_REPORT:
        return c_string((char *)"Membership Report");

    case ICMP6_MEMBERSHIP_REDUCTION:
        return c_string((char *)"Membership Reduction");

    case ICMP6_ROUTER_SOLICITATION:
        return c_string((char *)"Router Solicitation");

    case ICMP6_ROUTER_ADVERTISEMENT:
        return c_string((char *)"Router Advertisement");

    case ICMP6_NEIGHBOR_SOLICITATION:
        return c_string((char *)"Neighbor Solicitation");

    case ICMP6_NEIGHBOR_ADVERTISEMENT:
        return c_string((char *)"Neighbor Advertisement");

    case ICMP6_REDIRECT:
        return c_string((char *)"Redirect");

    case ICMP6_ROUTER_RENUM:
        switch (code)
        {
        case ICMP6_ROUTER_RENUM_COMMAND:
            return c_string((char *)"Router Renumbering Command");

        case ICMP6_ROUTER_RENUM_RESULT:
            return c_string((char *)"Router Renumbering Result");

        case ICMP6_ROUTER_RENUM_SNRESET:
            return c_string((char *)"Sequence Number Reset");
        }

    case ICMP6_NODE_INFORMATION_QUERRY:
        return c_string((char *)"ICMP Node Information Query");

    case ICMP6_NODE_INFORMATION_RESPONSE:
        return c_string((char *)"ICMP Node Information Response");

    case ICMP6_INV_NEIGHBOR_SOLICICATION:
        return c_string((char *)"Inverse Neighbor Discovery Solicitation");

    case ICMP6_INV_NEIGHBOR_ADVERTISEMENT:
        return c_string((char *)"Inverse Neighbor Discovery Advertisement");

    default:
        return c_string((char *)"Unknown");
    }
}
