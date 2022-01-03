#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string eigrp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_eigrp_header header(packet_info.packet);

    output_string.add((char *)"EIGRP\t");

    output_string.add((char *)"VER %u  OPCODE %u ",
                      header.get_ver(),
                      header.get_opcode());

    switch (header.get_opcode())
    {

    case EIGRP_OPCODE_UPDATE:
        output_string += "(Update)";
        break;

    case EIGRP_OPCODE_QUERY:
        output_string += "(Query)";
        break;

    case EIGRP_OPCODE_REPLY:
        output_string += "(Reply)";
        break;

    case EIGRP_OPCODE_HELLO:
        output_string += "(Hello)";
        break;

    case EIGRP_OPCODE_IPXSAP:
        output_string += "(IPX Sap)";
        break;

    case EIGRP_OPCODE_SIA_QUERY:
        output_string += "(SIA Query)";
        break;

    case EIGRP_OPCODE_SIA_REPLY:
        output_string += "(SIA Reply)";
        break;

    default:
        output_string += "(Unknown)";
    }

    output_string.add((char *)"  AS %u  SEQ %u  ACK %u\n",
                      header.get_as(),
                      header.get_seq(),
                      header.get_ack());

    output_string.add_hex((char *)"\tFLAGS 0x%02X%02X |",
                          header.get_flags());

    if (header.get_flag_init())
    {
        output_string.add((char *)"INIT|");
    }
    else
    {
        output_string.add((char *)"    |");
    }

    if (header.get_flag_cr())
    {
        output_string.add((char *)" CR |");
    }
    else
    {
        output_string.add((char *)"    |");
    }

    output_string.add((char *)"  CKSUM %u ", header.get_cksum());

    if (!cksum(packet_info.packet, packet_info.packet_len))
    {
        output_string.add((char *)"(OK)");
    }
    else
    {
        output_string.add((char *)"(BAD)");
    }

    output_string.add((char *)"\n");

    u_int i = 0;

    while (i < packet_info.packet_len - EIGRP_HEADER_LEN)
    {
        c_eigrp_tlv tlv(packet_info.packet + EIGRP_HEADER_LEN + i);

        output_string.add((char *)"\nTLV\tTYPE %u ",
                          tlv.get_type());

        switch (tlv.get_type())
        {
        case EIGRP_TLV_TYPE_PARAMETERS:
            output_string += "(Parameters)";
            break;

        case EIGRP_TLV_TYPE_SEQUENCE:
            output_string += "(Sequence)";
            break;

        case EIGRP_TLV_TYPE_SOFTWARE_VERSION:
            output_string += "(Software Version)";
            break;

        case EIGRP_TLV_TYPE_NEXT_MULTICAST_SEQUENCE:
            output_string += "(Multicast Sequence)";
            break;

        case EIGRP_TLV_TYPE_IP_INTERNAL_ROUTE:
            output_string += "(Internal Route)";
            break;

        case EIGRP_TLV_TYPE_IP_EXTERNAL_ROUTE:
            output_string += "(External Route)";
            break;

        case EIGRP_TLV_TYPE_APPLETALK_INTENAL_ROUTE:
            output_string += "(Appletalk Internal Route)";
            break;

        case EIGRP_TLV_TYPE_APPLETALK_EXTERNAL_ROUTE:
            output_string += "(Appletalk External Route)";
            break;

        case EIGRP_TLV_TYPE_APPLETALK_CABLE_CONFIG:
            output_string += "(Appletalk Cable Config)";
            break;

        case EIGRP_TLV_TYPE_IPX_INTERNAL_ROUTE:
            output_string += "(IPX Internal Route)";
            break;

        case EIGRP_TLV_TYPE_IPX_EXTERNAL_ROUTE:
            output_string += "(IPX External Route)";
            break;

        default:
            output_string += "(Unknown)";
            break;
        }

        output_string.add((char *)"  LEN %u\n",
                          tlv.get_len());

        switch (tlv.get_type())
        {
        case EIGRP_TLV_TYPE_PARAMETERS:
        {
            c_eigrp_tlv_parameters tlv_parameters(packet_info.packet + EIGRP_HEADER_LEN + i);

            output_string.add((char *)"\tK1 %u  K2 %u  K3 %u  K4 %u  K5 %u  HOLD TIME %u\n",
                              tlv_parameters.get_k1(),
                              tlv_parameters.get_k2(),
                              tlv_parameters.get_k3(),
                              tlv_parameters.get_k4(),
                              tlv_parameters.get_k5(),
                              tlv_parameters.get_holdtime());

            break;
        }

        case EIGRP_TLV_TYPE_SOFTWARE_VERSION:
        {
            c_eigrp_tlv_softver tlv_softver(packet_info.packet + EIGRP_HEADER_LEN + i);

            output_string.add((char *)"\tSOFTWARE VERSION %u.%u %u %u\n",
                              tlv_softver.get_ver(0),
                              tlv_softver.get_ver(1),
                              tlv_softver.get_ver(2),
                              tlv_softver.get_ver(3));

            break;
        }

        case EIGRP_TLV_TYPE_IP_INTERNAL_ROUTE:
        {
            c_eigrp_tlv_ipintup tlv_ipintup(packet_info.packet + EIGRP_HEADER_LEN + i);

            string destination_string[16];

            conv_ip_str(destination_string, tlv_ipintup.get_destination());

            output_string.add((char *)"\tNETWORK %s ",
                              destination_string);

            output_string.add((char *)"/%u",
                              tlv_ipintup.get_prefixlen());

            string nexthop_string[16];

            conv_ip_str(nexthop_string, tlv_ipintup.get_nexthop());

            output_string.add((char *)"  NEXTHOP %s\n",
                              nexthop_string);

            output_string.add(
                (char *)"\tDELAY %u  BW %u  MTU %u  HOPCOUNT %u  REL %u  LOAD %u \n",
                tlv_ipintup.get_delay(),
                tlv_ipintup.get_bandwidth(),
                tlv_ipintup.get_mtu(),
                tlv_ipintup.get_hopcount(),
                tlv_ipintup.get_reliability(),
                tlv_ipintup.get_load());

            break;
        }

        case EIGRP_TLV_TYPE_IP_EXTERNAL_ROUTE:
        {
            c_eigrp_tlv_ipextup tlv_ipextup(packet_info.packet + EIGRP_HEADER_LEN + i);

            string destination_string[16];
            conv_ip_str(destination_string, tlv_ipextup.get_destination());
            output_string.add((char *)"\tNETWORK %s ",
                              destination_string);

            output_string.add((char *)"/%u",
                              tlv_ipextup.get_prefixlen());

            string nexthop_string[16];
            conv_ip_str(nexthop_string, tlv_ipextup.get_nexthop());
            output_string.add((char *)"  NEXTHOP %s\n",
                              nexthop_string);

            string orouter_string[16];
            conv_ip_str(orouter_string, tlv_ipextup.get_orouter());
            output_string.add((char *)"\tOROUTER %s  ",
                              orouter_string);

            output_string.add((char *)"OAS %u  BW %u  ATAG %u  EPMETRIC %u  \n",
                              tlv_ipextup.get_oas(),
                              tlv_ipextup.get_atag(),
                              tlv_ipextup.get_epmetric());

            output_string.add_hex((char *)"\tEPID 0x%02X (",
                                  tlv_ipextup.get_epid());

            switch (tlv_ipextup.get_epid())
            {
            case EIGRP_TLV_IEU_EPID_IGRP:
                output_string.add((char *)"IGRP");
                break;

            case EIGRP_TLV_IEU_EPID_EIGRP:
                output_string.add((char *)"EIGRP");
                break;

            case EIGRP_TLV_IEU_EPID_STATIC:
                output_string.add((char *)"STATIC");
                break;

            case EIGRP_TLV_IEU_EPID_RIP:
                output_string.add((char *)"RIP");
                break;

            case EIGRP_TLV_IEU_EPID_HELLO:
                output_string.add((char *)"HELLO");
                break;

            case EIGRP_TLV_IEU_EPID_OSPF:
                output_string.add((char *)"OSPF");
                break;

            case EIGRP_TLV_IEU_EPID_ISIS:
                output_string.add((char *)"ISIS");
                break;

            case EIGRP_TLV_IEU_EPID_EGP:
                output_string.add((char *)"EGP");
                break;

            case EIGRP_TLV_IEU_EPID_BGP:
                output_string.add((char *)"BGP");
                break;

            case EIGRP_TLV_IEU_EPID_IDRP:
                output_string.add((char *)"IDRP");
                break;

            case EIGRP_TLV_IEU_EPID_CONNECTED:
                output_string.add((char *)"IDRP");
                break;

            default:
                output_string.add((char *)"NONE");
            }

            output_string.add_hex((char *)")  FLAGS 0x%02X\n",
                                  tlv_ipextup.get_flags());

            output_string.add(
                (char *)"\tDELAY %u  BW %u  MTU %u  HOPCOUNT %u  REL %u  LOAD %u \n",
                tlv_ipextup.get_delay(),
                tlv_ipextup.get_bandwidth(),
                tlv_ipextup.get_mtu(),
                tlv_ipextup.get_hopcount(),
                tlv_ipextup.get_reliability(),
                tlv_ipextup.get_load());

            break;
        }
        }

        i += tlv.get_len();
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
