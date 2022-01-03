#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string print_sap(byte);

c_string llc_i_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_llc_i_header header(packet_info.packet);

    output_string.add((char *)"LLC I\t");

    output_string.add_hex((char *)"DSAP 0x%02X ",
                          header.get_dsap());

    output_string.add_bin((char *)"(%u%u%u%u%u%u%u|%u) (",
                          header.get_dsap());

    output_string += print_sap(header.get_dsap());

    if (header.get_dsap_ig())
    {
        output_string.add((char *)", Group Address");
    }
    else
    {
        output_string.add((char *)", Individual Address");
    }

    output_string.add((char *)")\n");

    output_string.add_hex((char *)"\tSSAP 0x%02X ",
                          header.get_ssap());

    output_string.add_bin((char *)"(%u%u%u%u%u%u%u|%u) (",
                          header.get_ssap());

    output_string += print_sap(header.get_ssap());

    if (header.get_ssap_cr())
    {
        output_string.add((char *)", Response");
    }
    else
    {
        output_string.add((char *)", Command");
    }

    output_string.add((char *)")\n");

    output_string.add((char *)"\tCTRL ");

    output_string.add_hex((char *)"0x%02X%02X ",
                          header.get_ctrl());

    output_string.add_bin((char *)"(%u%u%u%u%u%u%u|%u|%u%u%u%u%u%u%u|%u|) ",
                          header.get_ctrl());

    output_string.add((char *)"(I-type, N(S) %u, N(R) %u",
                      header.get_ctrl_ns(),
                      header.get_ctrl_ns());

    if (header.get_ctrl_pf())
    {
        if (header.get_ssap_cr())
        {
            output_string.add((char *)", Finall");
        }
        else
        {
            output_string.add((char *)", Poll");
        }
    }

    output_string.add((char *)")\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_sap(byte sap)
{
    switch (sap)
    {
    case LLC_SAP_NLSAP:
        return c_string((char *)"Null LSAP");

    case LLC_SAP_ILSM:
        return c_string((char *)"Individual LLC Sublayer Management");

    case LLC_SAP_GLSM:
        return c_string((char *)"Group LLC Sublayer Management");

    case LLC_SAP_SNAPC:
        return c_string((char *)"SNA Path Control");

    case LLC_SAP_DODIP:
        return c_string((char *)"DoD IP");

    case LLC_SAP_PLAN_0E:
        return c_string((char *)"PROWAY-LAN");

    case LLC_SAP_EIA:
        return c_string((char *)"EIA-RS 511");

    case LLC_SAP_ISIIP:
        return c_string((char *)"ISI IP");

    case LLC_SAP_PLAN_8E:
        return c_string((char *)"PROWAY-LAN");

    case LLC_SAP_3COM:
        return c_string((char *)"3Com");

    case LLC_SAP_SNAP:
        return c_string((char *)"SNAP");

    case LLC_SAP_BC:
        return c_string((char *)"Banyan");

    case LLC_SAP_LANMAN:
        return c_string((char *)"Lan Manager");

    case LLC_SAP_NOVELL:
        return c_string((char *)"Novell");

    case LLC_SAP_NETBEUI:
        return c_string((char *)"NetBEUI");

    case LLC_SAP_CLNS:
        return c_string((char *)"ISO CLNS IS 8473");

    case LLC_SAP_GLOBAL:
        return c_string((char *)"Global DSAP");

    default:
        return c_string((char *)"Unknown");
    }
}
