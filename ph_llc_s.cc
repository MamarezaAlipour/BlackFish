#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string print_sap(byte);

c_string llc_s_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_llc_s_header header(packet_info.packet);

    output_string.add((char *)"LLC S\t");

    output_string.add_hex((char *)"DSAP 0x%02X ",
                          header.get_dsap());

    output_string.add_bin((char *)"(%u%u%u%u%u%u%u|%u) (",
                          header.get_dsap());

    output_string += print_sap(header.get_dsap());

    if (header.get_dsap() & LLC_DSAP_IG_MASK)
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

    if (header.get_dsap() & LLC_SSAP_CR_MASK)
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

    output_string.add_bin((char *)"(%u%u%u%u|%u%u|%u%u|%u%u%u%u%u%u%u|%u|) ",
                          header.get_ctrl());

    output_string.add((char *)"(S-type, N(R) %u",
                      header.get_ctrl_nr());

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

    switch (header.get_ctrl_s())
    {
    case LLC_S_S_RR:
        output_string.add((char *)", RR");
        break;

    case LLC_S_S_RNR:
        output_string.add((char *)", RNR");
        break;

    case LLC_S_S_REJ:
        output_string.add((char *)", REJ");
        break;
    }

    output_string.add((char *)")");

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
