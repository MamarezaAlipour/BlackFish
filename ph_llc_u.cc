#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string print_sap(byte);

c_string llc_u_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_llc_u_header header(packet_info.packet);

    output_string.add((char *)"LLC U\t");

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

    output_string.add_hex((char *)"0x%02X ",
                          header.get_ctrl());

    output_string.add_bin((char *)"(%u%u%u|%u|%u%u|%u%u) ",
                          header.get_ctrl());

    output_string.add((char *)"(U-type");

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

    switch (header.get_ctrl_m())
    {
    case LLC_U_M_UI:
        output_string.add((char *)", UI");
        break;

    case LLC_U_M_SABME:
        output_string.add((char *)", SABME");
        break;

    case LLC_U_M_DISC:
        output_string.add((char *)", DISC");
        break;

    case LLC_U_M_UA:
        output_string.add((char *)", UA");
        break;

    case LLC_U_M_DM:
        output_string.add((char *)", DM");
        break;

    case LLC_U_M_FRMR:
        output_string.add((char *)", FRMR");
        break;

    case LLC_U_M_XID:
        output_string.add((char *)", XID");
        break;

    case LLC_U_M_TEST:
        output_string.add((char *)", TEST");
        break;
    }

    output_string.add((char *)")");

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
