#include <netz.h>

#include "ether_type.h"
#include "support.h"
#include "ph_packet.h"

c_string gre_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_gre_header header(packet_info.packet);

    output_string.add((char *)"GRE\tFLAGS |");

    if (header.get_flag_cksum())
    {
        output_string.add((char *)"C|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_flag_routing())
    {
        output_string.add((char *)"R|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_flag_key())
    {
        output_string.add((char *)"K|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_flag_seq())
    {
        output_string.add((char *)"S|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_flag_ssr())
    {
        output_string.add((char *)"s|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    output_string.add((char *)"  RECUR %u  VER %u  ",
                      header.get_recur(),
                      header.get_ver());

    output_string.add_hex((char *)"TYPE 0x%02X%02X (",
                          header.get_type());

    output_string += print_ether_type(header.get_type());

    output_string.add((char *)")");

    if (header.get_flag_cksum() | header.get_flag_routing() | header.get_flag_key() | header.get_flag_seq() | header.get_flag_routing())
    {
        output_string.add((char *)"\n\t");
    }

    if (header.get_flag_cksum())
    {
        output_string.add((char *)"CKSUM %u ",
                          header.get_cksum());

        if (!cksum(packet_info.packet, packet_info.packet_len))
        {
            output_string.add((char *)"(OK)");
        }
        else
        {
            output_string.add((char *)"(BAD)");
        }

        output_string.add((char *)"  ");
    }

    if (header.get_flag_routing())
    {
        output_string.add((char *)"OFFSET %u  ",
                          header.get_offset());
    }

    if (header.get_flag_key())
    {
        output_string.add((char *)"KEY %u  ",
                          header.get_key());
    }

    if (header.get_flag_seq())
    {
        output_string.add((char *)"SEQ %u  ",
                          header.get_offset());
    }

    output_string.add((char *)"\n");

    if (header.get_flag_routing())
    {
        output_string.add((char *)"\n");

        /* missing SRR handler here */
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
