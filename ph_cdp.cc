#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string cdp_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_cdp_header header(packet_info.packet);

    output_string.add((char *)"CDP\t");
    output_string.add((char *)"VER %u  TTL %u  CKSUM %u ",
                      header.get_ver(),
                      header.get_ttl(),
                      header.get_cksum());

    if (!cksum(packet_info.packet, packet_info.packet_len))
    {
        output_string.add((char *)"(OK)");
    }
    else
    {
        output_string.add((char *)"(BAD)");
    }

    output_string.add((char *)"\n");

    byte *cdp_data = packet_info.packet + CDP_HEADER_LEN;

    while (cdp_data < packet_info.packet + packet_info.packet_len)
    {
        c_cdp_dheader dheader(cdp_data);

        output_string.add_hex((char *)"\tTYPE 0x%02X%02X (",
                              dheader.get_type());

        switch (dheader.get_type())
        {

        case CDP_DHEADER_TYPE_DEVICE_ID:
            output_string += "Device ID";
            break;

        case CDP_DHEADER_TYPE_ADDRESS:
            output_string += "Address";
            break;

        case CDP_DHEADER_TYPE_PORT_ID:
            output_string += "Port ID";
            break;

        case CDP_DHEADER_TYPE_CAPABILITIES:
            output_string += "Capabil.";
            break;

        case CDP_DHEADER_TYPE_VERSION:
            output_string += "Version";
            break;

        case CDP_DHEADER_TYPE_PLATFORM:
            output_string += "Platform";
            break;

        case CDP_DHEADER_TYPE_IP_PREFIX:
            output_string += "IP Prefix";
            break;

        default:
            output_string += "Unknown";
        }

        output_string.add((char *)")\t  LEN %u  ",
                          dheader.get_len());

        output_string += "\n";

        cdp_data += dheader.get_len();
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
