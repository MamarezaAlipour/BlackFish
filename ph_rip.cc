#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string rip_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_rip_header header(packet_info.packet);

    output_string.add((char *)"RIP\t");
    output_string.add((char *)"CMD %u (",
                      header.get_cmd());

    switch (header.get_cmd())
    {
    case RIP_CMD_REQUEST:
        output_string.add((char *)"REQUEST");
        break;

    case RIP_CMD_RESPONSE:
        output_string.add((char *)"RESPONSE");
        break;

    default:
        output_string.add((char *)"UNKNOWN");
    }

    output_string.add((char *)")  VER %u  (ROUTES %u)\n",
                      header.get_ver(),
                      packet_info.rip_entries_len / RIP_ENTRY_LEN);

    if (packet_info.rip_authentry)
    {
        c_rip_authentry authentry(packet_info.rip_authentry);

        output_string.add((char *)"\n[AUTH]\tAUTHTYPE %u (",
                          authentry.get_type());

        switch (authentry.get_type())
        {
        case RIP_AUTHTYPE_SIMPLE:
            output_string.add((char *)"SIMPLE");
            output_string.add((char *)")  AUTHKEY ");
            output_string.add_raw((byte *)authentry.get_key(), 16);
            break;

        case RIP_AUTHTYPE_MD5:
        {
            output_string.add((char *)"MD5");
            output_string.add((char *)")  LEN %u  KEYID %u  ADLEN %u  SEQ %u",
                              authentry.get_len(),
                              authentry.get_keyid(),
                              authentry.get_adlen(),
                              authentry.get_seq());
            break;
        }

        default:
            output_string.add((char *)"UNKNOWN");
        }

        output_string.add((char *)"\n");
    }

    for (u_int i = 0; i < packet_info.rip_entries_len / RIP_ENTRY_LEN; i++)
    {
        c_rip_entry entry(packet_info.rip_entries + i * RIP_ENTRY_LEN);

        string ip_string[16];
        string mask_string[16];
        string nexthop_string[16];

        conv_ip_str(ip_string, entry.get_ip());
        conv_ip_str(mask_string, entry.get_mask());
        conv_ip_str(nexthop_string, entry.get_nexthop());

        output_string.add((char *)"\n[ROUTE]\t");

        switch (header.get_ver())
        {
        case 1:
        {
            output_string.add((char *)"AFI %u (",
                              entry.get_afi());

            switch (entry.get_afi())
            {
            case AFI_INET:
                output_string.add((char *)"INET");
                break;

            default:
                output_string.add((char *)"UNKNOWN");
            }

            output_string.add((char *)")  IP %s  METRIC %u",
                              ip_string,
                              entry.get_metric());

            break;
        }

        case 2:
        {
            output_string.add((char *)"AFI %u (",
                              entry.get_afi());

            switch (entry.get_afi())
            {
            case AFI_INET:
                output_string.add((char *)"INET");
                break;

            default:
                output_string.add((char *)"UNKNOWN");
            }

            output_string.add((char *)")  TAG %u  IP %s  MASK %s\n",
                              entry.get_tag(),
                              ip_string,
                              mask_string);

            output_string.add((char *)"\tNEXTHOP %s  METRIC %u",
                              nexthop_string,
                              entry.get_metric());

            break;
        }
        }

        output_string.add((char *)"\n");
    }

    if (packet_info.rip_authentry)
    {
        c_rip_authentry authentry(packet_info.rip_authentry);

        if (authentry.get_type() == RIP_AUTHTYPE_MD5)
        {
            c_rip_md5entry md5entry(packet_info.rip_md5entry);

            output_string.add((char *)"\n[MD5]\t");
            output_string += print_hex_data(md5entry.get_key(), 16, false);
            output_string.add((char *)"\n");
        }
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}
