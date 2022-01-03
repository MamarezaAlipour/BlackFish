#include <netz.h>

#include "ip_proto.h"
#include "ph_packet.h"
#include "support.h"

c_string ip_options_handler(c_packet_info);
c_string ip_option_handler(byte *, u_int &);
c_string ip_option_handler(c_ipopt_eol);
c_string ip_option_handler(c_ipopt_nop);
c_string ip_option_handler(c_ipopt_rr);
c_string ip_option_handler(c_ipopt_pmtu);
c_string ip_option_handler(c_ipopt_rmtu);
c_string ip_option_handler(c_ipopt_ts);
c_string ip_option_handler(c_ipopt_tr);
c_string ip_option_handler(c_ipopt_sec);
c_string ip_option_handler(c_ipopt_lsrr);
c_string ip_option_handler(c_ipopt_xsec);
c_string ip_option_handler(c_ipopt_satid);
c_string ip_option_handler(c_ipopt_ssrr);
c_string ip_option_handler(c_ipopt_generic);

c_string ip_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ip_header header(packet_info.header);

    output_string.add((char *)"IP\t");

    string ip_src_string[16];
    string ip_dst_string[16];

    conv_ip_str(ip_src_string, header.get_src());
    conv_ip_str(ip_dst_string, header.get_dst());

    output_string.add((char *)"SRC %s  DST %s  ",
                      ip_src_string,
                      ip_dst_string);

    output_string.add((char *)"VER %u  ",
                      header.get_ver());

    output_string.add((char *)"CKSUM %u ",
                      header.get_cksum());

    if (!cksum((byte *)header.get_header(), header.get_hlen()))
    {
        output_string.add((char *)"(OK)");
    }
    else
    {
        output_string.add((char *)"(BAD)");
    }

    output_string.add_hex((char *)"\n\tTOS 0x%02X ",
                          header.get_tos());

    output_string.add_hex((char *)"(PREC 0x%02X ",
                          header.get_tos_prec());

    switch (header.get_tos_prec())
    {
    case IP_TOS_PREC_NETCONTROL:
        output_string.add((char *)"Network Control");
        break;

    case IP_TOS_PREC_INTERNETCONTROL:
        output_string.add((char *)"Internetwork Control");
        break;

    case IP_TOS_PREC_CRITICECP:
        output_string.add((char *)"CRITIC/ECP");
        break;

    case IP_TOS_PREC_FLASHOVERRIDE:
        output_string.add((char *)"Flash Overide");
        break;

    case IP_TOS_PREC_FLASH:
        output_string.add((char *)"Flash");
        break;

    case IP_TOS_PREC_IMMEDIATE:
        output_string.add((char *)"Immediate");
        break;

    case IP_TOS_PREC_PRIORITY:
        output_string.add((char *)"Priority");
        break;

    case IP_TOS_PREC_ROUTINE:
        output_string.add((char *)"Routine");
        break;

    default:
        output_string.add((char *)"Unknown");
    }

    output_string.add((char *)", FLAGS |");

    if (header.get_tos_delay())
    {
        output_string.add((char *)"D|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_tos_throughput())
    {
        output_string.add((char *)"T|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_tos_reliability())
    {
        output_string.add((char *)"R|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_tos_ectcap())
    {
        output_string.add((char *)"E|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    if (header.get_tos_congestion())
    {
        output_string.add((char *)"C|");
    }
    else
    {
        output_string.add((char *)" |");
    }

    output_string.add((char *)")\n");

    output_string.add((char *)"\tTTL %u  ID %u  ",
                      header.get_ttl(),
                      header.get_id());

    output_string.add_hex((char *)"FRAG 0x%02X ",
                          header.get_frag());

    output_string.add((char *)"(FLAGS |");

    if (header.get_frag_rf())
    {
        output_string.add((char *)"RF|");
    }
    else
    {
        output_string.add((char *)"  |");
    }

    if (header.get_frag_df())
    {
        output_string.add((char *)"DF|");
    }
    else
    {
        output_string.add((char *)"  |");
    }

    if (header.get_frag_mf())
    {
        output_string.add((char *)"MF|");
    }
    else
    {
        output_string.add((char *)"  |");
    }

    output_string.add((char *)", OFFSET %u)  ",
                      header.get_frag_off());

    output_string.add((char *)"\n\tHLEN %u  PLEN %u  OLEN %u  DLEN %u  ",
                      header.get_hlen(),
                      header.get_len(),
                      header.get_hlen() - sizeof(s_ip_header),
                      header.get_len() - header.get_hlen());

    output_string.add((char *)"PROTO %u (",
                      header.get_proto());

    output_string += print_ip_proto(header.get_proto());

    output_string.add((char *)")");

    output_string += ip_options_handler(packet_info);

    output_string.add((char *)"\n");

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string ip_options_handler(c_packet_info packet_info)
{
    c_string output_string;

    if (packet_info.ip_options)
    {
        c_string options_string;

        u_int pos = 0;

        while (pos < packet_info.ip_options_len)
        {
            options_string += ip_option_handler(packet_info.ip_options, pos);
        }

        output_string = print_options_string(options_string);
    }

    return output_string;
}

c_string ip_option_handler(byte *options, u_int &pos)
{
    c_string option_string;

    option_string.add((char *)"[");

    switch (c_ipopt_generic(options + pos).get_code())
    {
    case IPOPT_EOL:
    {
        c_ipopt_eol option(options + pos);
        pos += option.get_len() + 64;
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_NOP:
    {
        c_ipopt_nop option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_RR:
    {
        c_ipopt_rr option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_TS:
    {
        c_ipopt_ts option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_TR:
    {
        c_ipopt_tr option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_SEC:
    {
        c_ipopt_sec option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_XSEC:
    {
        c_ipopt_xsec option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_LSRR:
    {
        c_ipopt_lsrr option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_SATID:
    {
        c_ipopt_satid option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_SSRR:
    {
        c_ipopt_ssrr option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_PMTU:
    {
        c_ipopt_pmtu option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    case IPOPT_RMTU:
    {
        c_ipopt_rmtu option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
        break;
    }

    default:
    {
        c_ipopt_generic option(options + pos);
        pos += option.get_len();
        option_string += ip_option_handler(option);
    }
    }

    option_string.add((char *)"] ");

    return option_string;
}

c_string ip_option_handler(c_ipopt_eol)
{
    c_string option_string;

    option_string.add((char *)"eol");

    return option_string;
}

c_string ip_option_handler(c_ipopt_nop)
{
    c_string option_string;

    option_string.add((char *)"nop");

    return option_string;
}

c_string ip_option_handler(c_ipopt_rr option)
{
    c_string option_string;

    u_int rr_count = (option.get_ptr() - 4) / IPOPT_RR_DATALEN;

    option_string.add((char *)"rr %u(%u)",
                      option.get_ptr(),
                      rr_count);

    for (u_int i = 0; i < rr_count; i++)
    {
        string ip_string[16];

        option_string.add((char *)" {%s}",
                          conv_ip_str(ip_string, option.get_ip(i)));
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_pmtu option)
{
    c_string option_string;

    option_string.add((char *)"pmtu %u",
                      option.get_mtu());

    return option_string;
}

c_string ip_option_handler(c_ipopt_rmtu option)
{
    c_string option_string;

    option_string.add((char *)"rmtu %u",
                      option.get_mtu());

    return option_string;
}

c_string ip_option_handler(c_ipopt_ts option)
{
    c_string option_string;

    u_int ts_count = 0;

    option_string.add((char *)"ts %u",
                      option.get_ptr());

    switch (option.get_flags())
    {
    case IPOPT_TS_TSONLY:

        ts_count = (option.get_ptr() - 5) / IPOPT_TS_TSONLY_DATALEN;

        option_string.add((char *)"(%u) %u %u ",
                          ts_count,
                          option.get_ovflow(),
                          option.get_flags());

        for (u_int i = 0; i < ts_count; i++)
        {
            option_string.add((char *)" {%u}",
                              option.get_timestamp(i));
        }

        break;

    case IPOPT_TS_TSANDADDR:

        ts_count = (option.get_ptr() - 5) / IPOPT_TS_TSANDADDR_DATALEN;

        option_string.add((char *)"(%u) %u %u ",
                          ts_count,
                          option.get_ovflow(),
                          option.get_flags());

        for (u_int i = 0; i < ts_count; i++)
        {
            string ip_string[16];

            option_string.add((char *)" {%s : %u}",
                              conv_ip_str(ip_string, option.get_ip(i)),
                              option.get_timestamp(i));
        }

        break;

    case IPOPT_TS_PRESPEC:

        ts_count = (option.get_ptr() - 5) / IPOPT_TS_PRESPEC_DATALEN;

        option_string.add((char *)"(%u) %u %u ",
                          ts_count,
                          option.get_ovflow(),
                          option.get_flags());

        for (u_int i = 0; i < ts_count; i++)
        {
            string ip_string[16];

            option_string.add((char *)" {%s : %u}",
                              conv_ip_str(ip_string, option.get_ip(i)),
                              option.get_timestamp(i));
        }

        break;
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_tr option)
{
    c_string option_string;

    string ip_string[16];

    option_string.add((char *)"tr %u %u %u %s",
                      option.get_id(),
                      option.get_ohcount(),
                      option.get_rhcount(),
                      conv_ip_str(ip_string, option.get_originator()));

    return option_string;
}

c_string ip_option_handler(c_ipopt_sec option)
{
    c_string option_string;

    option_string.add((char *)"sec %u (",
                      option.get_cl());

    switch (option.get_cl())
    {
    case 222:
        option_string.add((char *)"Top Secret");
        break;

    case 173:
        option_string.add((char *)"Secret");
        break;

    case 122:
        option_string.add((char *)"Confidential");
        break;

    case 85:
        option_string.add((char *)"Unclasified");
        break;

    default:
        option_string.add((char *)"Unknown");
    }

    option_string.add((char *)")");

    if (option.get_len() > IPOPT_SEC_LEN)
    {
        u_int i = 0;
        bool coma_flag;

        do
        {
            option_string.add((char *)" {");

            coma_flag = 0;

            if (option.get_flags(i) & 128)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"GENSEC");
                coma_flag = true;
            }

            if (option.get_flags(i) & 64)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"SIOP-ESI");
                coma_flag = true;
            }

            if (option.get_flags(i) & 32)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"SCI");
                coma_flag = true;
            }

            if (option.get_flags(i) & 16)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"NSA");
                coma_flag = true;
            }

            if (option.get_flags(i) & 8)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"DOE");
                coma_flag = true;
            }

            option_string.add((char *)"}");

            i++;
        } while (option.get_flags(i - 1) & 1);
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_lsrr option)
{
    c_string option_string;

    u_int lsrr_count = (option.get_ptr() - 4) / IPOPT_LSRR_DATALEN;

    option_string.add((char *)"lsrr %u(%u)",
                      option.get_ptr(),
                      lsrr_count);

    for (u_int i = 0; i < lsrr_count; i++)
    {
        string ip_string[16];

        option_string.add((char *)" {%s}",
                          conv_ip_str(ip_string, option.get_ip(i)));
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_xsec option)
{
    c_string option_string;

    option_string.add((char *)"xsec %u",
                      option.get_asiac());

    if (option.get_len() > IPOPT_XSEC_LEN)
    {
        u_int i = 0;
        bool coma_flag;

        do
        {
            option_string.add((char *)" {");

            coma_flag = 0;

            if (option.get_flags(i) & 128)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"GENSER");
                coma_flag = true;
            }

            if (option.get_flags(i) & 64)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"SIOP");
                coma_flag = true;
            }

            if (option.get_flags(i) & 32)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"DSCCS-SPINTCOM");
                coma_flag = true;
            }

            if (option.get_flags(i) & 16)
            {
                if (coma_flag)
                    option_string.add((char *)", ");
                option_string.add((char *)"DSCCS-CRITICOM");
                coma_flag = true;
            }

            option_string.add((char *)"}");

            i++;
        } while (option.get_flags(i - 1) & 1);
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_satid option)
{
    c_string option_string;

    option_string.add((char *)"satid %u",
                      option.get_id());

    return option_string;
}

c_string ip_option_handler(c_ipopt_ssrr option)
{
    c_string option_string;

    u_int ssrr_count = (option.get_ptr() - 4) / IPOPT_SSRR_DATALEN;

    option_string.add((char *)"ssrr %u(%u)",
                      option.get_ptr(),
                      ssrr_count);

    for (u_int i = 0; i < ssrr_count; i++)
    {
        string ip_string[16];

        option_string.add((char *)" {%s}",
                          conv_ip_str(ip_string, option.get_ip(i)));
    }

    return option_string;
}

c_string ip_option_handler(c_ipopt_generic option)
{
    c_string option_string;

    option_string.add((char *)"unknown %u %u(%u) {",
                      option.get_code(),
                      option.get_len(),
                      option.get_len() - 2);

    for (u_int i = 0; i < (u_int)(option.get_len() - 2); i++)
    {
        option_string.add((char *)"0x%02X",
                          option.get_data() + i);

        if (i + 1 < (u_int)(option.get_len() - 2))
        {
            option_string.add((char *)" ");
        }
    }

    option_string.add((char *)"}");

    return option_string;
}
