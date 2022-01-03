#include <netz.h>

#include "support.h"
#include "ph_packet.h"

c_string print_ospf_hello_packet(c_ospf_hello_packet);
c_string print_ospf_dd_packet(c_ospf_hello_packet);
c_string print_ospf_lsr_packet(c_ospf_hello_packet);
c_string print_ospf_lsu_packet(c_ospf_hello_packet);
c_string print_ospf_lsa_packet(c_ospf_hello_packet);

c_string print_ospf_lsa_header(c_ospf_lsa_header);

c_string ospf_packet_handler(c_packet_info packet_info)
{
    c_string output_string;

    c_ospf_header header(packet_info.packet);

    bool lls_present = false;
    bool md5_present = false;

    output_string.add((char *)"OSPF\t");

    output_string.add((char *)"TYPE %u (",
                      header.get_type());

    switch (header.get_type())
    {
    case OSPF_TYPE_HELLO_PACKET:
        output_string.add((char *)"Hello");
        break;

    case OSPF_TYPE_DD_PACKET:
        output_string.add((char *)"DD");
        break;

    case OSPF_TYPE_LSR_PACKET:
        output_string.add((char *)"LSR");
        break;

    case OSPF_TYPE_LSU_PACKET:
        output_string.add((char *)"LSU");
        break;

    case OSPF_TYPE_LSA_PACKET:
        output_string.add((char *)"LSA");
        break;

    default:
        output_string.add((char *)"Unknown");
    };

    output_string.add((char *)")  ");

    string router_id_string[16];
    string area_id_string[16];

    conv_ip_str(router_id_string, header.get_routerid());
    conv_ip_str(area_id_string, header.get_areaid());

    output_string.add((char *)"ROUTER ID %s  AREA ID %s\n",
                      router_id_string,
                      area_id_string);

    output_string.add((char *)"\tVER %u  PLEN %u  (TPLEN %u)  CKSUM %u ",
                      header.get_ver(),
                      header.get_plen(),
                      packet_info.packet_len,
                      header.get_cksum());

    if (header.get_authtype() == OSPF_AUTHTYPE_CRYPTO)
    {
        output_string.add((char *)"(NONE)");
    }
    else
    {
        if (!cksum(packet_info.packet, header.get_plen()))
        {
            output_string.add((char *)"(OK)");
        }
        else
        {
            output_string.add((char *)"(BAD)");
        }
    }

    output_string.add((char *)"  AUTH TYPE %u (",
                      header.get_authtype());

    switch (header.get_authtype())
    {
    case OSPF_AUTHTYPE_NULL:
        output_string.add((char *)"Null");
        break;

    case OSPF_AUTHTYPE_PASSWORD:
        output_string.add((char *)"Password");
        break;

    case OSPF_AUTHTYPE_CRYPTO:
        md5_present = true;
        output_string.add((char *)"Crypto");
        break;

    default:
        output_string.add((char *)"Unknown");
    }

    output_string.add((char *)")\n");

    if (header.get_authtype() == OSPF_AUTHTYPE_PASSWORD)
    {
        output_string.add((char *)"\tPASSWORD %s\n",
                          header.get_password());
    }

    if (header.get_authtype() == OSPF_AUTHTYPE_CRYPTO)
    {
        output_string.add((char *)"\tAUTH KEY ID %u  AUTH DATA LEN %u  AUTH SEQ %u\n",
                          header.get_keyid(),
                          header.get_adlen(),
                          header.get_cryptoseq());
    }

    if (header.get_type() == OSPF_TYPE_HELLO_PACKET)
    {
        c_ospf_hello_packet hello_packet(packet_info.packet + OSPF_HEADER_LEN);

        string netmask_string[16];

        conv_ip_str(netmask_string, hello_packet.get_netmask());

        output_string.add((char *)"\tNETMASK %s  HELLO INT %u  ",
                          netmask_string,
                          hello_packet.get_hellointerval());

        output_string.add_hex((char *)"OPTIONS 0x%02X [ ",
                              hello_packet.get_options());

        if (hello_packet.get_option_dc())
        {
            output_string.add((char *)"DC ");
        }

        if (hello_packet.get_option_l())
        {
            lls_present = true;
            output_string.add((char *)"L ");
        }

        if (hello_packet.get_option_np())
        {
            output_string.add((char *)"N/P ");
        }

        if (hello_packet.get_option_mc())
        {
            output_string.add((char *)"MC ");
        }

        if (hello_packet.get_option_e())
        {
            output_string.add((char *)"E ");
        }

        output_string.add((char *)"]");

        output_string.add((char *)"\n");

        string dr_string[16];
        string bdr_string[16];

        conv_ip_str(dr_string, hello_packet.get_dr());
        conv_ip_str(bdr_string, hello_packet.get_bdr());

        output_string.add((char *)"\tPRIORITY %u  DEAD INT %u  DR %s  BDR %s\n",
                          hello_packet.get_priority(),
                          hello_packet.get_deadinterval(),
                          dr_string,
                          bdr_string);

        u_int neighbors_len = header.get_plen() - OSPF_HEADER_LEN - OSPF_HELLO_PACKET_LEN;

        for (u_int i = 0; i < neighbors_len / 4; i++)
        {
            string neighbor_string[16];
            conv_ip_str(neighbor_string, hello_packet.get_neighbor(i));

            output_string.add((char *)"\tNEIGHBOR %u - %s\n",
                              i,
                              neighbor_string);
        }
    }

    if (header.get_type() == OSPF_TYPE_DD_PACKET)
    {
        c_ospf_dd_packet dd_packet(packet_info.packet + OSPF_HEADER_LEN);

        output_string.add((char *)"\tMTU %u  ",
                          dd_packet.get_mtu());

        output_string.add_hex((char *)"OPTIONS 0x%02X%02X [ ",
                              dd_packet.get_options());

        if (dd_packet.get_option_i())
        {
            output_string.add((char *)"I ");
        }

        if (dd_packet.get_option_m())
        {
            output_string.add((char *)"M ");
        }

        if (dd_packet.get_option_ms())
        {
            output_string.add((char *)"MS ");
        }

        output_string.add((char *)"]  SEQ %u\n",
                          dd_packet.get_seq());

        u_int lsa_offset = OSPF_HEADER_LEN + OSPF_DD_PACKET_LEN;

        while (lsa_offset < header.get_plen())
        {
            c_ospf_lsa_header lsa_header(packet_info.packet + lsa_offset);

            output_string += print_ospf_lsa_header(lsa_header);
            output_string += "\n";

            lsa_offset += OSPF_LSA_HEADER_LEN;
        }
    }

    if (header.get_type() == OSPF_TYPE_LSR_PACKET)
    {
        u_int lsr_offset = OSPF_HEADER_LEN;

        while (lsr_offset < header.get_plen())
        {
            c_ospf_lsr_packet lsr_packet(packet_info.packet + lsr_offset);

            output_string.add((char *)"\nLSA %u\tTYPE %u (",
                              lsr_packet.get_type(),
                              lsr_packet.get_type());

            switch (lsr_packet.get_type())
            {
            case OSPF_LSA_HEADER_TYPE_1:
                output_string.add((char *)"Router");
                break;

            case OSPF_LSA_HEADER_TYPE_2:
                output_string.add((char *)"Network");
                break;

            case OSPF_LSA_HEADER_TYPE_3:
                output_string.add((char *)"Summary IP network");
                break;

            case OSPF_LSA_HEADER_TYPE_4:
                output_string.add((char *)"Summary ASBR");
                break;

            case OSPF_LSA_HEADER_TYPE_5:
                output_string.add((char *)"AS External");
                break;

            case OSPF_LSA_HEADER_TYPE_7:
                output_string.add((char *)"NSSA");
                break;

            default:
                output_string.add((char *)"Unknown");
            }

            output_string.add((char *)")  LS ID %u  ",
                              lsr_packet.get_id());

            string advrtr_string[16];

            conv_ip_str(advrtr_string, lsr_packet.get_advrtr());

            output_string.add((char *)"ADV RTR %s\n",
                              advrtr_string);

            lsr_offset += OSPF_LSR_PACKET_LEN;
        }
    }

    if (header.get_type() == OSPF_TYPE_LSU_PACKET)
    {
        c_ospf_lsu_packet lsu_packet(packet_info.packet + OSPF_HEADER_LEN);

        output_string.add((char *)"\tLSA COUNT %u\n",
                          lsu_packet.get_lcount());

        u_int lsa_offset = OSPF_HEADER_LEN + OSPF_LSU_PACKET_LEN;

        u_int i = lsu_packet.get_lcount();

        while (i--)
        {
            c_ospf_lsa_header lsa_header(packet_info.packet + lsa_offset);

            if (lsa_header.get_option_l())
            {
                lls_present = true;
            }

            output_string += print_ospf_lsa_header(lsa_header);

            if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_1)
            {
                c_ospf_lsa_1_body lsa_1_body(packet_info.packet + lsa_offset + OSPF_LSA_HEADER_LEN);

                output_string.add_hex((char *)"  OPTIONS 0x%02X [ ",
                                      lsa_1_body.get_flags());

                if (lsa_1_body.get_flag_v())
                {
                    output_string.add((char *)"V ");
                }

                if (lsa_1_body.get_flag_e())
                {
                    output_string.add((char *)"E ");
                }

                if (lsa_1_body.get_flag_b())
                {
                    output_string.add((char *)"B ");
                }

                if (lsa_1_body.get_flag_w())
                {
                    output_string.add((char *)"W ");
                }

                if (lsa_1_body.get_flag_nt())
                {
                    output_string.add((char *)"Nt ");
                }

                output_string.add((char *)"]  LINK COUNT %u\n",
                                  lsa_1_body.get_lcount());

                u_int link_offset = lsa_offset + OSPF_LSA_HEADER_LEN + OSPF_LSA_1_BODY_LEN;

                u_int j = lsa_1_body.get_lcount();

                while (j--)
                {
                    c_ospf_lsa_1_link lsa_1_link(packet_info.packet + link_offset);

                    output_string += "\t";

                    string id_string[16];
                    string data_string[16];

                    conv_ip_str(id_string, lsa_1_link.get_id());
                    conv_ip_str(data_string, lsa_1_link.get_data());

                    output_string.add((char *)"ID %s  DATA %s  ",
                                      id_string,
                                      data_string);

                    output_string.add((char *)"TYPE %u (",
                                      lsa_1_link.get_type());

                    switch (lsa_1_link.get_type())
                    {
                    case OSPF_LSA_1_LINK_TYPE_P2P:
                        output_string.add((char *)"P2P");
                        break;

                    case OSPF_LSA_1_LINK_TYPE_TRANSIT:
                        output_string.add((char *)"Transit");
                        break;

                    case OSPF_LSA_1_LINK_TYPE_STUB:
                        output_string.add((char *)"Stub");
                        break;

                    case OSPF_LSA_1_LINK_TYPE_VIRTUAL:
                        output_string.add((char *)"Virtual");
                        break;

                    default:
                        output_string.add((char *)"Unknown");
                    }

                    output_string.add((char *)")  METRIC %u",
                                      lsa_1_link.get_metric());

                    output_string.add((char *)"\n");

                    u_int tos_offset = link_offset + OSPF_LSA_1_LINK_LEN;

                    u_int k = lsa_1_link.get_tcount();

                    while (k--)
                    {
                        /* we dont show TOS fields as they are obsolete */
                        tos_offset += OSPF_LSA_1_LINK_TOS_LEN;
                    }

                    link_offset += OSPF_LSA_1_LINK_LEN + lsa_1_link.get_tcount() * OSPF_LSA_1_LINK_TOS_LEN;
                }
            }

            else if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_2)
            {
                u_int link_offset = lsa_offset + OSPF_LSA_HEADER_LEN;

                output_string += "\n";

                while (link_offset < lsa_offset + lsa_header.get_len())
                {
                    c_ospf_lsa_2_link lsa_2_link(packet_info.packet + link_offset);

                    output_string.add((char *)"\t");

                    string netmask_string[16];
                    string attrtr_string[16];

                    conv_ip_str(netmask_string, lsa_2_link.get_netmask());
                    conv_ip_str(attrtr_string, lsa_2_link.get_attrtr());

                    output_string.add((char *)"NETMASK %s  ATTACHED ROUTER %s\n",
                                      netmask_string,
                                      attrtr_string);

                    link_offset += OSPF_LSA_2_LINK_LEN;
                }
            }

            else if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_3)
            {
                c_ospf_lsa_3_body lsa_3_link(packet_info.packet + lsa_offset + OSPF_LSA_HEADER_LEN);

                string netmask_string[16];

                conv_ip_str(netmask_string, lsa_3_link.get_netmask());

                output_string.add((char *)"  NETMASK %s  METRIC %u\n",
                                  netmask_string,
                                  lsa_3_link.get_metric());

                /* we dont support TOS fields as they are obsolete */
            }

            else if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_4)
            {
                c_ospf_lsa_4_body lsa_4_link(packet_info.packet + lsa_offset + OSPF_LSA_HEADER_LEN);

                output_string.add((char *)"  METRIC %u\n",
                                  lsa_4_link.get_metric());

                /* we dont support TOS fields as they are obsolete */
            }

            else if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_5)
            {
                c_ospf_lsa_5_body lsa_5_body(packet_info.packet + lsa_offset + OSPF_LSA_HEADER_LEN);

                string netmask_string[16];

                conv_ip_str(netmask_string, lsa_5_body.get_netmask());

                output_string.add((char *)"  NETMASK %s\n\tTYPE ",
                                  netmask_string);

                if (lsa_5_body.get_type())
                {
                    output_string.add((char *)"E2");
                }
                else
                {
                    output_string.add((char *)"E1");
                }

                output_string.add((char *)"  METRIC %u  ",
                                  lsa_5_body.get_metric());

                string fwdaddr_string[16];

                conv_ip_str(fwdaddr_string, lsa_5_body.get_fwdaddr());

                output_string.add((char *)"FWD ADDR %s  TAG %u\n",
                                  fwdaddr_string,
                                  lsa_5_body.get_tag());
            }

            else if (lsa_header.get_type() == OSPF_LSA_HEADER_TYPE_7)
            {
                output_string.add((char *)"\n");
            }

            else
            {
                output_string.add((char *)"\n");
            }

            lsa_offset += lsa_header.get_len();
        }
    }

    if (header.get_type() == OSPF_TYPE_LSA_PACKET)
    {
        u_int lsa_offset = OSPF_HEADER_LEN;

        while (lsa_offset < header.get_plen())
        {
            c_ospf_lsa_header lsa_header(packet_info.packet + lsa_offset);

            output_string += print_ospf_lsa_header(lsa_header);
            output_string += "\n";

            lsa_offset += OSPF_LSA_HEADER_LEN;
        }
    }

    if (header.get_authtype() == OSPF_AUTHTYPE_CRYPTO)
    {
        output_string += print_hex_data(packet_info.packet + header.get_plen(), 16, true, (char *)"MD5\t");
    }

    if (lls_present)
    {
        c_ospf_lls lls(packet_info.packet + header.get_plen() + md5_present * 16);

        output_string.add((char *)"\n");
        output_string.add((char *)"LLS\tCKSUM %u ",
                          lls.get_cksum());

        if (header.get_authtype() == OSPF_AUTHTYPE_CRYPTO)
        {
            output_string.add((char *)"(NONE)");
        }
        else if (!cksum(packet_info.packet + header.get_plen() + md5_present * 16, lls.get_dlen()))
        {
            output_string.add((char *)"(OK)");
        }
        else
        {
            output_string.add((char *)"(BAD)");
        }

        output_string.add((char *)"  DLEN %u",
                          lls.get_dlen());

        output_string.add((char *)"\n");

        u_int i = 0;

        while (i < lls.get_dlen() - OSPF_LLS_LEN)
        {
            c_ospf_lls_tlv lls_tlv(packet_info.packet + header.get_plen() + OSPF_LLS_LEN + md5_present * 16 + i);

            output_string.add((char *)"\nTLV\tTYPE %u ",
                              lls_tlv.get_type());

            switch (lls_tlv.get_type())
            {
            case OSPF_LLS_TLV_TYPE_EXTOPT:
            {
                c_ospf_lls_tlv_extopt lls_tlv_extopt(packet_info.packet + header.get_plen() + OSPF_LLS_LEN + md5_present * 16 + i);

                output_string.add((char *)"(Extended Options)  VLEN %u\n",
                                  lls_tlv.get_vlen());

                output_string.add_hex((char *)"\tOPTIONS 0x%02X%02X%02X%02X [ ",
                                      lls_tlv_extopt.get_flags());

                if (lls_tlv_extopt.get_flag_rs())
                {
                    output_string.add((char *)"RS ");
                }

                if (lls_tlv_extopt.get_flag_lr())
                {
                    output_string.add((char *)"LR ");
                }

                output_string.add((char *)"]");

                break;
            }

            case OSPF_LLS_TLV_TYPE_CAUTH:
            {
                c_ospf_lls_tlv_cauth lls_tlv_cauth(packet_info.packet + header.get_plen() + OSPF_LLS_LEN + md5_present * 16 + i);

                output_string.add((char *)"(Cryptographic Authentication)  "
                                          "VLEN %u\n\tAUTH SEQ %u\n\t",
                                  lls_tlv.get_vlen(),
                                  lls_tlv_cauth.get_cryptoseq());

                output_string += print_hex_data(packet_info.packet + header.get_plen() + OSPF_LLS_LEN + md5_present * 16 + i + 4, 16, false);

                break;
            }

            default:
                output_string += "(Unknown)";
            }

            output_string.add((char *)"\n");

            i += lls_tlv.get_vlen() + OSPF_LLS_TLV_LEN;
        }
    }

    output_string += debug(packet_info);

    output_string += print_line();

    return output_string;
}

c_string print_ospf_lsa_header(c_ospf_lsa_header lsa_header)
{
    c_string output_string;

    output_string.add((char *)"\nLSA %u\tAGE %u  ",
                      lsa_header.get_type(),
                      lsa_header.get_age());

    output_string.add_hex((char *)"OPTIONS 0x%02X [ ",
                          lsa_header.get_options());

    if (lsa_header.get_option_dc())
    {
        output_string.add((char *)"DC ");
    }

    if (lsa_header.get_option_l())
    {
        output_string.add((char *)"L ");
    }

    if (lsa_header.get_option_np())
    {
        output_string.add((char *)"N/P ");
    }

    if (lsa_header.get_option_mc())
    {
        output_string.add((char *)"MC ");
    }

    if (lsa_header.get_option_e())
    {
        output_string.add((char *)"E ");
    }

    output_string.add((char *)"]  TYPE %u (",
                      lsa_header.get_type());

    switch (lsa_header.get_type())
    {
    case OSPF_LSA_HEADER_TYPE_1:
        output_string.add((char *)"Router");
        break;

    case OSPF_LSA_HEADER_TYPE_2:
        output_string.add((char *)"Network");
        break;

    case OSPF_LSA_HEADER_TYPE_3:
        output_string.add((char *)"Summary IP network");
        break;

    case OSPF_LSA_HEADER_TYPE_4:
        output_string.add((char *)"Summary ASBR");
        break;

    case OSPF_LSA_HEADER_TYPE_5:
        output_string.add((char *)"AS External");
        break;

    case OSPF_LSA_HEADER_TYPE_7:
        output_string.add((char *)"NSSA");
        break;

    default:
        output_string.add((char *)"Unknown");
    }

    output_string.add((char *)")\n");

    string id_string[16];
    string advrtr_string[16];

    conv_ip_str(id_string, lsa_header.get_id());
    conv_ip_str(advrtr_string, lsa_header.get_advrtr());

    output_string.add((char *)"\tLS ID %s  ADV RTR %s  SEQ %u\n",
                      id_string,
                      advrtr_string,
                      lsa_header.get_seq());

    output_string.add((char *)"\tCKSUM %u  ",
                      lsa_header.get_cksum());

    output_string.add((char *)"LEN %u",
                      lsa_header.get_len());

    return output_string;
}
