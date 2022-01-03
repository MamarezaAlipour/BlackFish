#include "ospf_support.h"
#include "support.h"
#include "string.h"

c_ospf_header::c_ospf_header(byte *ospf_header)
{
    header = (s_ospf_header *)ospf_header;
}

c_ospf_header::c_ospf_header(s_ospf_header *ospf_header)
{
    header = ospf_header;
}

byte c_ospf_header::get_ver()
{
    return ntoh(header->ver);
}

byte c_ospf_header::get_type()
{
    return ntoh(header->type);
}

word c_ospf_header::get_plen()
{
    return ntoh(header->plen);
}

dword c_ospf_header::get_routerid()
{
    return ntoh(header->routerid);
}

dword c_ospf_header::get_areaid()
{
    return ntoh(header->areaid);
}

word c_ospf_header::get_cksum()
{
    return header->cksum;
}

word c_ospf_header::get_authtype()
{
    return ntoh(header->authtype);
}

string *c_ospf_header::get_password()
{
    strncpy(password, header->password, 8);
    return password;
}

byte c_ospf_header::get_keyid()
{
    return ntoh(header->authdata.keyid);
}

byte c_ospf_header::get_adlen()
{
    return ntoh(header->authdata.adlen);
}

dword c_ospf_header::get_cryptoseq()
{
    return ntoh(header->authdata.cryptoseq);
}

c_ospf_lls::c_ospf_lls(byte *ospf_lls)
{
    lls = (s_ospf_lls *)ospf_lls;
}

c_ospf_lls::c_ospf_lls(s_ospf_lls *ospf_lls)
{
    lls = ospf_lls;
}

word c_ospf_lls::get_cksum()
{
    return lls->cksum;
}

dword c_ospf_lls::get_dlen()
{
    return ntoh(lls->dlen) << 2;
}

c_ospf_lls_tlv::c_ospf_lls_tlv(byte *ospf_lls_tlv)
{
    lls_tlv = (s_ospf_lls_tlv *)ospf_lls_tlv;
}

c_ospf_lls_tlv::c_ospf_lls_tlv(s_ospf_lls_tlv *ospf_lls_tlv)
{
    lls_tlv = ospf_lls_tlv;
}

word c_ospf_lls_tlv::get_type()
{
    return ntoh(lls_tlv->type);
}

word c_ospf_lls_tlv::get_vlen()
{
    return ntoh(lls_tlv->vlen);
}

c_ospf_lls_tlv_extopt::c_ospf_lls_tlv_extopt(byte *ospf_lls_tlv_extopt)
{
    lls_tlv_extopt = (s_ospf_lls_tlv_extopt *)ospf_lls_tlv_extopt;
}

c_ospf_lls_tlv_extopt::c_ospf_lls_tlv_extopt(s_ospf_lls_tlv_extopt *ospf_lls_tlv_extopt)
{
    lls_tlv_extopt = ospf_lls_tlv_extopt;
}

word c_ospf_lls_tlv_extopt::get_type()
{
    return ntoh(lls_tlv_extopt->type);
}

word c_ospf_lls_tlv_extopt::get_vlen()
{
    return ntoh(lls_tlv_extopt->vlen);
}

dword c_ospf_lls_tlv_extopt::get_flags()
{
    return ntoh(lls_tlv_extopt->flags);
}

c_ospf_lls_tlv_cauth::c_ospf_lls_tlv_cauth(byte *ospf_lls_tlv_cauth)
{
    lls_tlv_cauth = (s_ospf_lls_tlv_cauth *)ospf_lls_tlv_cauth;
}

c_ospf_lls_tlv_cauth::c_ospf_lls_tlv_cauth(s_ospf_lls_tlv_cauth *ospf_lls_tlv_cauth)
{
    lls_tlv_cauth = ospf_lls_tlv_cauth;
}

word c_ospf_lls_tlv_cauth::get_type()
{
    return ntoh(lls_tlv_cauth->type);
}

word c_ospf_lls_tlv_cauth::get_vlen()
{
    return ntoh(lls_tlv_cauth->vlen);
}

dword c_ospf_lls_tlv_cauth::get_cryptoseq()
{
    return ntoh(lls_tlv_cauth->cryptoseq);
}

byte *c_ospf_lls_tlv_cauth::get_authdata()
{
    return lls_tlv_cauth->authdata;
}

byte c_ospf_lls_tlv_extopt::get_flag_lr()
{
    return bits(get_flags(), OSPF_LLS_TLV_EXTOPT_FLAG_LR_MASK);
}

byte c_ospf_lls_tlv_extopt::get_flag_rs()
{
    return bits(get_flags(), OSPF_LLS_TLV_EXTOPT_FLAG_RS_MASK);
}

c_ospf_hello_packet::c_ospf_hello_packet(byte *ospf_hello_packet)
{
    hello_packet = (s_ospf_hello_packet *)ospf_hello_packet;
}

c_ospf_hello_packet::c_ospf_hello_packet(s_ospf_hello_packet *ospf_hello_packet)
{
    hello_packet = ospf_hello_packet;
}

dword c_ospf_hello_packet::get_netmask()
{
    return ntoh(hello_packet->netmask);
}

word c_ospf_hello_packet::get_hellointerval()
{
    return ntoh(hello_packet->hellointerval);
}

byte c_ospf_hello_packet::get_options()
{
    return ntoh(hello_packet->options);
}

byte c_ospf_hello_packet::get_option_dc()
{
    return bits(get_options(), OSPF_HELLO_PACKET_OPTION_DC_MASK);
}

byte c_ospf_hello_packet::get_option_l()
{
    return bits(get_options(), OSPF_HELLO_PACKET_OPTION_L_MASK);
}

byte c_ospf_hello_packet::get_option_np()
{
    return bits(get_options(), OSPF_HELLO_PACKET_OPTION_NP_MASK);
}

byte c_ospf_hello_packet::get_option_mc()
{
    return bits(get_options(), OSPF_HELLO_PACKET_OPTION_MC_MASK);
}

byte c_ospf_hello_packet::get_option_e()
{
    return bits(get_options(), OSPF_HELLO_PACKET_OPTION_E_MASK);
}

byte c_ospf_hello_packet::get_priority()
{
    return ntoh(hello_packet->priority);
}

dword c_ospf_hello_packet::get_deadinterval()
{
    return ntoh(hello_packet->deadinterval);
}

dword c_ospf_hello_packet::get_dr()
{
    return ntoh(hello_packet->dr);
}

dword c_ospf_hello_packet::get_bdr()
{
    return ntoh(hello_packet->bdr);
}

dword c_ospf_hello_packet::get_neighbor(u_int n)
{
    return ntoh(hello_packet->neighbor[n]);
}

c_ospf_dd_packet::c_ospf_dd_packet(byte *ospf_dd_packet)
{
    dd_packet = (s_ospf_dd_packet *)ospf_dd_packet;
}

c_ospf_dd_packet::c_ospf_dd_packet(s_ospf_dd_packet *ospf_dd_packet)
{
    dd_packet = ospf_dd_packet;
}

word c_ospf_dd_packet::get_mtu()
{
    return ntoh(dd_packet->mtu);
}

word c_ospf_dd_packet::get_options()
{
    return ntoh(dd_packet->options);
}

byte c_ospf_dd_packet::get_option_ms()
{
    return bits(get_options(), OSPF_DD_PACKET_OPTION_MS_MASK);
}

byte c_ospf_dd_packet::get_option_m()
{
    return bits(get_options(), OSPF_DD_PACKET_OPTION_M_MASK);
}

byte c_ospf_dd_packet::get_option_i()
{
    return bits(get_options(), OSPF_DD_PACKET_OPTION_I_MASK);
}

dword c_ospf_dd_packet::get_seq()
{
    return ntoh(dd_packet->seq);
}

c_ospf_lsr_packet::c_ospf_lsr_packet(byte *ospf_lsr_packet)
{
    lsr_packet = (s_ospf_lsr_packet *)ospf_lsr_packet;
}

c_ospf_lsr_packet::c_ospf_lsr_packet(s_ospf_lsr_packet *ospf_lsr_packet)
{
    lsr_packet = ospf_lsr_packet;
}

dword c_ospf_lsr_packet::get_type()
{
    return ntoh(lsr_packet->type);
}

dword c_ospf_lsr_packet::get_id()
{
    return ntoh(lsr_packet->id);
}

dword c_ospf_lsr_packet::get_advrtr()
{
    return ntoh(lsr_packet->advrtr);
}

c_ospf_lsu_packet::c_ospf_lsu_packet(byte *ospf_lsu_packet)
{
    lsu_packet = (s_ospf_lsu_packet *)ospf_lsu_packet;
}

c_ospf_lsu_packet::c_ospf_lsu_packet(s_ospf_lsu_packet *ospf_lsu_packet)
{
    lsu_packet = ospf_lsu_packet;
}

dword c_ospf_lsu_packet::get_lcount()
{
    return ntoh(lsu_packet->lcount);
}

c_ospf_lsa_header::c_ospf_lsa_header(byte *ospf_lsa_header)
{
    lsa_header = (s_ospf_lsa_header *)ospf_lsa_header;
}

c_ospf_lsa_header::c_ospf_lsa_header(s_ospf_lsa_header *ospf_lsa_header)
{
    lsa_header = ospf_lsa_header;
}

word c_ospf_lsa_header::get_age()
{
    return ntoh(lsa_header->age);
}

byte c_ospf_lsa_header::get_options()
{
    return ntoh(lsa_header->options);
}

byte c_ospf_lsa_header::get_option_dc()
{
    return bits(get_options(), OSPF_LSA_HEADER_OPTION_DC_MASK);
}

byte c_ospf_lsa_header::get_option_l()
{
    return bits(get_options(), OSPF_LSA_HEADER_OPTION_L_MASK);
}

byte c_ospf_lsa_header::get_option_np()
{
    return bits(get_options(), OSPF_LSA_HEADER_OPTION_NP_MASK);
}

byte c_ospf_lsa_header::get_option_mc()
{
    return bits(get_options(), OSPF_LSA_HEADER_OPTION_MC_MASK);
}

byte c_ospf_lsa_header::get_option_e()
{
    return bits(get_options(), OSPF_LSA_HEADER_OPTION_E_MASK);
}

byte c_ospf_lsa_header::get_type()
{
    return ntoh(lsa_header->type);
}

dword c_ospf_lsa_header::get_id()
{
    return ntoh(lsa_header->id);
}

dword c_ospf_lsa_header::get_advrtr()
{
    return ntoh(lsa_header->advrtr);
}

dword c_ospf_lsa_header::get_seq()
{
    return ntoh(lsa_header->seq);
}

word c_ospf_lsa_header::get_cksum()
{
    return lsa_header->cksum;
}

word c_ospf_lsa_header::get_len()
{
    return ntoh(lsa_header->len);
}

c_ospf_lsa_1_body::c_ospf_lsa_1_body(byte *ospf_lsa_1_body)
{
    lsa_1_body = (s_ospf_lsa_1_body *)ospf_lsa_1_body;
}

c_ospf_lsa_1_body::c_ospf_lsa_1_body(s_ospf_lsa_1_body *ospf_lsa_1_body)
{
    lsa_1_body = ospf_lsa_1_body;
}

byte c_ospf_lsa_1_body::get_flags()
{
    return ntoh(lsa_1_body->flags);
}

byte c_ospf_lsa_1_body::get_flag_v()
{
    return bits(get_flags(), OSPF_LSA_1_BODY_FLAG_V_MASK);
}

byte c_ospf_lsa_1_body::get_flag_e()
{
    return bits(get_flags(), OSPF_LSA_1_BODY_FLAG_E_MASK);
}

byte c_ospf_lsa_1_body::get_flag_b()
{
    return bits(get_flags(), OSPF_LSA_1_BODY_FLAG_B_MASK);
}

byte c_ospf_lsa_1_body::get_flag_w()
{
    return bits(get_flags(), OSPF_LSA_1_BODY_FLAG_W_MASK);
}

byte c_ospf_lsa_1_body::get_flag_nt()
{
    return bits(get_flags(), OSPF_LSA_1_BODY_FLAG_NT_MASK);
}

word c_ospf_lsa_1_body::get_lcount()
{
    return ntoh(lsa_1_body->lcount);
}

c_ospf_lsa_1_link::c_ospf_lsa_1_link(byte *ospf_lsa_1_link)
{
    lsa_1_link = (s_ospf_lsa_1_link *)ospf_lsa_1_link;
}

c_ospf_lsa_1_link::c_ospf_lsa_1_link(s_ospf_lsa_1_link *ospf_lsa_1_link)
{
    lsa_1_link = ospf_lsa_1_link;
}

dword c_ospf_lsa_1_link::get_id()
{
    return ntoh(lsa_1_link->id);
}

dword c_ospf_lsa_1_link::get_data()
{
    return ntoh(lsa_1_link->data);
}

byte c_ospf_lsa_1_link::get_type()
{
    return ntoh(lsa_1_link->type);
}

byte c_ospf_lsa_1_link::get_tcount()
{
    return ntoh(lsa_1_link->tcount);
}

word c_ospf_lsa_1_link::get_metric()
{
    return ntoh(lsa_1_link->metric);
}

c_ospf_lsa_1_link_tos::c_ospf_lsa_1_link_tos(byte *ospf_lsa_1_link_tos)
{
    lsa_1_link_tos = (s_ospf_lsa_1_link_tos *)ospf_lsa_1_link_tos;
}

c_ospf_lsa_1_link_tos::c_ospf_lsa_1_link_tos(s_ospf_lsa_1_link_tos *ospf_lsa_1_link_tos)
{
    lsa_1_link_tos = ospf_lsa_1_link_tos;
}

byte c_ospf_lsa_1_link_tos::get_tos()
{
    return ntoh(lsa_1_link_tos->tos);
}

word c_ospf_lsa_1_link_tos::get_metric()
{
    return ntoh(lsa_1_link_tos->metric);
}

c_ospf_lsa_2_link::c_ospf_lsa_2_link(byte *ospf_lsa_2_link)
{
    lsa_2_link = (s_ospf_lsa_2_link *)ospf_lsa_2_link;
}

c_ospf_lsa_2_link::c_ospf_lsa_2_link(s_ospf_lsa_2_link *ospf_lsa_2_link)
{
    lsa_2_link = ospf_lsa_2_link;
}

dword c_ospf_lsa_2_link::get_netmask()
{
    return ntoh(lsa_2_link->netmask);
}

dword c_ospf_lsa_2_link::get_attrtr()
{
    return ntoh(lsa_2_link->attrtr);
}

c_ospf_lsa_3_body::c_ospf_lsa_3_body(byte *ospf_lsa_3_body)
{
    lsa_3_body = (s_ospf_lsa_3_body *)ospf_lsa_3_body;
}

c_ospf_lsa_3_body::c_ospf_lsa_3_body(s_ospf_lsa_3_body *ospf_lsa_3_body)
{
    lsa_3_body = ospf_lsa_3_body;
}

dword c_ospf_lsa_3_body::get_netmask()
{
    return ntoh(lsa_3_body->netmask);
}

dword c_ospf_lsa_3_body::get_metric()
{
    dword metric;

    *((byte *)&metric + 0) = 0;
    *((byte *)&metric + 1) = ntoh(lsa_3_body->metric[0]);
    *((byte *)&metric + 2) = ntoh(lsa_3_body->metric[1]);
    *((byte *)&metric + 3) = ntoh(lsa_3_body->metric[2]);

    return ntoh(metric);
}

c_ospf_lsa_4_body::c_ospf_lsa_4_body(byte *ospf_lsa_4_body)
{
    lsa_4_body = (s_ospf_lsa_4_body *)ospf_lsa_4_body;
}

c_ospf_lsa_4_body::c_ospf_lsa_4_body(s_ospf_lsa_4_body *ospf_lsa_4_body)
{
    lsa_4_body = ospf_lsa_4_body;
}

dword c_ospf_lsa_4_body::get_metric()
{
    dword metric;

    *((byte *)&metric + 0) = 0;
    *((byte *)&metric + 1) = ntoh(lsa_4_body->metric[0]);
    *((byte *)&metric + 2) = ntoh(lsa_4_body->metric[1]);
    *((byte *)&metric + 3) = ntoh(lsa_4_body->metric[2]);

    return ntoh(metric);
}

c_ospf_lsa_5_body::c_ospf_lsa_5_body(byte *ospf_lsa_5_body)
{
    lsa_5_body = (s_ospf_lsa_5_body *)ospf_lsa_5_body;
}

c_ospf_lsa_5_body::c_ospf_lsa_5_body(s_ospf_lsa_5_body *ospf_lsa_5_body)
{
    lsa_5_body = ospf_lsa_5_body;
}

dword c_ospf_lsa_5_body::get_netmask()
{
    return ntoh(lsa_5_body->netmask);
}

byte c_ospf_lsa_5_body::get_type()
{
    return bits(ntoh(lsa_5_body->type), OSPF_LSA_5_BODY_TYPE_MASK);
}

dword c_ospf_lsa_5_body::get_metric()
{
    dword metric;

    *((byte *)&metric + 0) = 0;
    *((byte *)&metric + 1) = ntoh(lsa_5_body->metric[0]);
    *((byte *)&metric + 2) = ntoh(lsa_5_body->metric[1]);
    *((byte *)&metric + 3) = ntoh(lsa_5_body->metric[2]);

    return ntoh(metric);
}

dword c_ospf_lsa_5_body::get_fwdaddr()
{
    return ntoh(lsa_5_body->fwdaddr);
}

dword c_ospf_lsa_5_body::get_tag()
{
    return ntoh(lsa_5_body->tag);
}

c_ospf_lsa_7_body::c_ospf_lsa_7_body(byte *ospf_lsa_7_body)
{
    lsa_7_body = (s_ospf_lsa_7_body *)ospf_lsa_7_body;
}

c_ospf_lsa_7_body::c_ospf_lsa_7_body(s_ospf_lsa_7_body *ospf_lsa_7_body)
{
    lsa_7_body = ospf_lsa_7_body;
}

dword c_ospf_lsa_7_body::get_netmask()
{
    return ntoh(lsa_7_body->netmask);
}

byte c_ospf_lsa_7_body::get_type()
{
    return bits(ntoh(lsa_7_body->type), OSPF_LSA_7_BODY_TYPE_MASK);
}

dword c_ospf_lsa_7_body::get_metric()
{
    dword metric;

    *((byte *)&metric + 0) = 0;
    *((byte *)&metric + 1) = ntoh(lsa_7_body->metric[0]);
    *((byte *)&metric + 2) = ntoh(lsa_7_body->metric[1]);
    *((byte *)&metric + 3) = ntoh(lsa_7_body->metric[2]);

    return ntoh(metric);
}

dword c_ospf_lsa_7_body::get_fwdaddr()
{
    return ntoh(lsa_7_body->fwdaddr);
}

dword c_ospf_lsa_7_body::get_tag()
{
    return ntoh(lsa_7_body->tag);
}
