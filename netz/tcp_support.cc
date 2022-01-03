#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include "tcp_support.h"
#include "support.h"

c_tcp_header::c_tcp_header(byte *tcp_header)
{
    header = (s_tcp_header *)tcp_header;
}

c_tcp_header::c_tcp_header(s_tcp_header *tcp_header)
{
    header = tcp_header;
}

word c_tcp_header::get_sport()
{
    return ntoh(header->sport);
}

void c_tcp_header::set_sport(word sport)
{
    header->sport = hton(sport);
}

word c_tcp_header::get_dport()
{
    return ntoh(header->dport);
}

void c_tcp_header::set_dport(word dport)
{
    header->dport = hton(dport);
}

dword c_tcp_header::get_seq()
{
    return ntoh(header->seq);
}

void c_tcp_header::set_seq(dword seq)
{
    header->seq = hton(seq);
}

dword c_tcp_header::get_ack()
{
    return ntoh(header->ack);
}

void c_tcp_header::set_ack(dword ack)
{
    header->ack = hton(ack);
}

byte c_tcp_header::get_hlen()
{
    return bits(ntoh(header->hlen), TCP_HLEN_MASK) * 4;
}

void c_tcp_header::set_hlen(byte hlen)
{
    header->hlen = hton(bits(ntoh(header->hlen), TCP_HLEN_MASK, hlen >> 2));
}

byte c_tcp_header::get_flags()
{
    return ntoh(header->flags);
}

void c_tcp_header::set_flags(byte flags)
{
    header->flags = hton(flags);
}

word c_tcp_header::get_win()
{
    return ntoh(header->win);
}

void c_tcp_header::set_win(word win)
{
    header->win = hton(win);
}

word c_tcp_header::get_cksum()
{
    return header->cksum;
}

void c_tcp_header::set_cksum(word cksum)
{
    header->cksum = cksum;
}

word c_tcp_header::get_urp()
{
    return ntoh(header->urp);
}

void c_tcp_header::set_urp(word urp)
{
    header->urp = hton(urp);
}

byte c_tcp_header::get_flag_fin()
{
    return bits(get_flags(), TCP_FLAG_FIN_MASK);
}

void c_tcp_header::set_flag_fin(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_FIN_MASK, flag));
}

byte c_tcp_header::get_flag_syn()
{
    return bits(get_flags(), TCP_FLAG_SYN_MASK);
}

void c_tcp_header::set_flag_syn(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_SYN_MASK, flag));
}

byte c_tcp_header::get_flag_rst()
{
    return bits(get_flags(), TCP_FLAG_RST_MASK);
}

void c_tcp_header::set_flag_rst(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_RST_MASK, flag));
}

byte c_tcp_header::get_flag_psh()
{
    return bits(get_flags(), TCP_FLAG_PSH_MASK);
}

void c_tcp_header::set_flag_psh(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_PSH_MASK, flag));
}

byte c_tcp_header::get_flag_ack()
{
    return bits(get_flags(), TCP_FLAG_ACK_MASK);
}

void c_tcp_header::set_flag_ack(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_ACK_MASK, flag));
}

byte c_tcp_header::get_flag_urg()
{
    return bits(get_flags(), TCP_FLAG_URG_MASK);
}

void c_tcp_header::set_flag_urg(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_URG_MASK, flag));
}

byte c_tcp_header::get_flag_x()
{
    return bits(get_flags(), TCP_FLAG_X_MASK);
}

void c_tcp_header::set_flag_x(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_X_MASK, flag));
}

byte c_tcp_header::get_flag_y()
{
    return bits(get_flags(), TCP_FLAG_Y_MASK);
}

void c_tcp_header::set_flag_y(byte flag)
{
    header->flags = hton(bits(ntoh(header->flags),
                              TCP_FLAG_Y_MASK, flag));
}

/*
 * TCP options support
 */

c_tcpopt_generic::c_tcpopt_generic(byte *tcp_option)
{
    option = (s_tcpopt_generic *)tcp_option;
}

byte c_tcpopt_generic::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_generic::set_code(byte code)
{
    option->code = hton(code);
    ;
}

byte c_tcpopt_generic::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_generic::set_len(byte len)
{
    option->len = hton(len);
}

byte *c_tcpopt_generic::get_data()
{
    return option->data;
}

void c_tcpopt_generic::set_data(byte *data, u_int data_len)
{
    memcpy(option->data, data, data_len);
}

c_tcpopt_eol::c_tcpopt_eol(byte *tcp_option)
{
    option = (s_tcpopt_eol *)tcp_option;
}

byte c_tcpopt_eol::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_eol::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_eol::get_len()
{
    return TCPOPT_EOL_LEN;
}

c_tcpopt_nop::c_tcpopt_nop(byte *tcp_option)
{
    option = (s_tcpopt_nop *)tcp_option;
}

byte c_tcpopt_nop::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_nop::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_nop::get_len()
{
    return TCPOPT_NOP_LEN;
}

c_tcpopt_mss::c_tcpopt_mss(byte *tcp_option)
{
    option = (s_tcpopt_mss *)tcp_option;
}

byte c_tcpopt_mss::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_mss::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_mss::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_mss::set_len(byte len)
{
    option->len = hton(len);
}

word c_tcpopt_mss::get_size()
{
    return ntoh(option->size);
}

void c_tcpopt_mss::set_size(word size)
{
    option->size = hton(size);
}

c_tcpopt_wscale::c_tcpopt_wscale(byte *tcp_option)
{
    option = (s_tcpopt_wscale *)tcp_option;
}

byte c_tcpopt_wscale::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_wscale::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_wscale::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_wscale::set_len(byte len)
{
    option->len = hton(len);
}

byte c_tcpopt_wscale::get_scale()
{
    return ntoh(option->scale);
}

void c_tcpopt_wscale::set_scale(byte scale)
{
    option->scale = hton(scale);
}

c_tcpopt_sackperm::c_tcpopt_sackperm(byte *tcp_option)
{
    option = (s_tcpopt_sackperm *)tcp_option;
}

byte c_tcpopt_sackperm::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_sackperm::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_sackperm::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_sackperm::set_len(byte len)
{
    option->len = hton(len);
}

c_tcpopt_sack::c_tcpopt_sack(byte *tcp_option)
{
    option = (s_tcpopt_sack *)tcp_option;
}

byte c_tcpopt_sack::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_sack::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_sack::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_sack::set_len(byte len)
{
    option->len = hton(len);
}

dword c_tcpopt_sack::get_ledge(u_int n)
{
    return ntoh(option->block[n].ledge);
}

void c_tcpopt_sack::set_ledge(u_int n, dword ledge)
{
    option->block[n].ledge = hton(ledge);
}

dword c_tcpopt_sack::get_redge(u_int n)
{
    return ntoh(option->block[n].redge);
}

void c_tcpopt_sack::set_redge(u_int n, dword redge)
{
    option->block[n].ledge = hton(redge);
}

c_tcpopt_echo::c_tcpopt_echo(byte *tcp_option)
{
    option = (s_tcpopt_echo *)tcp_option;
}

byte c_tcpopt_echo::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_echo::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_echo::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_echo::set_len(byte len)
{
    option->len = hton(len);
}

dword c_tcpopt_echo::get_info()
{
    return ntoh(option->info);
}

void c_tcpopt_echo::set_info(dword info)
{
    option->info = hton(info);
}

c_tcpopt_echoreply::c_tcpopt_echoreply(byte *tcp_option)
{
    option = (s_tcpopt_echoreply *)tcp_option;
}

byte c_tcpopt_echoreply::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_echoreply::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_echoreply::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_echoreply::set_len(byte len)
{
    option->len = hton(len);
}

dword c_tcpopt_echoreply::get_info()
{
    return ntoh(option->info);
}

void c_tcpopt_echoreply::set_info(dword info)
{
    option->info = hton(info);
}

c_tcpopt_timestamp::c_tcpopt_timestamp(byte *tcp_option)
{
    option = (s_tcpopt_timestamp *)tcp_option;
}

byte c_tcpopt_timestamp::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_timestamp::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_timestamp::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_timestamp::set_len(byte len)
{
    option->len = hton(len);
}

dword c_tcpopt_timestamp::get_tsval()
{
    return ntoh(option->tsval);
}

void c_tcpopt_timestamp::set_tsval(dword tsval)
{
    option->tsval = hton(tsval);
}

dword c_tcpopt_timestamp::get_tsecr()
{
    return ntoh(option->tsecr);
}

void c_tcpopt_timestamp::set_tsecr(dword tsecr)
{
    option->tsecr = hton(tsecr);
}

c_tcpopt_pocperm::c_tcpopt_pocperm(byte *tcp_option)
{
    option = (s_tcpopt_pocperm *)tcp_option;
}

byte c_tcpopt_pocperm::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_pocperm::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_pocperm::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_pocperm::set_len(byte len)
{
    option->len = hton(len);
}

c_tcpopt_pocsprof::c_tcpopt_pocsprof(byte *tcp_option)
{
    option = (s_tcpopt_pocsprof *)tcp_option;
}

byte c_tcpopt_pocsprof::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_pocsprof::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_pocsprof::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_pocsprof::set_len(byte len)
{
    option->len = hton(len);
}

byte c_tcpopt_pocsprof::get_sflag()
{
    return bits(ntoh(option->es), IPOPT_POCSPROF_ES_SFLAG_MASK);
}

void c_tcpopt_pocsprof::set_sflag(byte sflag)
{
    option->es = hton(bits(ntoh(option->es), IPOPT_POCSPROF_ES_SFLAG_MASK,
                           sflag));
}

byte c_tcpopt_pocsprof::get_eflag()
{
    return bits(ntoh(option->es), IPOPT_POCSPROF_ES_EFLAG_MASK);
}

void c_tcpopt_pocsprof::set_eflag(byte eflag)
{
    option->es = hton(bits(ntoh(option->es), IPOPT_POCSPROF_ES_EFLAG_MASK,
                           eflag));
}

c_tcpopt_cc::c_tcpopt_cc(byte *tcp_option)
{
    option = (s_tcpopt_cc *)tcp_option;
}

byte c_tcpopt_cc::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_cc::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_cc::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_cc::set_len(byte len)
{
    option->len = hton(len);
}

word c_tcpopt_cc::get_segment()
{
    return ntoh(option->segment);
}

void c_tcpopt_cc::set_segment(word segment)
{
    option->segment = hton(segment);
}

c_tcpopt_ccnew::c_tcpopt_ccnew(byte *tcp_option)
{
    option = (s_tcpopt_ccnew *)tcp_option;
}

byte c_tcpopt_ccnew::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_ccnew::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_ccnew::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_ccnew::set_len(byte len)
{
    option->len = hton(len);
}

word c_tcpopt_ccnew::get_segment()
{
    return ntoh(option->segment);
}

void c_tcpopt_ccnew::set_segment(word segment)
{
    option->segment = hton(segment);
}

c_tcpopt_ccecho::c_tcpopt_ccecho(byte *tcp_option)
{
    option = (s_tcpopt_ccecho *)tcp_option;
}

byte c_tcpopt_ccecho::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_ccecho::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_ccecho::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_ccecho::set_len(byte len)
{
    option->len = hton(len);
}

word c_tcpopt_ccecho::get_segment()
{
    return ntoh(option->segment);
}

void c_tcpopt_ccecho::set_segment(word segment)
{
    option->segment = hton(segment);
}

c_tcpopt_altcsr::c_tcpopt_altcsr(byte *tcp_option)
{
    option = (s_tcpopt_altcsr *)tcp_option;
}

byte c_tcpopt_altcsr::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_altcsr::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_altcsr::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_altcsr::set_len(byte len)
{
    option->len = hton(len);
}

word c_tcpopt_altcsr::get_cksum()
{
    return ntoh(option->cksum);
}

void c_tcpopt_altcsr::set_cksum(word cksum)
{
    option->cksum = hton(cksum);
}

c_tcpopt_altcsd::c_tcpopt_altcsd(byte *tcp_option)
{
    option = (s_tcpopt_altcsd *)tcp_option;
}

byte c_tcpopt_altcsd::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_altcsd::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_altcsd::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_altcsd::set_len(byte len)
{
    option->len = hton(len);
}

byte *c_tcpopt_altcsd::get_data()
{
    return option->data;
}

void c_tcpopt_altcsd::set_data(byte *data, u_int data_len)
{
    memcpy(option->data, data, data_len);
}

c_tcpopt_signature::c_tcpopt_signature(byte *tcp_option)
{
    option = (s_tcpopt_signature *)tcp_option;
}

byte c_tcpopt_signature::get_code()
{
    return ntoh(option->code);
}

void c_tcpopt_signature::set_code(byte code)
{
    option->code = hton(code);
}

byte c_tcpopt_signature::get_len()
{
    return ntoh(option->len);
}

void c_tcpopt_signature::set_len(byte len)
{
    option->len = hton(len);
}

string *c_tcpopt_signature::get_signature()
{
    return option->signature;
}

void c_tcpopt_signature::set_signature(string *signature)
{
    memcpy(option->signature, signature, 16);
}
