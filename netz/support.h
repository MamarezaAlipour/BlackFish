#ifndef _NETZ_SUPPORT_H_
#define _NETZ_SUPPORT_H_

#include "types.h"

void message(string *, ...);

byte hton(byte);
byte ntoh(byte);

word hton(word);
word ntoh(word);

dword hton(dword);
dword ntoh(dword);

byte rotation(dword);

byte bits(byte, byte);
word bits(word, word);
word bits(dword, dword);
byte bits(byte, byte, byte);
word bits(word, word, byte);
word bits(word, word, word);
dword bits(dword, dword, byte);
dword bits(dword, dword, word);
dword bits(dword, dword, dword);

string *conv_ip_str(string *, dword);
string *conv_ip_str(string *, byte *);
string *conv_ip6_str(string *, byte *);
string *conv_ether_str(string *, byte *);
string *conv_ipx_str(string *, byte *);
string *conv_ieee8023_str(string *, byte *);
string *conv_raw8023_str(string *, byte *);

dword conv_str_ip(string *);

int cmp_ether_str(string *, string *);

#endif /* _NETZ_SUPPORT_H_ */
