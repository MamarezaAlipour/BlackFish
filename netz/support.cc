#ifdef OS_AIX
#include <sys/types.h>
#include <string.h>
#endif

#ifdef OS_OPENBSD
#include <string.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>

#include "ip6.h"
#include "ether.h"

void message(string *format, ...)
{
    va_list varg;
    va_start(varg, format);

    string message_string[256];

    message_string[0] = 0;

    vsnprintf(message_string, 256, format, varg);

    write(2, message_string, strlen(message_string));
}

byte hton(byte v)
{
    return v;
}

byte ntoh(byte v)
{
    return v;
}

word hton(word v)
{
    return htons(v);
}

word ntoh(word v)
{
    return ntohs(v);
}

dword hton(dword v)
{
    return htonl(v);
}

dword ntoh(dword v)
{
    return ntohl(v);
}

byte rotation(dword mask)
{
    byte rotation = 0;

    while (!(mask & 1))
    {
        mask = mask >> 1;
        rotation++;

        if (rotation > 31)
        {
            return 0;
        }
    }

    return rotation;
}

byte bits(byte field, byte mask)
{
    return (field & mask) >> rotation(mask);
}

word bits(word field, word mask)
{
    return (field & mask) >> rotation(mask);
}

dword bits(dword field, dword mask)
{
    return (field & mask) >> rotation(mask);
}

byte bits(byte field, byte mask, byte value)
{
    return (field & ~(byte)mask) | (value << rotation(mask));
}

word bits(word field, word mask, byte value)
{
    return (field & ~(word)mask) | (((word)value) << rotation(mask));
}

word bits(word field, word mask, word value)
{
    return (field & ~(word)mask) | (value << rotation(mask));
}

dword bits(dword field, dword mask, byte value)
{
    return (field & ~(dword)mask) | (((dword)value) << rotation(mask));
}

dword bits(dword field, dword mask, word value)
{
    return (field & ~(dword)mask) | (((dword)value) << rotation(mask));
}

dword bits(dword field, dword mask, dword value)
{
    return (field & ~(dword)mask) | (value << rotation(mask));
}

string *conv_ip_str(string *str, dword addr)
{
    sprintf(str, "%u.%u.%u.%u",
            *(((byte *)&addr) + 3),
            *(((byte *)&addr) + 2),
            *(((byte *)&addr) + 1),
            *(((byte *)&addr) + 0));

    return str;
}

string *conv_ip_str(string *str, byte *addr)
{
    sprintf(str, "%u.%u.%u.%u",
            *(addr + 0),
            *(addr + 1),
            *(addr + 2),
            *(addr + 3));

    return str;
}

string *conv_ip6_str(string *str, byte *addr)
{
    str[0] = 0;

    for (u_int i = 0; i < IP6_ADDR_LEN; i += 2)
    {
        sprintf(str + strlen(str), "%02x", addr[i]);
        sprintf(str + strlen(str), "%02x", addr[i + 1]);

        if (i < IP6_ADDR_LEN - 2)
        {
            sprintf(str + strlen(str), ":");
        }
    }

    return str;
}

string *conv_ipx_str(string *str, byte *addr)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            *(addr + 0),
            *(addr + 1),
            *(addr + 2),
            *(addr + 3),
            *(addr + 4),
            *(addr + 5));

    return str;
}

string *conv_ether_str(string *str, byte *addr)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            *(addr + 0),
            *(addr + 1),
            *(addr + 2),
            *(addr + 3),
            *(addr + 4),
            *(addr + 5));

    return str;
}

string *conv_ieee8023_str(string *str, byte *addr)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            *(addr + 0),
            *(addr + 1),
            *(addr + 2),
            *(addr + 3),
            *(addr + 4),
            *(addr + 5));

    return str;
}

string *conv_raw8023_str(string *str, byte *addr)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            *(addr + 0),
            *(addr + 1),
            *(addr + 2),
            *(addr + 3),
            *(addr + 4),
            *(addr + 5));

    return str;
}

dword conv_str_ip(string *str)
{
    return inet_addr(str);
}

int cmp_ether_str(string *str1, string *str2)
{
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (*(str1 + i) != *(str2 + i))
        {
            return 1;
        }
    }

    return 0;
}
