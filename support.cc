#ifdef OS_AIX
#include <memory.h>
#endif

#ifdef OS_OPENBSD
#include <memory.h>
#endif

#ifdef OS_LINUX
#include <string.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <netz.h>

#include "support.h"

c_string::c_string()
{
    data = 0;
    len = 0;
}

c_string::c_string(const c_string &cstr)
{
    u_int str_len = cstr.get_len();

    data = new string[str_len];

    memcpy(data, cstr.get_data(), str_len);

    len = str_len;
}

c_string::c_string(string *format, ...)
{
    string str[C_STRING_LEN];

    va_list varg;

    va_start(varg, format);

    u_int str_len = vsnprintf(str, C_STRING_LEN, format, varg);

    data = new string[str_len];

    memcpy(data, str, str_len);

    len = str_len;
}

c_string::~c_string()
{
    if (data)
    {
        delete data;
        data = 0;
        len = 0;
    }
}

void c_string::clear()
{
    if (data)
    {
        delete data;
        data = 0;
        len = 0;
    }
}

u_int c_string::add(const c_string &cstr)
{
    u_int str_len = cstr.get_len();

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, cstr.get_data(), str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return str_len;
}

u_int c_string::add_raw(byte *str, u_int str_len)
{
    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, str, str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return str_len;
}

u_int c_string::add_bin(byte value)
{
    string str[] = "%u%u%u%u%u%u%u%u";

    return add_bin(str, value);
}

u_int c_string::add_bin(string *str, byte value)
{
    return add(str,
               bits(value, 0x80),
               bits(value, 0x40),
               bits(value, 0x20),
               bits(value, 0x10),
               bits(value, 0x08),
               bits(value, 0x04),
               bits(value, 0x02),
               bits(value, 0x01));
}

u_int c_string::add_bin(word value)
{
    string str[] = "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u";

    return add_bin(str, value);
}

u_int c_string::add_bin(string *str, word value)
{
    return add(str,
               bits(value, 0x8000),
               bits(value, 0x4000),
               bits(value, 0x2000),
               bits(value, 0x1000),
               bits(value, 0x0800),
               bits(value, 0x0400),
               bits(value, 0x0200),
               bits(value, 0x0100),
               bits(value, 0x0080),
               bits(value, 0x0040),
               bits(value, 0x0020),
               bits(value, 0x0010),
               bits(value, 0x0008),
               bits(value, 0x0004),
               bits(value, 0x0002),
               bits(value, 0x0001));
}

u_int c_string::add_bin(dword value)
{
    string str[] = "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u"
                   "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u";

    return add_bin(str, value);
}

u_int c_string::add_bin(string *str, dword value)
{
    return add(str,
               bits(value, 0x80000000),
               bits(value, 0x40000000),
               bits(value, 0x20000000),
               bits(value, 0x10000000),
               bits(value, 0x08000000),
               bits(value, 0x04000000),
               bits(value, 0x02000000),
               bits(value, 0x01000000),
               bits(value, 0x00800000),
               bits(value, 0x00400000),
               bits(value, 0x00200000),
               bits(value, 0x00100000),
               bits(value, 0x00080000),
               bits(value, 0x00040000),
               bits(value, 0x00020000),
               bits(value, 0x00010000),
               bits(value, 0x00008000),
               bits(value, 0x00004000),
               bits(value, 0x00002000),
               bits(value, 0x00001000),
               bits(value, 0x00000800),
               bits(value, 0x00000400),
               bits(value, 0x00000200),
               bits(value, 0x00000100),
               bits(value, 0x00000080),
               bits(value, 0x00000040),
               bits(value, 0x00000020),
               bits(value, 0x00000010),
               bits(value, 0x00000008),
               bits(value, 0x00000004),
               bits(value, 0x00000002),
               bits(value, 0x00000001));
}

u_int c_string::add_hex(byte value)
{
    string str[] = "0x%02X";

    return add_bin(str, value);
}

u_int c_string::add_hex(string *str, byte value)
{
    return add(str, value);
}

u_int c_string::add_hex(word value)
{
    string str[] = "0x%02X%02X";

    return add_bin(str, value);
}

u_int c_string::add_hex(string *str, word value)
{
    return add(str,
               bits(value, 0xFF00),
               bits(value, 0x00FF));
}

u_int c_string::add_hex(dword value)
{
    string str[] = "0x%02X%02X%02X%02X";

    return add_bin(str, value);
}

u_int c_string::add_hex(string *str, dword value)
{
    return add(str,
               bits(value, 0xFF000000),
               bits(value, 0x00FF0000),
               bits(value, 0x0000FF00),
               bits(value, 0x000000FF));
}

u_int c_string::add(char c)
{

    string *tmp_data = data;

    data = new string[len + 1];

    memcpy(data, tmp_data, len);
    *(data + len) = c;

    len += 1;

    if (data)
    {
        delete tmp_data;
    }

    return len + 1;
}

u_int c_string::add(string *format, ...)
{
    string str[C_STRING_LEN];

    va_list varg;

    va_start(varg, format);

    u_int str_len = vsnprintf(str, C_STRING_LEN, format, varg);

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, str, str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return str_len;
}

string *c_string::get_data() const
{
    return data;
}

u_int c_string::get_len() const
{
    return len;
}

c_string &c_string::operator=(const c_string &cstr)
{
    u_int str_len = cstr.get_len();

    if (data)
    {
        delete data;
    }

    data = new string[str_len];

    memcpy(data, cstr.get_data(), str_len);

    len = str_len;

    return *this;
}

c_string &c_string::operator=(const string *str)
{
    u_int str_len = strlen(str);

    if (data)
    {
        delete data;
    }

    data = new string[str_len];

    memcpy(data, str, str_len);

    len = str_len;

    return *this;
}

c_string &c_string::operator+=(const c_string &cstr)
{
    u_int str_len = cstr.get_len();

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, cstr.get_data(), str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return *this;
}

c_string &c_string::operator+=(const string *str)
{
    u_int str_len = strlen(str);

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, str, str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return *this;
}

c_string &c_string::operator<<(const c_string &cstr)
{
    u_int str_len = cstr.get_len();

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, cstr.get_data(), str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return *this;
}

c_string &c_string::operator<<(const string *str)
{
    u_int str_len = strlen(str);

    string *tmp_data = data;

    data = new string[len + str_len];

    memcpy(data, tmp_data, len);
    memcpy(data + len, str, str_len);

    len += str_len;

    if (data)
    {
        delete tmp_data;
    }

    return *this;
}

bool c_string::operator==(const c_string &cstr)
{
    if (cstr.get_len() != len)
    {
        return false;
    }

    for (u_int i = 0; i < len; i++)
    {
        if (cstr.get_data()[i] != data[i])
        {
            return false;
        }
    }

    return true;
}

bool c_string::operator==(const string *str)
{
    if (strlen(str) != len)
    {
        return false;
    }

    for (u_int i = 0; i < len; i++)
    {
        if (str[i] != data[i])
        {
            return false;
        }
    }

    return true;
}

c_string print_line()
{
    return c_string((char *)"----------------------------------------"
                            "---------------------------------------\n");
}

c_string print_options_string(c_string opt_cstr)
{
    c_string output_string;

    string options_string[512];

    for (int i = 0; i < 512; i++)
    {
        options_string[i] = 0;
    }

    memcpy(options_string, opt_cstr.get_data(), opt_cstr.get_len());

    u_int cursor_pos = 13;
    u_int options_string_pos = 0;
    u_int last_break_pos = 0;

    output_string.add((char *)"\n\tOPTS ");

    while (options_string[options_string_pos])
    {
        if (options_string[options_string_pos] == ']')
        {
            options_string[options_string_pos] = 0;

            if (cursor_pos + options_string_pos - last_break_pos + 1 > 79)
            {
                output_string.add((char *)"\n\t    ");
                cursor_pos = 13;
            }

            output_string.add((char *)"%s]", options_string + last_break_pos);
            cursor_pos += options_string_pos - last_break_pos + 1;
            last_break_pos = options_string_pos + 1;
        }

        if (options_string[options_string_pos] == ',')
        {
            options_string[options_string_pos] = 0;

            if (cursor_pos + options_string_pos - last_break_pos + 1 > 79)
            {
                output_string.add((char *)"\n\t    ");
                cursor_pos = 13;
            }

            output_string.add((char *)"%s,", options_string + last_break_pos);
            cursor_pos += options_string_pos - last_break_pos + 1;
            last_break_pos = options_string_pos + 1;
        }

        if (options_string[options_string_pos] == '}')
        {
            if (options_string[options_string_pos + 1] != ']')
            {
                options_string[options_string_pos] = 0;

                if (cursor_pos + options_string_pos - last_break_pos + 1 > 79)
                {
                    output_string.add((char *)"\n\t    ");
                    cursor_pos = 13;
                }

                output_string.add((char *)"%s}", options_string + last_break_pos);
                cursor_pos += options_string_pos - last_break_pos + 1;
                last_break_pos = options_string_pos + 1;
            }
        }

        options_string_pos++;
    }

    output_string.add((char *)"%s", options_string + last_break_pos);

    return output_string;
}

char *argvncpy(char *str, char **argv, u_int max_len)
{

    char **p;
    u_int len = 0;
    char *src;
    char *dst = str;

    p = argv;
    if (*p == 0)
        return str;

    while (*p && max_len--)
        len += strlen(*p++) + 1;

    p = argv;

    while ((src = *p++) != NULL)
    {
        while ((*dst++ = *src++) != '\0')
            ;
        dst[-1] = ' ';
    }
    dst[-1] = '\0';

    return str;
}
